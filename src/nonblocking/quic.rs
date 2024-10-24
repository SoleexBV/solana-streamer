use {
    crate::{
        nonblocking::stream_throttle::{
            ConnectionStreamCounter, StakedStreamLoadEMA, STREAM_THROTTLING_INTERVAL,
            STREAM_THROTTLING_INTERVAL_MS,
        },
        quic::{configure_server, QuicServerError, StreamStats},
        streamer::StakedNodes,
        tls_certificates::get_pubkey_from_tls_certificate,
    },
    async_channel::{
        unbounded as async_unbounded, Receiver as AsyncReceiver, Sender as AsyncSender,
    },
    bytes::Bytes,
    crossbeam_channel::Sender,
    indexmap::map::{Entry, IndexMap},
    percentage::Percentage,
    quinn::{Connecting, Connection, Endpoint, EndpointConfig, TokioRuntime, VarInt},
    quinn_proto::VarIntBoundsExceeded,
    rand::{thread_rng, Rng},
    smallvec::SmallVec,
    solana_perf::packet::{PacketBatch, PACKETS_PER_BATCH},
    solana_sdk::{
        packet::{Meta, PACKET_DATA_SIZE},
        pubkey::Pubkey,
        quic::{
            QUIC_CONNECTION_HANDSHAKE_TIMEOUT, QUIC_MAX_STAKED_CONCURRENT_STREAMS,
            QUIC_MAX_STAKED_RECEIVE_WINDOW_RATIO, QUIC_MAX_UNSTAKED_CONCURRENT_STREAMS,
            QUIC_MIN_STAKED_CONCURRENT_STREAMS, QUIC_MIN_STAKED_RECEIVE_WINDOW_RATIO,
            QUIC_TOTAL_STAKED_CONCURRENT_STREAMS, QUIC_UNSTAKED_RECEIVE_WINDOW_RATIO,
        },
        signature::Keypair,
        timing,
    },
    std::{
        iter::repeat_with,
        net::{IpAddr, SocketAddr, UdpSocket},
        // CAUTION: be careful not to introduce any awaits while holding an RwLock.
        sync::{
            atomic::{AtomicBool, AtomicU64, Ordering},
            Arc, RwLock,
        },
        time::{Duration, Instant},
    },
    tokio::{
        // CAUTION: It's kind of sketch that we're mixing async and sync locks (see the RwLock above).
        // This is done so that sync code can also access the stake table.
        // Make sure we don't hold a sync lock across an await - including the await to
        // lock an async Mutex. This does not happen now and should not happen as long as we
        // don't hold an async Mutex and sync RwLock at the same time (currently true)
        // but if we do, the scope of the RwLock must always be a subset of the async Mutex
        // (i.e. lock order is always async Mutex -> RwLock). Also, be careful not to
        // introduce any other awaits while holding the RwLock.
        select,
        sync::{Mutex, MutexGuard},
        task::JoinHandle,
        time::{sleep, timeout},
    },
    tokio_util::sync::CancellationToken,
};

pub const DEFAULT_WAIT_FOR_CHUNK_TIMEOUT: Duration = Duration::from_secs(2);

pub const ALPN_TPU_PROTOCOL_ID: &[u8] = b"solana-tpu";

const CONNECTION_CLOSE_CODE_DROPPED_ENTRY: u32 = 1;
const CONNECTION_CLOSE_REASON_DROPPED_ENTRY: &[u8] = b"dropped";

const CONNECTION_CLOSE_CODE_DISALLOWED: u32 = 2;
const CONNECTION_CLOSE_REASON_DISALLOWED: &[u8] = b"disallowed";

const CONNECTION_CLOSE_CODE_EXCEED_MAX_STREAM_COUNT: u32 = 3;
const CONNECTION_CLOSE_REASON_EXCEED_MAX_STREAM_COUNT: &[u8] = b"exceed_max_stream_count";

const CONNECTION_CLOSE_CODE_TOO_MANY: u32 = 4;
const CONNECTION_CLOSE_REASON_TOO_MANY: &[u8] = b"too_many";

/// Limit to 250K PPS
pub const DEFAULT_MAX_STREAMS_PER_MS: u64 = 250;

// A sequence of bytes that is part of a packet
// along with where in the packet it is
struct PacketChunk {
    pub bytes: Bytes,
    // The offset of these bytes in the Quic stream
    // and thus the beginning offset in the slice of the
    // Packet data array into which the bytes will be copied
    pub offset: usize,
    // The end offset of these bytes in the Quic stream
    // and thus the end of the slice in the Packet data array
    // into which the bytes will be copied
    pub end_of_chunk: usize,
}

// A struct to accumulate the bytes making up
// a packet, along with their offsets, and the
// packet metadata. We use this accumulator to avoid
// multiple copies of the Bytes (when building up
// the Packet and then when copying the Packet into a PacketBatch)
struct PacketAccumulator {
    pub meta: Meta,
    pub chunks: SmallVec<[PacketChunk; 2]>,
}

#[derive(Copy, Clone, Debug)]
pub enum ConnectionPeerType {
    Unstaked,
    Staked(u64),
}

impl ConnectionPeerType {
    pub(crate) fn is_staked(&self) -> bool {
        matches!(self, ConnectionPeerType::Staked(_))
    }
}

pub struct SpawnNonBlockingServerResult {
    pub endpoint: Endpoint,
    pub stats: Arc<StreamStats>,
    pub thread: JoinHandle<()>,
    pub max_concurrent_connections: usize,
}

#[allow(clippy::too_many_arguments)]
pub fn spawn_server(
    name: &'static str,
    sock: UdpSocket,
    keypair: &Keypair,
    gossip_host: IpAddr,
    packet_sender: Sender<PacketBatch>,
    exit: Arc<AtomicBool>,
    max_connections_per_peer: usize,
    staked_nodes: Arc<RwLock<StakedNodes>>,
    max_staked_connections: usize,
    max_unstaked_connections: usize,
    max_streams_per_ms: u64,
    wait_for_chunk_timeout: Duration,
    coalesce: Duration,
) -> Result<SpawnNonBlockingServerResult, QuicServerError> {
    info!("Start {name} quic server on {sock:?}");
    let concurrent_connections = max_staked_connections + max_unstaked_connections;
    let max_concurrent_connections = concurrent_connections + concurrent_connections / 4;
    let (config, _cert) = configure_server(keypair, gossip_host, max_concurrent_connections)?;

    let endpoint = Endpoint::new(
        EndpointConfig::default(),
        Some(config),
        sock,
        Arc::new(TokioRuntime),
    )
    .map_err(QuicServerError::EndpointFailed)?;

    let stats = Arc::<StreamStats>::default();
    let handle = tokio::spawn(run_server(
        name,
        endpoint.clone(),
        packet_sender,
        exit,
        max_connections_per_peer,
        staked_nodes,
        max_staked_connections,
        max_unstaked_connections,
        max_streams_per_ms,
        stats.clone(),
        wait_for_chunk_timeout,
        coalesce,
    ));
    Ok(SpawnNonBlockingServerResult {
        endpoint,
        stats,
        thread: handle,
        max_concurrent_connections,
    })
}

#[allow(clippy::too_many_arguments)]
async fn run_server(
    name: &'static str,
    incoming: Endpoint,
    packet_sender: Sender<PacketBatch>,
    exit: Arc<AtomicBool>,
    max_connections_per_peer: usize,
    staked_nodes: Arc<RwLock<StakedNodes>>,
    max_staked_connections: usize,
    max_unstaked_connections: usize,
    max_streams_per_ms: u64,
    stats: Arc<StreamStats>,
    wait_for_chunk_timeout: Duration,
    coalesce: Duration,
) {
    const WAIT_FOR_CONNECTION_TIMEOUT: Duration = Duration::from_secs(1);
    debug!("spawn quic server");
    let mut last_datapoint = Instant::now();
    let unstaked_connection_table: Arc<Mutex<ConnectionTable>> =
        Arc::new(Mutex::new(ConnectionTable::new()));
    let stream_load_ema = Arc::new(StakedStreamLoadEMA::new(
        stats.clone(),
        max_unstaked_connections,
        max_streams_per_ms,
    ));
    let staked_connection_table: Arc<Mutex<ConnectionTable>> =
        Arc::new(Mutex::new(ConnectionTable::new()));
    let (sender, receiver) = async_unbounded();
    tokio::spawn(packet_batch_sender(
        packet_sender,
        receiver,
        exit.clone(),
        stats.clone(),
        coalesce,
    ));
    while !exit.load(Ordering::Relaxed) {
        let timeout_connection = timeout(WAIT_FOR_CONNECTION_TIMEOUT, incoming.accept()).await;

        if last_datapoint.elapsed().as_secs() >= 5 {
            stats.report(name);
            last_datapoint = Instant::now();
        }

        if let Ok(Some(connection)) = timeout_connection {
            info!("Got a connection {:?}", connection.remote_address());
            tokio::spawn(setup_connection(
                connection,
                unstaked_connection_table.clone(),
                staked_connection_table.clone(),
                sender.clone(),
                max_connections_per_peer,
                staked_nodes.clone(),
                max_staked_connections,
                max_unstaked_connections,
                max_streams_per_ms,
                stats.clone(),
                wait_for_chunk_timeout,
                stream_load_ema.clone(),
            ));
        } else {
            debug!("accept(): Timed out waiting for connection");
        }
    }
}

fn prune_unstaked_connection_table(
    unstaked_connection_table: &mut ConnectionTable,
    max_unstaked_connections: usize,
    stats: Arc<StreamStats>,
) {
    if unstaked_connection_table.total_size >= max_unstaked_connections {
        const PRUNE_TABLE_TO_PERCENTAGE: u8 = 90;
        let max_percentage_full = Percentage::from(PRUNE_TABLE_TO_PERCENTAGE);

        let max_connections = max_percentage_full.apply_to(max_unstaked_connections);
        let num_pruned = unstaked_connection_table.prune_oldest(max_connections);
        stats.num_evictions.fetch_add(num_pruned, Ordering::Relaxed);
    }
}

pub fn get_remote_pubkey(connection: &Connection) -> Option<Pubkey> {
    // Use the client cert only if it is self signed and the chain length is 1.
    connection
        .peer_identity()?
        .downcast::<Vec<rustls::Certificate>>()
        .ok()
        .filter(|certs| certs.len() == 1)?
        .first()
        .and_then(get_pubkey_from_tls_certificate)
}

fn get_connection_stake(
    connection: &Connection,
    staked_nodes: &RwLock<StakedNodes>,
) -> Option<(Pubkey, u64, u64, u64, u64)> {
    let pubkey = get_remote_pubkey(connection)?;
    debug!("Peer public key is {pubkey:?}");
    let staked_nodes = staked_nodes.read().unwrap();
    Some((
        pubkey,
        staked_nodes.get_node_stake(&pubkey)?,
        staked_nodes.total_stake(),
        staked_nodes.max_stake(),
        staked_nodes.min_stake(),
    ))
}

pub fn compute_max_allowed_uni_streams(peer_type: ConnectionPeerType, total_stake: u64) -> usize {
    match peer_type {
        ConnectionPeerType::Staked(peer_stake) => {
            // No checked math for f64 type. So let's explicitly check for 0 here
            if total_stake == 0 || peer_stake > total_stake {
                warn!(
                    "Invalid stake values: peer_stake: {:?}, total_stake: {:?}",
                    peer_stake, total_stake,
                );

                QUIC_MIN_STAKED_CONCURRENT_STREAMS
            } else {
                let delta = (QUIC_TOTAL_STAKED_CONCURRENT_STREAMS
                    - QUIC_MIN_STAKED_CONCURRENT_STREAMS) as f64;

                (((peer_stake as f64 / total_stake as f64) * delta) as usize
                    + QUIC_MIN_STAKED_CONCURRENT_STREAMS)
                    .clamp(
                        QUIC_MIN_STAKED_CONCURRENT_STREAMS,
                        QUIC_MAX_STAKED_CONCURRENT_STREAMS,
                    )
            }
        }
        ConnectionPeerType::Unstaked => QUIC_MAX_UNSTAKED_CONCURRENT_STREAMS,
    }
}

enum ConnectionHandlerError {
    ConnectionAddError,
    MaxStreamError,
}

#[derive(Clone)]
struct NewConnectionHandlerParams {
    // In principle, the code can be made to work with a crossbeam channel
    // as long as we're careful never to use a blocking recv or send call
    // but I've found that it's simply too easy to accidentally block
    // in async code when using the crossbeam channel, so for the sake of maintainability,
    // we're sticking with an async channel
    packet_sender: AsyncSender<PacketAccumulator>,
    remote_pubkey: Option<Pubkey>,
    peer_type: ConnectionPeerType,
    total_stake: u64,
    max_connections_per_peer: usize,
    stats: Arc<StreamStats>,
    max_stake: u64,
    min_stake: u64,
}

impl NewConnectionHandlerParams {
    fn new_unstaked(
        packet_sender: AsyncSender<PacketAccumulator>,
        max_connections_per_peer: usize,
        stats: Arc<StreamStats>,
    ) -> NewConnectionHandlerParams {
        NewConnectionHandlerParams {
            packet_sender,
            remote_pubkey: None,
            peer_type: ConnectionPeerType::Unstaked,
            total_stake: 0,
            max_connections_per_peer,
            stats,
            max_stake: 0,
            min_stake: 0,
        }
    }
}

fn handle_and_cache_new_connection(
    connection: Connection,
    mut connection_table_l: MutexGuard<ConnectionTable>,
    connection_table: Arc<Mutex<ConnectionTable>>,
    params: &NewConnectionHandlerParams,
    wait_for_chunk_timeout: Duration,
    stream_load_ema: Arc<StakedStreamLoadEMA>,
) -> Result<(), ConnectionHandlerError> {
    if let Ok(max_uni_streams) = VarInt::from_u64(compute_max_allowed_uni_streams(
        params.peer_type,
        params.total_stake,
    ) as u64)
    {
        let remote_addr = connection.remote_address();
        let receive_window =
            compute_recieve_window(params.max_stake, params.min_stake, params.peer_type);

        debug!(
            "Peer type {:?}, total stake {}, max streams {} receive_window {:?} from peer {}",
            params.peer_type,
            params.total_stake,
            max_uni_streams.into_inner(),
            receive_window,
            remote_addr,
        );

        if let Some((last_update, cancel_connection, stream_counter)) = connection_table_l
            .try_add_connection(
                ConnectionTableKey::new(remote_addr.ip(), params.remote_pubkey),
                remote_addr.port(),
                Some(connection.clone()),
                params.peer_type,
                timing::timestamp(),
                params.max_connections_per_peer,
            )
        {
            drop(connection_table_l);

            if let Ok(receive_window) = receive_window {
                connection.set_receive_window(receive_window);
            }
            connection.set_max_concurrent_uni_streams(max_uni_streams);

            tokio::spawn(handle_connection(
                connection,
                remote_addr,
                last_update,
                connection_table,
                cancel_connection,
                params.clone(),
                wait_for_chunk_timeout,
                stream_load_ema,
                stream_counter,
            ));
            Ok(())
        } else {
            params
                .stats
                .connection_add_failed
                .fetch_add(1, Ordering::Relaxed);
            Err(ConnectionHandlerError::ConnectionAddError)
        }
    } else {
        connection.close(
            CONNECTION_CLOSE_CODE_EXCEED_MAX_STREAM_COUNT.into(),
            CONNECTION_CLOSE_REASON_EXCEED_MAX_STREAM_COUNT,
        );
        params
            .stats
            .connection_add_failed_invalid_stream_count
            .fetch_add(1, Ordering::Relaxed);
        Err(ConnectionHandlerError::MaxStreamError)
    }
}

async fn prune_unstaked_connections_and_add_new_connection(
    connection: Connection,
    connection_table: Arc<Mutex<ConnectionTable>>,
    max_connections: usize,
    params: &NewConnectionHandlerParams,
    wait_for_chunk_timeout: Duration,
    stream_load_ema: Arc<StakedStreamLoadEMA>,
) -> Result<(), ConnectionHandlerError> {
    let stats = params.stats.clone();
    if max_connections > 0 {
        let connection_table_clone = connection_table.clone();
        let mut connection_table = connection_table.lock().await;
        prune_unstaked_connection_table(&mut connection_table, max_connections, stats);
        handle_and_cache_new_connection(
            connection,
            connection_table,
            connection_table_clone,
            params,
            wait_for_chunk_timeout,
            stream_load_ema,
        )
    } else {
        connection.close(
            CONNECTION_CLOSE_CODE_DISALLOWED.into(),
            CONNECTION_CLOSE_REASON_DISALLOWED,
        );
        Err(ConnectionHandlerError::ConnectionAddError)
    }
}

/// Calculate the ratio for per connection receive window from a staked peer
fn compute_receive_window_ratio_for_staked_node(max_stake: u64, min_stake: u64, stake: u64) -> u64 {
    // Testing shows the maximum througput from a connection is achieved at receive_window =
    // PACKET_DATA_SIZE * 10. Beyond that, there is not much gain. We linearly map the
    // stake to the ratio range from QUIC_MIN_STAKED_RECEIVE_WINDOW_RATIO to
    // QUIC_MAX_STAKED_RECEIVE_WINDOW_RATIO. Where the linear algebra of finding the ratio 'r'
    // for stake 's' is,
    // r(s) = a * s + b. Given the max_stake, min_stake, max_ratio, min_ratio, we can find
    // a and b.

    if stake > max_stake {
        return QUIC_MAX_STAKED_RECEIVE_WINDOW_RATIO;
    }

    let max_ratio = QUIC_MAX_STAKED_RECEIVE_WINDOW_RATIO;
    let min_ratio = QUIC_MIN_STAKED_RECEIVE_WINDOW_RATIO;
    if max_stake > min_stake {
        let a = (max_ratio - min_ratio) as f64 / (max_stake - min_stake) as f64;
        let b = max_ratio as f64 - ((max_stake as f64) * a);
        let ratio = (a * stake as f64) + b;
        ratio.round() as u64
    } else {
        QUIC_MAX_STAKED_RECEIVE_WINDOW_RATIO
    }
}

fn compute_recieve_window(
    max_stake: u64,
    min_stake: u64,
    peer_type: ConnectionPeerType,
) -> Result<VarInt, VarIntBoundsExceeded> {
    match peer_type {
        ConnectionPeerType::Unstaked => {
            VarInt::from_u64(PACKET_DATA_SIZE as u64 * QUIC_UNSTAKED_RECEIVE_WINDOW_RATIO)
        }
        ConnectionPeerType::Staked(peer_stake) => {
            let ratio =
                compute_receive_window_ratio_for_staked_node(max_stake, min_stake, peer_stake);
            VarInt::from_u64(PACKET_DATA_SIZE as u64 * ratio)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn setup_connection(
    connecting: Connecting,
    unstaked_connection_table: Arc<Mutex<ConnectionTable>>,
    staked_connection_table: Arc<Mutex<ConnectionTable>>,
    packet_sender: AsyncSender<PacketAccumulator>,
    max_connections_per_peer: usize,
    staked_nodes: Arc<RwLock<StakedNodes>>,
    max_staked_connections: usize,
    max_unstaked_connections: usize,
    max_streams_per_ms: u64,
    stats: Arc<StreamStats>,
    wait_for_chunk_timeout: Duration,
    stream_load_ema: Arc<StakedStreamLoadEMA>,
) {
    const PRUNE_RANDOM_SAMPLE_SIZE: usize = 2;
    let from = connecting.remote_address();
    if let Ok(connecting_result) = timeout(QUIC_CONNECTION_HANDSHAKE_TIMEOUT, connecting).await {
        match connecting_result {
            Ok(new_connection) => {
                stats.total_new_connections.fetch_add(1, Ordering::Relaxed);

                let params = get_connection_stake(&new_connection, &staked_nodes).map_or(
                    NewConnectionHandlerParams::new_unstaked(
                        packet_sender.clone(),
                        max_connections_per_peer,
                        stats.clone(),
                    ),
                    |(pubkey, stake, total_stake, max_stake, min_stake)| {
                        // The heuristic is that the stake should be large engouh to have 1 stream pass throuh within one throttle
                        // interval during which we allow max (MAX_STREAMS_PER_MS * STREAM_THROTTLING_INTERVAL_MS) streams.
                        let min_stake_ratio =
                            1_f64 / (max_streams_per_ms * STREAM_THROTTLING_INTERVAL_MS) as f64;
                        let stake_ratio = stake as f64 / total_stake as f64;
                        let peer_type = if stake_ratio < min_stake_ratio {
                            // If it is a staked connection with ultra low stake ratio, treat it as unstaked.
                            ConnectionPeerType::Unstaked
                        } else {
                            ConnectionPeerType::Staked(stake)
                        };
                        NewConnectionHandlerParams {
                            packet_sender,
                            remote_pubkey: Some(pubkey),
                            peer_type,
                            total_stake,
                            max_connections_per_peer,
                            stats: stats.clone(),
                            max_stake,
                            min_stake,
                        }
                    },
                );

                match params.peer_type {
                    ConnectionPeerType::Staked(stake) => {
                        let mut connection_table_l = staked_connection_table.lock().await;

                        if connection_table_l.total_size >= max_staked_connections {
                            let num_pruned =
                                connection_table_l.prune_random(PRUNE_RANDOM_SAMPLE_SIZE, stake);
                            stats.num_evictions.fetch_add(num_pruned, Ordering::Relaxed);
                        }

                        if connection_table_l.total_size < max_staked_connections {
                            if let Ok(()) = handle_and_cache_new_connection(
                                new_connection,
                                connection_table_l,
                                staked_connection_table.clone(),
                                &params,
                                wait_for_chunk_timeout,
                                stream_load_ema.clone(),
                            ) {
                                stats
                                    .connection_added_from_staked_peer
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                        } else {
                            // If we couldn't prune a connection in the staked connection table, let's
                            // put this connection in the unstaked connection table. If needed, prune a
                            // connection from the unstaked connection table.
                            if let Ok(()) = prune_unstaked_connections_and_add_new_connection(
                                new_connection,
                                unstaked_connection_table.clone(),
                                max_unstaked_connections,
                                &params,
                                wait_for_chunk_timeout,
                                stream_load_ema.clone(),
                            )
                            .await
                            {
                                stats
                                    .connection_added_from_staked_peer
                                    .fetch_add(1, Ordering::Relaxed);
                            } else {
                                stats
                                    .connection_add_failed_on_pruning
                                    .fetch_add(1, Ordering::Relaxed);
                                stats
                                    .connection_add_failed_staked_node
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    ConnectionPeerType::Unstaked => {
                        if let Ok(()) = prune_unstaked_connections_and_add_new_connection(
                            new_connection,
                            unstaked_connection_table.clone(),
                            max_unstaked_connections,
                            &params,
                            wait_for_chunk_timeout,
                            stream_load_ema.clone(),
                        )
                        .await
                        {
                            stats
                                .connection_added_from_unstaked_peer
                                .fetch_add(1, Ordering::Relaxed);
                        } else {
                            stats
                                .connection_add_failed_unstaked_node
                                .fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
            Err(e) => {
                handle_connection_error(e, &stats, from);
            }
        }
    } else {
        stats
            .connection_setup_timeout
            .fetch_add(1, Ordering::Relaxed);
    }
}

fn handle_connection_error(e: quinn::ConnectionError, stats: &StreamStats, from: SocketAddr) {
    debug!("error: {:?} from: {:?}", e, from);
    stats.connection_setup_error.fetch_add(1, Ordering::Relaxed);
    match e {
        quinn::ConnectionError::TimedOut => {
            stats
                .connection_setup_error_timed_out
                .fetch_add(1, Ordering::Relaxed);
        }
        quinn::ConnectionError::ConnectionClosed(_) => {
            stats
                .connection_setup_error_closed
                .fetch_add(1, Ordering::Relaxed);
        }
        quinn::ConnectionError::TransportError(_) => {
            stats
                .connection_setup_error_transport
                .fetch_add(1, Ordering::Relaxed);
        }
        quinn::ConnectionError::ApplicationClosed(_) => {
            stats
                .connection_setup_error_app_closed
                .fetch_add(1, Ordering::Relaxed);
        }
        quinn::ConnectionError::Reset => {
            stats
                .connection_setup_error_reset
                .fetch_add(1, Ordering::Relaxed);
        }
        quinn::ConnectionError::LocallyClosed => {
            stats
                .connection_setup_error_locally_closed
                .fetch_add(1, Ordering::Relaxed);
        }
        _ => {}
    }
}

async fn packet_batch_sender(
    packet_sender: Sender<PacketBatch>,
    packet_receiver: AsyncReceiver<PacketAccumulator>,
    exit: Arc<AtomicBool>,
    stats: Arc<StreamStats>,
    coalesce: Duration,
) {
    trace!("enter packet_batch_sender");
    let mut batch_start_time = Instant::now();
    loop {
        let mut packet_batch = PacketBatch::with_capacity(PACKETS_PER_BATCH);
        let mut total_bytes: usize = 0;

        stats
            .total_packet_batches_allocated
            .fetch_add(1, Ordering::Relaxed);
        stats
            .total_packets_allocated
            .fetch_add(PACKETS_PER_BATCH, Ordering::Relaxed);

        loop {
            if exit.load(Ordering::Relaxed) {
                return;
            }
            let elapsed = batch_start_time.elapsed();
            if packet_batch.len() >= PACKETS_PER_BATCH
                || (!packet_batch.is_empty() && elapsed >= coalesce)
            {
                let len = packet_batch.len();
                if let Err(e) = packet_sender.send(packet_batch) {
                    stats
                        .total_packet_batch_send_err
                        .fetch_add(1, Ordering::Relaxed);
                    trace!("Send error: {}", e);
                } else {
                    stats
                        .total_packet_batches_sent
                        .fetch_add(1, Ordering::Relaxed);

                    stats
                        .total_packets_sent_to_consumer
                        .fetch_add(len, Ordering::Relaxed);

                    stats
                        .total_bytes_sent_to_consumer
                        .fetch_add(total_bytes, Ordering::Relaxed);

                    trace!("Sent {} packet batch", len);
                }
                break;
            }

            let timeout_res = timeout(Duration::from_micros(250), packet_receiver.recv()).await;

            if let Ok(Ok(packet_accumulator)) = timeout_res {
                // Start the timeout from when the packet batch first becomes non-empty
                if packet_batch.is_empty() {
                    batch_start_time = Instant::now();
                }

                unsafe {
                    packet_batch.set_len(packet_batch.len() + 1);
                }

                let i = packet_batch.len() - 1;
                *packet_batch[i].meta_mut() = packet_accumulator.meta;
                let num_chunks = packet_accumulator.chunks.len();
                for chunk in packet_accumulator.chunks {
                    packet_batch[i].buffer_mut()[chunk.offset..chunk.end_of_chunk]
                        .copy_from_slice(&chunk.bytes);
                }

                total_bytes += packet_batch[i].meta().size;

                stats
                    .total_chunks_processed_by_batcher
                    .fetch_add(num_chunks, Ordering::Relaxed);
            }
        }
    }
}

async fn handle_connection(
    connection: Connection,
    remote_addr: SocketAddr,
    last_update: Arc<AtomicU64>,
    connection_table: Arc<Mutex<ConnectionTable>>,
    cancel: CancellationToken,
    params: NewConnectionHandlerParams,
    wait_for_chunk_timeout: Duration,
    stream_load_ema: Arc<StakedStreamLoadEMA>,
    stream_counter: Arc<ConnectionStreamCounter>,
) {
    let stats = params.stats;
    debug!(
        "quic new connection {} streams: {} connections: {}",
        remote_addr,
        stats.total_streams.load(Ordering::Relaxed),
        stats.total_connections.load(Ordering::Relaxed),
    );
    let stable_id = connection.stable_id();
    stats.total_connections.fetch_add(1, Ordering::Relaxed);
    loop {
        // Wait for new streams. If the peer is disconnected we get a cancellation signal and stop
        // the connection task.
        let mut stream = select! {
            stream = connection.accept_uni() => match stream {
                Ok(stream) => stream,
                Err(e) => {
                    debug!("stream error: {:?}", e);
                    break;
                }
            },
            _ = cancel.cancelled() => break,
        };

        let max_streams_per_throttling_interval = stream_load_ema
            .available_load_capacity_in_throttling_duration(params.peer_type, params.total_stake);

        let throttle_interval_start = stream_counter.reset_throttling_params_if_needed();
        let streams_read_in_throttle_interval = stream_counter.stream_count.load(Ordering::Relaxed);
        if streams_read_in_throttle_interval >= max_streams_per_throttling_interval {
            // The peer is sending faster than we're willing to read. Sleep for what's
            // left of this read interval so the peer backs off.
            let throttle_duration =
                STREAM_THROTTLING_INTERVAL.saturating_sub(throttle_interval_start.elapsed());

            if !throttle_duration.is_zero() {
                debug!("Throttling stream from {remote_addr:?}, peer type: {:?}, total stake: {}, \
                                    max_streams_per_interval: {max_streams_per_throttling_interval}, read_interval_streams: {streams_read_in_throttle_interval} \
                                    throttle_duration: {throttle_duration:?}",
                                    params.peer_type, params.total_stake);
                stats.throttled_streams.fetch_add(1, Ordering::Relaxed);
                match params.peer_type {
                    ConnectionPeerType::Unstaked => {
                        stats
                            .throttled_unstaked_streams
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    ConnectionPeerType::Staked(_) => {
                        stats
                            .throttled_staked_streams
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
                sleep(throttle_duration).await;
            }
        }
        stream_load_ema.increment_load(params.peer_type);
        stream_counter.stream_count.fetch_add(1, Ordering::Relaxed);
        stats.total_streams.fetch_add(1, Ordering::Relaxed);
        stats.total_new_streams.fetch_add(1, Ordering::Relaxed);
        let cancel = cancel.clone();
        let stats = stats.clone();
        let packet_sender = params.packet_sender.clone();
        let last_update = last_update.clone();
        let stream_load_ema = stream_load_ema.clone();
        tokio::spawn(async move {
            let mut maybe_batch = None;
            loop {
                // Read the next chunk, waiting up to `wait_for_chunk_timeout`. If we don't get a
                // chunk before then, we assume the stream is dead and stop the stream task. This
                // can only happen if there's severe packet loss or the peer stop sending for
                // whatever reason.
                let chunk = match tokio::select! {
                    chunk = tokio::time::timeout(
                        wait_for_chunk_timeout,
                        stream.read_chunk(PACKET_DATA_SIZE, true)) => chunk,

                    // If the peer gets disconnected stop the task right away.
                    _ = cancel.cancelled() => break,
                } {
                    // read_chunk returned success
                    Ok(Ok(chunk)) => chunk,
                    // read_chunk returned error
                    Ok(Err(e)) => {
                        debug!("Received stream error: {:?}", e);
                        stats
                            .total_stream_read_errors
                            .fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                    // timeout elapsed
                    Err(_) => {
                        debug!("Timeout in receiving on stream");
                        stats
                            .total_stream_read_timeouts
                            .fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                };

                if handle_chunk(
                    chunk,
                    &mut maybe_batch,
                    &remote_addr,
                    &packet_sender,
                    stats.clone(),
                    params.peer_type,
                )
                .await
                {
                    last_update.store(timing::timestamp(), Ordering::Relaxed);
                    break;
                }
            }

            stats.total_streams.fetch_sub(1, Ordering::Relaxed);
            stream_load_ema.update_ema_if_needed();
        });
    }

    let removed_connection_count = connection_table.lock().await.remove_connection(
        ConnectionTableKey::new(remote_addr.ip(), params.remote_pubkey),
        remote_addr.port(),
        stable_id,
    );
    if removed_connection_count > 0 {
        stats
            .connection_removed
            .fetch_add(removed_connection_count, Ordering::Relaxed);
    } else {
        stats
            .connection_remove_failed
            .fetch_add(1, Ordering::Relaxed);
    }
    stats.total_connections.fetch_sub(1, Ordering::Relaxed);
}

// Return true if the server should drop the stream
async fn handle_chunk(
    maybe_chunk: Option<quinn::Chunk>,
    packet_accum: &mut Option<PacketAccumulator>,
    remote_addr: &SocketAddr,
    packet_sender: &AsyncSender<PacketAccumulator>,
    stats: Arc<StreamStats>,
    peer_type: ConnectionPeerType,
) -> bool {
    if let Some(chunk) = maybe_chunk {
        trace!("got chunk: {:?}", chunk);
        let chunk_len = chunk.bytes.len() as u64;

        // shouldn't happen, but sanity check the size and offsets
        if chunk.offset > PACKET_DATA_SIZE as u64 || chunk_len > PACKET_DATA_SIZE as u64 {
            stats.total_invalid_chunks.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        let Some(end_of_chunk) = chunk.offset.checked_add(chunk_len) else {
            return true;
        };
        if end_of_chunk > PACKET_DATA_SIZE as u64 {
            stats
                .total_invalid_chunk_size
                .fetch_add(1, Ordering::Relaxed);
            return true;
        }

        // chunk looks valid
        if packet_accum.is_none() {
            let mut meta = Meta::default();
            meta.set_socket_addr(remote_addr);
            meta.set_from_staked_node(matches!(peer_type, ConnectionPeerType::Staked(_)));
            *packet_accum = Some(PacketAccumulator {
                meta,
                chunks: SmallVec::new(),
            });
        }

        if let Some(accum) = packet_accum.as_mut() {
            let offset = chunk.offset;
            let Some(end_of_chunk) = (chunk.offset as usize).checked_add(chunk.bytes.len()) else {
                return true;
            };
            accum.chunks.push(PacketChunk {
                bytes: chunk.bytes,
                offset: offset as usize,
                end_of_chunk,
            });

            accum.meta.size = std::cmp::max(accum.meta.size, end_of_chunk);
        }

        if peer_type.is_staked() {
            stats
                .total_staked_chunks_received
                .fetch_add(1, Ordering::Relaxed);
        } else {
            stats
                .total_unstaked_chunks_received
                .fetch_add(1, Ordering::Relaxed);
        }
    } else {
        // done receiving chunks
        trace!("chunk is none");
        if let Some(accum) = packet_accum.take() {
            let bytes_sent = accum.meta.size;
            let chunks_sent = accum.chunks.len();

            if let Err(err) = packet_sender.send(accum).await {
                stats
                    .total_handle_chunk_to_packet_batcher_send_err
                    .fetch_add(1, Ordering::Relaxed);
                trace!("packet batch send error {:?}", err);
            } else {
                stats
                    .total_packets_sent_for_batching
                    .fetch_add(1, Ordering::Relaxed);
                stats
                    .total_bytes_sent_for_batching
                    .fetch_add(bytes_sent, Ordering::Relaxed);
                stats
                    .total_chunks_sent_for_batching
                    .fetch_add(chunks_sent, Ordering::Relaxed);

                match peer_type {
                    ConnectionPeerType::Unstaked => {
                        stats
                            .total_unstaked_packets_sent_for_batching
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    ConnectionPeerType::Staked(_) => {
                        stats
                            .total_staked_packets_sent_for_batching
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }

                trace!("sent {} byte packet for batching", bytes_sent);
            }
        } else {
            stats
                .total_packet_batches_none
                .fetch_add(1, Ordering::Relaxed);
        }
        return true;
    }
    false
}

#[derive(Debug)]
struct ConnectionEntry {
    cancel: CancellationToken,
    peer_type: ConnectionPeerType,
    last_update: Arc<AtomicU64>,
    port: u16,
    connection: Option<Connection>,
    stream_counter: Arc<ConnectionStreamCounter>,
}

impl ConnectionEntry {
    fn new(
        cancel: CancellationToken,
        peer_type: ConnectionPeerType,
        last_update: Arc<AtomicU64>,
        port: u16,
        connection: Option<Connection>,
        stream_counter: Arc<ConnectionStreamCounter>,
    ) -> Self {
        Self {
            cancel,
            peer_type,
            last_update,
            port,
            connection,
            stream_counter,
        }
    }

    fn last_update(&self) -> u64 {
        self.last_update.load(Ordering::Relaxed)
    }

    fn stake(&self) -> u64 {
        match self.peer_type {
            ConnectionPeerType::Unstaked => 0,
            ConnectionPeerType::Staked(stake) => stake,
        }
    }
}

impl Drop for ConnectionEntry {
    fn drop(&mut self) {
        if let Some(conn) = self.connection.take() {
            conn.close(
                CONNECTION_CLOSE_CODE_DROPPED_ENTRY.into(),
                CONNECTION_CLOSE_REASON_DROPPED_ENTRY,
            );
        }
        self.cancel.cancel();
    }
}

#[derive(Copy, Clone, Eq, Hash, PartialEq)]
enum ConnectionTableKey {
    IP(IpAddr),
    Pubkey(Pubkey),
}

impl ConnectionTableKey {
    fn new(ip: IpAddr, maybe_pubkey: Option<Pubkey>) -> Self {
        maybe_pubkey.map_or(ConnectionTableKey::IP(ip), |pubkey| {
            ConnectionTableKey::Pubkey(pubkey)
        })
    }
}

// Map of IP to list of connection entries
struct ConnectionTable {
    table: IndexMap<ConnectionTableKey, Vec<ConnectionEntry>>,
    total_size: usize,
}

// Prune the connection which has the oldest update
// Return number pruned
impl ConnectionTable {
    fn new() -> Self {
        Self {
            table: IndexMap::default(),
            total_size: 0,
        }
    }

    fn prune_oldest(&mut self, max_size: usize) -> usize {
        let mut num_pruned = 0;
        let key = |(_, connections): &(_, &Vec<_>)| {
            connections.iter().map(ConnectionEntry::last_update).min()
        };
        while self.total_size.saturating_sub(num_pruned) > max_size {
            match self.table.values().enumerate().min_by_key(key) {
                None => break,
                Some((index, connections)) => {
                    num_pruned += connections.len();
                    self.table.swap_remove_index(index);
                }
            }
        }
        self.total_size = self.total_size.saturating_sub(num_pruned);
        num_pruned
    }

    // Randomly selects sample_size many connections, evicts the one with the
    // lowest stake, and returns the number of pruned connections.
    // If the stakes of all the sampled connections are higher than the
    // threshold_stake, rejects the pruning attempt, and returns 0.
    fn prune_random(&mut self, sample_size: usize, threshold_stake: u64) -> usize {
        let num_pruned = std::iter::once(self.table.len())
            .filter(|&size| size > 0)
            .flat_map(|size| {
                let mut rng = thread_rng();
                repeat_with(move || rng.gen_range(0..size))
            })
            .map(|index| {
                let connection = self.table[index].first();
                let stake = connection.map(|connection| connection.stake());
                (index, stake)
            })
            .take(sample_size)
            .min_by_key(|&(_, stake)| stake)
            .filter(|&(_, stake)| stake < Some(threshold_stake))
            .and_then(|(index, _)| self.table.swap_remove_index(index))
            .map(|(_, connections)| connections.len())
            .unwrap_or_default();
        self.total_size = self.total_size.saturating_sub(num_pruned);
        num_pruned
    }

    fn try_add_connection(
        &mut self,
        key: ConnectionTableKey,
        port: u16,
        connection: Option<Connection>,
        peer_type: ConnectionPeerType,
        last_update: u64,
        max_connections_per_peer: usize,
    ) -> Option<(
        Arc<AtomicU64>,
        CancellationToken,
        Arc<ConnectionStreamCounter>,
    )> {
        let connection_entry = self.table.entry(key).or_default();
        let has_connection_capacity = connection_entry
            .len()
            .checked_add(1)
            .map(|c| c <= max_connections_per_peer)
            .unwrap_or(false);
        if has_connection_capacity {
            let cancel = CancellationToken::new();
            let last_update = Arc::new(AtomicU64::new(last_update));
            let stream_counter = connection_entry
                .first()
                .map(|entry| entry.stream_counter.clone())
                .unwrap_or(Arc::new(ConnectionStreamCounter::new()));
            connection_entry.push(ConnectionEntry::new(
                cancel.clone(),
                peer_type,
                last_update.clone(),
                port,
                connection,
                stream_counter.clone(),
            ));
            self.total_size += 1;
            Some((last_update, cancel, stream_counter))
        } else {
            if let Some(connection) = connection {
                connection.close(
                    CONNECTION_CLOSE_CODE_TOO_MANY.into(),
                    CONNECTION_CLOSE_REASON_TOO_MANY,
                );
            }
            None
        }
    }

    // Returns number of connections that were removed
    fn remove_connection(&mut self, key: ConnectionTableKey, port: u16, stable_id: usize) -> usize {
        if let Entry::Occupied(mut e) = self.table.entry(key) {
            let e_ref = e.get_mut();
            let old_size = e_ref.len();

            e_ref.retain(|connection_entry| {
                // Retain the connection entry if the port is different, or if the connection's
                // stable_id doesn't match the provided stable_id.
                // (Some unit tests do not fill in a valid connection in the table. To support that,
                // if the connection is none, the stable_id check is ignored. i.e. if the port matches,
                // the connection gets removed)
                connection_entry.port != port
                    || connection_entry
                        .connection
                        .as_ref()
                        .and_then(|connection| (connection.stable_id() != stable_id).then_some(0))
                        .is_some()
            });
            let new_size = e_ref.len();
            if e_ref.is_empty() {
                e.swap_remove_entry();
            }
            let connections_removed = old_size.saturating_sub(new_size);
            self.total_size = self.total_size.saturating_sub(connections_removed);
            connections_removed
        } else {
            0
        }
    }
}
