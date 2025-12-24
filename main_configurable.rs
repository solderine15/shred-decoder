mod deshred;

use anyhow::Result;
use clap::Parser;
use crossbeam_channel::{bounded, Receiver, Sender};
use deshred::{ShredProcessor, ShredStats};
use log::{error, info, warn};
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{transport::Server, Request, Response, Status};

// Include the generated proto code
pub mod shredstream {
    tonic::include_proto!("shredstream");
}

use shredstream::{
    shred_decoder_server::{ShredDecoder, ShredDecoderServer},
    Entry, GetStatsRequest, StatsResponse, SubscribeEntriesRequest,
};

/// Command-line arguments
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// UDP port to receive shreds on
    #[arg(short = 'u', long, default_value_t = 8002, env = "SHRED_UDP_PORT")]
    udp_port: u16,

    /// gRPC port to serve decoded entries on
    #[arg(short = 'g', long, default_value_t = 50051, env = "SHRED_GRPC_PORT")]
    grpc_port: u16,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short = 'l', long, default_value = "info", env = "RUST_LOG")]
    log_level: String,
}

/// Main gRPC service implementation
struct ShredDecoderService {
    entry_sender: broadcast::Sender<Entry>,
    stats: Arc<ShredStats>,
    shreds_per_second: Arc<AtomicU64>,
}

#[tonic::async_trait]
impl ShredDecoder for ShredDecoderService {
    type SubscribeEntriesStream = ReceiverStream<Result<Entry, Status>>;

    async fn subscribe_entries(
        &self,
        _request: Request<SubscribeEntriesRequest>,
    ) -> Result<Response<Self::SubscribeEntriesStream>, Status> {
        let (tx, rx) = mpsc::channel(100);
        let mut entry_receiver = self.entry_sender.subscribe();

        tokio::spawn(async move {
            while let Ok(entry) = entry_receiver.recv().await {
                if tx.send(Ok(entry)).await.is_err() {
                    break; // Client disconnected
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn get_stats(
        &self,
        _request: Request<GetStatsRequest>,
    ) -> Result<Response<StatsResponse>, Status> {
        Ok(Response::new(StatsResponse {
            total_shreds_received: self.stats.shreds_received.load(Ordering::Relaxed),
            total_entries_decoded: self.stats.entries_decoded.load(Ordering::Relaxed),
            total_slots_processed: self.stats.slots_processed.load(Ordering::Relaxed),
            fec_recoveries: self.stats.fec_recoveries.load(Ordering::Relaxed),
            current_slot: self.stats.current_slot.load(Ordering::Relaxed),
            shreds_per_second: self.shreds_per_second.load(Ordering::Relaxed),
        }))
    }
}

/// UDP receiver thread that listens for shreds
fn start_udp_receiver(
    port: u16,
    sender: Sender<Vec<Vec<u8>>>,
    shutdown: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let socket = match UdpSocket::bind(format!("0.0.0.0:{}", port)) {
            Ok(s) => {
                info!("UDP receiver listening on port {}", port);
                s
            }
            Err(e) => {
                error!("Failed to bind UDP socket on port {}: {}", port, e);
                return;
            }
        };

        // Set non-blocking mode for checking shutdown
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .expect("Failed to set socket timeout");

        let mut buf = vec![0u8; 1280]; // Max shred size
        let mut batch = Vec::with_capacity(32);
        let mut last_send = Instant::now();

        while !shutdown.load(Ordering::Relaxed) {
            match socket.recv(&mut buf) {
                Ok(size) => {
                    batch.push(buf[..size].to_vec());

                    // Send batch when full or after timeout
                    if batch.len() >= 32 || last_send.elapsed() > Duration::from_millis(10) {
                        if sender.send(batch.clone()).is_err() {
                            break; // Receiver dropped
                        }
                        batch.clear();
                        last_send = Instant::now();
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Timeout - check if we have pending data to send
                    if !batch.is_empty() {
                        if sender.send(batch.clone()).is_err() {
                            break;
                        }
                        batch.clear();
                        last_send = Instant::now();
                    }
                }
                Err(e) => {
                    warn!("UDP receive error: {}", e);
                }
            }
        }

        info!("UDP receiver thread shutting down");
    })
}

/// Shred processor thread that performs FEC recovery and deserialization
fn start_shred_processor(
    receiver: Receiver<Vec<Vec<u8>>>,
    entry_sender: broadcast::Sender<Entry>,
    stats: Arc<ShredStats>,
    shreds_per_second: Arc<AtomicU64>,
    shutdown: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut processor = ShredProcessor::new(stats.clone());
        let mut shred_count = 0u64;
        let mut last_stats_time = Instant::now();

        while !shutdown.load(Ordering::Relaxed) {
            match receiver.recv_timeout(Duration::from_millis(100)) {
                Ok(packet_batch) => {
                    let batch_size = packet_batch.len();
                    shred_count += batch_size as u64;

                    // Process shreds and get decoded entries
                    let decoded_entries = processor.process_shreds(packet_batch);

                    // Send decoded entries to gRPC subscribers
                    for (slot, entries, entries_bytes) in decoded_entries {
                        let tx_count = entries.iter().map(|e| e.transactions.len()).sum::<usize>();
                        
                        let entry = Entry {
                            slot,
                            entries: entries_bytes,
                            transaction_count: tx_count as u32,
                            timestamp_ms: SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_millis() as i64,
                        };

                        // Broadcast to all subscribers (ignore if no subscribers)
                        let _ = entry_sender.send(entry);
                    }

                    // Update shreds per second metric
                    if last_stats_time.elapsed() >= Duration::from_secs(1) {
                        shreds_per_second.store(shred_count, Ordering::Relaxed);
                        shred_count = 0;
                        last_stats_time = Instant::now();
                    }
                }
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                    // No data, continue
                }
                Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                    break; // Channel closed
                }
            }
        }

        info!("Shred processor thread shutting down");
    })
}

/// Print statistics periodically
fn start_stats_reporter(stats: Arc<ShredStats>, shreds_per_second: Arc<AtomicU64>) {
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(10));
            
            info!(
                "Stats - Shreds: {}, Entries: {}, Slots: {}, FEC Recoveries: {}, Current Slot: {}, Shreds/sec: {}",
                stats.shreds_received.load(Ordering::Relaxed),
                stats.entries_decoded.load(Ordering::Relaxed),
                stats.slots_processed.load(Ordering::Relaxed),
                stats.fec_recoveries.load(Ordering::Relaxed),
                stats.current_slot.load(Ordering::Relaxed),
                shreds_per_second.load(Ordering::Relaxed),
            );
        }
    });
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command-line arguments
    let args = Args::parse();
    
    // Initialize logger with the specified level
    env_logger::init_from_env(env_logger::Env::new().default_filter_or(&args.log_level));

    info!("Starting Shred Decoder Service");
    info!("UDP Input Port: {}", args.udp_port);
    info!("gRPC Service Port: {}", args.grpc_port);

    // Create shared state
    let stats = Arc::new(ShredStats::default());
    let shreds_per_second = Arc::new(AtomicU64::new(0));
    let shutdown = Arc::new(AtomicBool::new(false));
    let (entry_tx, _entry_rx) = broadcast::channel::<Entry>(1000);

    // Create channel for UDP -> Processor communication
    let (packet_tx, packet_rx) = bounded::<Vec<Vec<u8>>>(100);

    // Start UDP receiver thread with configured port
    let udp_handle = start_udp_receiver(args.udp_port, packet_tx, shutdown.clone());

    // Start shred processor thread
    let processor_handle = start_shred_processor(
        packet_rx,
        entry_tx.clone(),
        stats.clone(),
        shreds_per_second.clone(),
        shutdown.clone(),
    );

    // Start stats reporter
    start_stats_reporter(stats.clone(), shreds_per_second.clone());

    // Setup gRPC service
    let service = ShredDecoderService {
        entry_sender: entry_tx,
        stats: stats.clone(),
        shreds_per_second: shreds_per_second.clone(),
    };

    // Parse gRPC address with configured port
    let addr = format!("0.0.0.0:{}", args.grpc_port).parse()?;
    
    info!("Starting gRPC server on {}", addr);

    // Handle shutdown signals
    let shutdown_clone = shutdown.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.expect("Failed to listen for ctrl+c");
        info!("Received shutdown signal");
        shutdown_clone.store(true, Ordering::Relaxed);
    });

    // Start gRPC server
    Server::builder()
        .add_service(ShredDecoderServer::new(service))
        .serve(addr)
        .await?;

    // Wait for threads to finish
    udp_handle.join().unwrap();
    processor_handle.join().unwrap();

    Ok(())
}
