//! Live Benchmark for Jito Shredstream
//!
//! Just run it and follow the prompts:
//!   cargo run --release --example benchmark_live

use std::net::UdpSocket;
use std::time::{Duration, Instant};
use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::sync::Arc;

use shred_decoder::{ShredPipeline, PipelineEvent, parse_shred};
use shred_decoder::pump::{PumpDetector, PumpConfig, PumpEvent};

fn main() -> std::io::Result<()> {
    println!();
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║         SHRED DECODER LIVE BENCHMARK                             ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!();

    // Interactive setup
    let port = prompt_port();

    println!();
    println!("┌──────────────────────────────────────────────────────────────────┐");
    println!("│ SETUP CHECKLIST                                                  │");
    println!("├──────────────────────────────────────────────────────────────────┤");
    println!("│                                                                  │");
    println!("│  Make sure jito-shredstream-proxy is running and forwarding      │");
    println!("│  shreds to this machine on port {:<5}                           │", port);
    println!("│                                                                  │");
    println!("│  Example shredstream-proxy command:                              │");
    println!("│                                                                  │");
    println!("│    ./jito-shredstream-proxy \\                                    │");
    println!("│      --block-engine-url <JITO_BLOCK_ENGINE> \\                    │");
    println!("│      --auth-keypair ~/keypair.json \\                             │");
    println!("│      --dest-ip-ports <THIS_MACHINE_IP>:{:<5}                    │", port);
    println!("│                                                                  │");
    println!("└──────────────────────────────────────────────────────────────────┘");
    println!();

    print!("Press ENTER when ready to start listening (or Ctrl+C to quit)... ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    run_benchmark(port)
}

fn prompt_port() -> u16 {
    print!("Enter UDP port to listen on [20000]: ");
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let input = input.trim();

    if input.is_empty() {
        20000
    } else {
        input.parse().unwrap_or_else(|_| {
            println!("Invalid port, using default 20000");
            20000
        })
    }
}

fn run_benchmark(port: u16) -> std::io::Result<()> {
    let bind_addr = format!("0.0.0.0:{}", port);
    println!("Binding to {} ...", bind_addr);

    let socket = UdpSocket::bind(&bind_addr)?;
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;

    // Increase receive buffer for high throughput
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = socket.as_raw_fd();
        unsafe {
            let bufsize: libc::c_int = 16 * 1024 * 1024; // 16MB
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &bufsize as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }

    println!();
    println!("✓ Listening for shreds on port {}...", port);
    println!("  (Press Ctrl+C to stop and see final results)");
    println!();

    // Stats
    let stats = Arc::new(Stats::new());
    let stats_clone = stats.clone();

    // Ctrl+C handler
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();
    ctrlc_handler(running_clone, stats_clone);

    // Pipeline and detector
    let mut pipeline = ShredPipeline::new();
    let detector = PumpDetector::with_config(PumpConfig::snipe());

    let mut buf = [0u8; 2048];
    let mut last_report = Instant::now();
    let start_time = Instant::now();
    let mut waiting_printed = false;

    while running.load(Ordering::Relaxed) {
        // Receive packet
        let (len, _src) = match socket.recv_from(&mut buf) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if !waiting_printed && stats.packets_rx.load(Ordering::Relaxed) == 0 {
                    if start_time.elapsed() > Duration::from_secs(3) {
                        println!("  Waiting for shreds... (is shredstream-proxy running?)");
                        waiting_printed = true;
                    }
                }
                // Timeout - print stats if needed
                if last_report.elapsed() > Duration::from_secs(5) && stats.packets_rx.load(Ordering::Relaxed) > 0 {
                    print_live_stats(&stats, start_time.elapsed());
                    last_report = Instant::now();
                }
                continue;
            }
            Err(e) => {
                eprintln!("recv error: {}", e);
                continue;
            }
        };

        // First packet received
        if stats.packets_rx.load(Ordering::Relaxed) == 0 {
            println!("  ✓ Receiving shreds!\n");
        }

        let packet_time = Instant::now();
        stats.packets_rx.fetch_add(1, Ordering::Relaxed);
        stats.bytes_rx.fetch_add(len as u64, Ordering::Relaxed);

        // Time shred parsing
        let parse_start = Instant::now();
        let _shred = match parse_shred(&buf[..len]) {
            Some(s) => s,
            None => {
                stats.parse_failures.fetch_add(1, Ordering::Relaxed);
                continue;
            }
        };
        let parse_time = parse_start.elapsed();
        stats.add_parse_time(parse_time);

        // Time pipeline ingestion (includes FEC tracking + RS decode if needed)
        let ingest_start = Instant::now();
        let event = unsafe { pipeline.ingest(&buf[..len]) };
        let ingest_time = ingest_start.elapsed();
        stats.add_ingest_time(ingest_time);

        match event {
            PipelineEvent::Invalid => {
                stats.invalid.fetch_add(1, Ordering::Relaxed);
            }
            PipelineEvent::Duplicate => {
                stats.duplicates.fetch_add(1, Ordering::Relaxed);
            }
            PipelineEvent::FecDecoded { .. } => {
                stats.fec_decodes.fetch_add(1, Ordering::Relaxed);
                stats.add_fec_time(ingest_time);
            }
            PipelineEvent::BatchReady { slot, batch_idx } => {
                stats.batches.fetch_add(1, Ordering::Relaxed);

                // Time pump detection
                if let Some(data) = pipeline.get_batch(slot, batch_idx) {
                    let detect_start = Instant::now();
                    let result = detector.scan_first_create(data, slot);
                    let detect_time = detect_start.elapsed();
                    stats.add_detect_time(detect_time);

                    if let Some(event) = result {
                        let total_latency = packet_time.elapsed();
                        stats.pump_creates.fetch_add(1, Ordering::Relaxed);
                        stats.add_e2e_time(total_latency);

                        print_detection(&event, slot, detect_time, total_latency);
                    }
                }
            }
            PipelineEvent::BlockComplete { slot, size } => {
                stats.blocks.fetch_add(1, Ordering::Relaxed);
                println!("  Block complete: slot={} size={} bytes", slot, size);
            }
            _ => {}
        }

        // Periodic stats
        if last_report.elapsed() > Duration::from_secs(5) {
            print_live_stats(&stats, start_time.elapsed());
            last_report = Instant::now();
        }
    }

    // Final stats
    println!("\n");
    print_final_stats(&stats, start_time.elapsed());

    Ok(())
}

fn print_detection(event: &PumpEvent, slot: u64, detect_time: Duration, total_latency: Duration) {
    let mint = event.mint();
    let mint_b58 = bs58::encode(mint).into_string();

    println!();
    println!("  🚀 PUMP.FUN CREATE DETECTED!");
    println!("     Slot:           {}", slot);
    println!("     Mint:           {}", mint_b58);
    if let Some(creator) = event.creator() {
        println!("     Creator:        {}", bs58::encode(creator).into_string());
    }
    if let Some(name) = event.name() {
        println!("     Name:           {}", name);
    }
    if let Some(symbol) = event.symbol() {
        println!("     Symbol:         {}", symbol);
    }
    println!("     ─────────────────────────────────────");
    println!("     Detection time: {:?}", detect_time);
    println!("     Total latency:  {:?} (packet → detection)", total_latency);
    println!();
}

fn print_live_stats(stats: &Stats, uptime: Duration) {
    let packets = stats.packets_rx.load(Ordering::Relaxed);
    let creates = stats.pump_creates.load(Ordering::Relaxed);
    let batches = stats.batches.load(Ordering::Relaxed);

    let rate = if uptime.as_secs() > 0 {
        packets / uptime.as_secs()
    } else {
        0
    };

    println!("─── Stats ({:.0}s) ─────────────────────────────────────────────────", uptime.as_secs_f64());
    println!("  Shreds: {} ({}/s) | Batches: {} | Pump Creates: {}", packets, rate, batches, creates);
    println!("  Avg parse: {:?} | Avg ingest: {:?} | Avg detect: {:?}",
             stats.avg_parse_time(),
             stats.avg_ingest_time(),
             stats.avg_detect_time());
    if stats.fec_decodes.load(Ordering::Relaxed) > 0 {
        println!("  FEC decodes: {} | Avg FEC time: {:?}",
                 stats.fec_decodes.load(Ordering::Relaxed),
                 stats.avg_fec_time());
    }
    if creates > 0 {
        println!("  Avg E2E latency: {:?}", stats.avg_e2e_time());
    }
    println!();
}

fn print_final_stats(stats: &Stats, uptime: Duration) {
    let packets = stats.packets_rx.load(Ordering::Relaxed);
    let bytes = stats.bytes_rx.load(Ordering::Relaxed);
    let creates = stats.pump_creates.load(Ordering::Relaxed);

    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║                     FINAL BENCHMARK RESULTS                      ║");
    println!("╠══════════════════════════════════════════════════════════════════╣");
    println!("║                                                                  ║");
    println!("║  Runtime:          {:>12.2}s                                  ║", uptime.as_secs_f64());
    println!("║  Shreds received:  {:>12}                                    ║", packets);
    println!("║  Data received:    {:>12.2} MB                                ║", bytes as f64 / 1_000_000.0);
    println!("║  Shred rate:       {:>12}/s                                  ║", packets / uptime.as_secs().max(1));
    println!("║                                                                  ║");
    println!("╠══════════════════════════════════════════════════════════════════╣");
    println!("║  TIMING (this is what matters for sniping speed)                 ║");
    println!("╠══════════════════════════════════════════════════════════════════╣");
    println!("║                                                                  ║");
    println!("║  Shred parse:      {:>12?}  avg                            ║", stats.avg_parse_time());
    println!("║  Pipeline ingest:  {:>12?}  avg                            ║", stats.avg_ingest_time());
    println!("║  Pump detection:   {:>12?}  avg                            ║", stats.avg_detect_time());

    if stats.fec_decodes.load(Ordering::Relaxed) > 0 {
        println!("║  FEC decode:       {:>12?}  avg ({} decodes)           ║",
                 stats.avg_fec_time(),
                 stats.fec_decodes.load(Ordering::Relaxed));
    }

    println!("║                                                                  ║");

    if creates > 0 {
        println!("╠══════════════════════════════════════════════════════════════════╣");
        println!("║  PUMP.FUN RESULTS                                                ║");
        println!("╠══════════════════════════════════════════════════════════════════╣");
        println!("║                                                                  ║");
        println!("║  Creates detected: {:>12}                                    ║", creates);
        println!("║  E2E latency:      {:>12?}  avg (packet → detection)    ║", stats.avg_e2e_time());
        println!("║                                                                  ║");
    }

    println!("╠══════════════════════════════════════════════════════════════════╣");
    println!("║  ERRORS                                                          ║");
    println!("╠══════════════════════════════════════════════════════════════════╣");
    println!("║                                                                  ║");
    println!("║  Parse failures:   {:>12}                                    ║", stats.parse_failures.load(Ordering::Relaxed));
    println!("║  Invalid shreds:   {:>12}                                    ║", stats.invalid.load(Ordering::Relaxed));
    println!("║  Duplicates:       {:>12}                                    ║", stats.duplicates.load(Ordering::Relaxed));
    println!("║                                                                  ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
}

fn ctrlc_handler(running: Arc<AtomicBool>, _stats: Arc<Stats>) {
    std::thread::spawn(move || {
        let mut signals = signal_hook::iterator::Signals::new(&[signal_hook::consts::SIGINT])
            .expect("Failed to register signal handler");

        for _ in signals.forever() {
            println!("\n\n  Stopping benchmark...");
            running.store(false, Ordering::Relaxed);
            break;
        }
    });
}

// Stats tracking
struct Stats {
    packets_rx: AtomicU64,
    bytes_rx: AtomicU64,
    parse_failures: AtomicU64,
    invalid: AtomicU64,
    duplicates: AtomicU64,
    fec_decodes: AtomicU64,
    batches: AtomicU64,
    blocks: AtomicU64,
    pump_creates: AtomicU64,

    parse_time_sum: AtomicU64,
    parse_time_count: AtomicU64,
    ingest_time_sum: AtomicU64,
    ingest_time_count: AtomicU64,
    detect_time_sum: AtomicU64,
    detect_time_count: AtomicU64,
    fec_time_sum: AtomicU64,
    fec_time_count: AtomicU64,
    e2e_time_sum: AtomicU64,
    e2e_time_count: AtomicU64,
}

impl Stats {
    fn new() -> Self {
        Self {
            packets_rx: AtomicU64::new(0),
            bytes_rx: AtomicU64::new(0),
            parse_failures: AtomicU64::new(0),
            invalid: AtomicU64::new(0),
            duplicates: AtomicU64::new(0),
            fec_decodes: AtomicU64::new(0),
            batches: AtomicU64::new(0),
            blocks: AtomicU64::new(0),
            pump_creates: AtomicU64::new(0),
            parse_time_sum: AtomicU64::new(0),
            parse_time_count: AtomicU64::new(0),
            ingest_time_sum: AtomicU64::new(0),
            ingest_time_count: AtomicU64::new(0),
            detect_time_sum: AtomicU64::new(0),
            detect_time_count: AtomicU64::new(0),
            fec_time_sum: AtomicU64::new(0),
            fec_time_count: AtomicU64::new(0),
            e2e_time_sum: AtomicU64::new(0),
            e2e_time_count: AtomicU64::new(0),
        }
    }

    fn add_parse_time(&self, d: Duration) {
        self.parse_time_sum.fetch_add(d.as_nanos() as u64, Ordering::Relaxed);
        self.parse_time_count.fetch_add(1, Ordering::Relaxed);
    }

    fn add_ingest_time(&self, d: Duration) {
        self.ingest_time_sum.fetch_add(d.as_nanos() as u64, Ordering::Relaxed);
        self.ingest_time_count.fetch_add(1, Ordering::Relaxed);
    }

    fn add_detect_time(&self, d: Duration) {
        self.detect_time_sum.fetch_add(d.as_nanos() as u64, Ordering::Relaxed);
        self.detect_time_count.fetch_add(1, Ordering::Relaxed);
    }

    fn add_fec_time(&self, d: Duration) {
        self.fec_time_sum.fetch_add(d.as_nanos() as u64, Ordering::Relaxed);
        self.fec_time_count.fetch_add(1, Ordering::Relaxed);
    }

    fn add_e2e_time(&self, d: Duration) {
        self.e2e_time_sum.fetch_add(d.as_nanos() as u64, Ordering::Relaxed);
        self.e2e_time_count.fetch_add(1, Ordering::Relaxed);
    }

    fn avg_parse_time(&self) -> Duration {
        let sum = self.parse_time_sum.load(Ordering::Relaxed);
        let count = self.parse_time_count.load(Ordering::Relaxed).max(1);
        Duration::from_nanos(sum / count)
    }

    fn avg_ingest_time(&self) -> Duration {
        let sum = self.ingest_time_sum.load(Ordering::Relaxed);
        let count = self.ingest_time_count.load(Ordering::Relaxed).max(1);
        Duration::from_nanos(sum / count)
    }

    fn avg_detect_time(&self) -> Duration {
        let sum = self.detect_time_sum.load(Ordering::Relaxed);
        let count = self.detect_time_count.load(Ordering::Relaxed).max(1);
        Duration::from_nanos(sum / count)
    }

    fn avg_fec_time(&self) -> Duration {
        let sum = self.fec_time_sum.load(Ordering::Relaxed);
        let count = self.fec_time_count.load(Ordering::Relaxed).max(1);
        Duration::from_nanos(sum / count)
    }

    fn avg_e2e_time(&self) -> Duration {
        let sum = self.e2e_time_sum.load(Ordering::Relaxed);
        let count = self.e2e_time_count.load(Ordering::Relaxed).max(1);
        Duration::from_nanos(sum / count)
    }
}
