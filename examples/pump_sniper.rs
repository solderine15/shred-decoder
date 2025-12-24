//! Pump.fun Sniper Bot Integration Example
//!
//! This example shows how to integrate the shred decoder with a trading bot
//! for ultra-low-latency pump.fun token sniping.
//!
//! ## Quick Start
//!
//! ```bash
//! cargo run --release --example pump_sniper
//! ```
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
//! │ Jito ShredStream│────▶│ ShredPipeline    │────▶│ PumpDetector    │
//! │ UDP :20000      │     │ (FEC + RS decode)│     │ (Fast filter)   │
//! └─────────────────┘     └──────────────────┘     └────────┬────────┘
//!                                                           │
//!                                                           ▼
//!                                                  ┌─────────────────┐
//!                                                  │ YOUR SNIPE CODE │
//!                                                  │ build_buy_tx()  │
//!                                                  │ send_to_jito()  │
//!                                                  └─────────────────┘
//! ```

use std::net::UdpSocket;
use std::time::{Duration, Instant};

use shred_decoder::{ShredPipeline, PipelineEvent};
use shred_decoder::pump::{PumpDetector, PumpEvent, PumpConfig};

// =============================================================================
// YOUR BOT CONFIGURATION - CUSTOMIZE THIS
// =============================================================================

/// Your Jito shredstream proxy endpoint
const SHREDSTREAM_HOST: &str = "127.0.0.1:20000";

/// Maximum SOL to spend per snipe (in lamports)
const MAX_BUY_LAMPORTS: u64 = 100_000_000; // 0.1 SOL

/// Slippage tolerance (basis points)
const SLIPPAGE_BPS: u64 = 500; // 5%

// =============================================================================
// SNIPE HANDLER TRAIT - IMPLEMENT THIS FOR YOUR BOT
// =============================================================================

/// Implement this trait in your trading bot
pub trait SnipeHandler {
    /// Called when a new pump.fun token is detected
    /// Return true to continue listening, false to stop
    fn on_create(&mut self, event: &CreateEvent) -> bool;

    /// Optional: Called on buy events (if detector configured for all events)
    fn on_buy(&mut self, _event: &BuyEvent) -> bool { true }

    /// Optional: Called on sell events
    fn on_sell(&mut self, _event: &SellEvent) -> bool { true }
}

/// Token creation event with all relevant info for sniping
#[derive(Debug, Clone)]
pub struct CreateEvent {
    pub slot: u64,
    pub mint: [u8; 32],
    pub mint_b58: String,
    pub creator: Option<[u8; 32]>,
    pub is_token_2022: bool,
    pub detected_at: Instant,
    /// Creator's initial buy in tokens
    pub creator_buy_tokens: Option<u64>,
    /// Creator's initial buy in SOL lamports
    pub creator_buy_sol: Option<u64>,
    /// All accounts needed to execute a buy
    pub buy_accounts: Option<shred_decoder::pump::PumpBuyAccounts>,
    /// Token name
    pub name: Option<String>,
    /// Token symbol
    pub symbol: Option<String>,
}

#[derive(Debug, Clone)]
pub struct BuyEvent {
    pub slot: u64,
    pub mint: [u8; 32],
    pub sol_amount: Option<u64>,
    pub token_amount: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct SellEvent {
    pub slot: u64,
    pub mint: [u8; 32],
    pub sol_amount: Option<u64>,
    pub token_amount: Option<u64>,
}

// =============================================================================
// SNIPER ENGINE
// =============================================================================

pub struct PumpSniper<H: SnipeHandler> {
    pipeline: ShredPipeline,
    detector: PumpDetector,
    handler: H,
    socket: UdpSocket,

    // Stats
    shreds_received: u64,
    creates_detected: u64,
    start_time: Instant,
}

impl<H: SnipeHandler> PumpSniper<H> {
    /// Create a new sniper with your handler
    pub fn new(handler: H) -> std::io::Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.connect(SHREDSTREAM_HOST)?;

        // Set socket options for low latency
        socket.set_read_timeout(Some(Duration::from_millis(100)))?;

        // Configure detector for creates only (fastest path)
        let config = PumpConfig {
            creates_only: true,
            extract_creator: true,
            extract_signature: true,
            ..Default::default()
        };

        Ok(Self {
            pipeline: ShredPipeline::new(),
            detector: PumpDetector::with_config(config),
            handler,
            socket,
            shreds_received: 0,
            creates_detected: 0,
            start_time: Instant::now(),
        })
    }

    /// Run the sniper loop
    pub fn run(&mut self) -> std::io::Result<()> {
        println!("Pump Sniper started");
        println!("Listening for shreds from {}", SHREDSTREAM_HOST);
        println!("----------------------------------------");

        let mut buf = [0u8; 2048];

        loop {
            // Receive shred packet
            let len = match self.socket.recv(&mut buf) {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            };

            self.shreds_received += 1;

            // Process through pipeline
            let event = unsafe { self.pipeline.ingest(&buf[..len]) };

            match event {
                PipelineEvent::BatchReady { slot, batch_idx } => {
                    // Copy data to avoid borrow issue
                    let data = self.pipeline.get_batch(slot, batch_idx)
                        .map(|d| d.to_vec());
                    if let Some(data) = data {
                        self.scan_data(&data, slot);
                    }
                }
                PipelineEvent::BlockComplete { slot, size: _ } => {
                    // Block complete - scan any remaining batches
                    let data = self.pipeline.get_block(slot)
                        .map(|d| d.to_vec());
                    if let Some(data) = data {
                        self.scan_data(&data, slot);
                    }
                }
                _ => {}
            }
        }
    }

    fn scan_data(&mut self, data: &[u8], slot: u64) {
        // Use scan_first_create for lowest latency
        if let Some(event) = self.detector.scan_first_create(data, slot) {
            let detected_at = Instant::now();
            self.creates_detected += 1;

            match event {
                PumpEvent::Create { mint, creator, creator_buy_tokens, creator_buy_sol, buy_accounts, name, symbol, .. } => {
                    let create_event = CreateEvent {
                        slot,
                        mint,
                        mint_b58: bs58::encode(&mint).into_string(),
                        creator,
                        is_token_2022: false,
                        detected_at,
                        creator_buy_tokens,
                        creator_buy_sol,
                        buy_accounts,
                        name,
                        symbol,
                    };

                    if !self.handler.on_create(&create_event) {
                        std::process::exit(0);
                    }
                }
                PumpEvent::CreateV2 { mint, creator, creator_buy_tokens, creator_buy_sol, buy_accounts, name, symbol, .. } => {
                    let create_event = CreateEvent {
                        slot,
                        mint,
                        mint_b58: bs58::encode(&mint).into_string(),
                        creator,
                        is_token_2022: true,
                        detected_at,
                        creator_buy_tokens,
                        creator_buy_sol,
                        buy_accounts,
                        name,
                        symbol,
                    };

                    if !self.handler.on_create(&create_event) {
                        std::process::exit(0);
                    }
                }
                _ => {}
            }
        }
    }

    /// Get statistics
    pub fn stats(&self) -> SniperStats {
        SniperStats {
            shreds_received: self.shreds_received,
            creates_detected: self.creates_detected,
            uptime_secs: self.start_time.elapsed().as_secs(),
        }
    }
}

#[derive(Debug)]
pub struct SniperStats {
    pub shreds_received: u64,
    pub creates_detected: u64,
    pub uptime_secs: u64,
}

// =============================================================================
// EXAMPLE HANDLER IMPLEMENTATION
// =============================================================================

/// Example handler that just prints events
struct PrintHandler;

impl SnipeHandler for PrintHandler {
    fn on_create(&mut self, event: &CreateEvent) -> bool {
        let latency = event.detected_at.elapsed();

        println!("\n🚀 NEW TOKEN DETECTED!");
        println!("  Slot:    {}", event.slot);
        println!("  Mint:    {}", event.mint_b58);
        if let Some(name) = &event.name {
            println!("  Name:    {}", name);
        }
        if let Some(symbol) = &event.symbol {
            println!("  Symbol:  {}", symbol);
        }
        println!("  Token22: {}", event.is_token_2022);
        if let Some(creator) = &event.creator {
            println!("  Creator: {}", bs58::encode(creator).into_string());
        }
        if let Some(tokens) = event.creator_buy_tokens {
            println!("  Creator Buy: {} tokens", tokens);
        }
        if let Some(sol) = event.creator_buy_sol {
            println!("  Creator SOL: {} lamports ({:.4} SOL)", sol, sol as f64 / 1_000_000_000.0);
        }
        if let Some(accounts) = &event.buy_accounts {
            println!("  Bonding Curve: {}", bs58::encode(&accounts.bonding_curve).into_string());
            println!("  BC Token Acct: {}", bs58::encode(&accounts.bonding_curve_ata).into_string());
        }
        println!("  Latency: {:?}", latency);
        println!();

        // In a real bot, you would:
        // 1. Build the buy transaction using event.buy_accounts
        // 2. Send to Jito bundle or TPU
        // 3. Monitor for confirmation

        true // Continue listening
    }
}

// =============================================================================
// EXAMPLE: INTEGRATE WITH YOUR EXISTING BOT
// =============================================================================

/// Example of a real trading bot handler
#[allow(dead_code)]
struct TradingBotHandler {
    // Your Solana RPC client
    // rpc: solana_client::rpc_client::RpcClient,

    // Your keypair for signing
    // payer: solana_sdk::signer::keypair::Keypair,

    // Jito tip account
    // jito_tip_account: solana_sdk::pubkey::Pubkey,

    // Buy amount in lamports
    buy_amount: u64,
}

#[allow(dead_code)]
impl TradingBotHandler {
    fn new() -> Self {
        Self {
            buy_amount: MAX_BUY_LAMPORTS,
        }
    }

    /// Build a pump.fun buy instruction
    fn build_buy_ix(&self, _mint: &[u8; 32]) -> Vec<u8> {
        // In a real implementation:
        // 1. Create pump buy instruction with:
        //    - mint account
        //    - bonding curve PDA
        //    - your token account (or create ATA)
        //    - SOL amount + slippage
        //
        // Example (pseudo-code):
        // ```
        // let ix = pump_sdk::instruction::buy(
        //     &self.payer.pubkey(),
        //     mint,
        //     self.buy_amount,
        //     min_tokens_out,
        // );
        // ```

        vec![]
    }

    /// Send transaction via Jito for MEV protection
    fn send_via_jito(&self, _tx_bytes: &[u8]) {
        // In a real implementation:
        // 1. Build bundle with tip
        // 2. Send to Jito block engine
        //
        // Example (pseudo-code):
        // ```
        // let bundle = jito_sdk::Bundle::new()
        //     .add_transaction(tx)
        //     .add_tip(self.jito_tip_account, TIP_LAMPORTS);
        // self.jito_client.send_bundle(bundle).await?;
        // ```
    }
}

impl SnipeHandler for TradingBotHandler {
    fn on_create(&mut self, event: &CreateEvent) -> bool {
        println!("Token detected: {} - Building snipe...", event.mint_b58);

        // 1. Build buy instruction
        let _buy_ix = self.build_buy_ix(&event.mint);

        // 2. Send via Jito
        // self.send_via_jito(&tx_bytes);

        println!("Snipe sent for {}", event.mint_b58);
        true
    }
}

// =============================================================================
// MAIN
// =============================================================================

fn main() -> std::io::Result<()> {
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║           PUMP.FUN SNIPER - Shred Decoder Demo            ║");
    println!("╠═══════════════════════════════════════════════════════════╣");
    println!("║ This example shows how to detect new tokens from raw      ║");
    println!("║ Jito shredstream data with nanosecond-level latency.      ║");
    println!("║                                                           ║");
    println!("║ To use in production:                                     ║");
    println!("║ 1. Run jito-shredstream-proxy on port 20000               ║");
    println!("║ 2. Implement SnipeHandler with your trading logic         ║");
    println!("║ 3. Build and send buy transactions via Jito               ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();

    // Use the print handler for demo
    let handler = PrintHandler;

    // Create and run sniper
    let mut sniper = PumpSniper::new(handler)?;
    sniper.run()
}

// =============================================================================
// MINIMAL INTEGRATION (Copy-Paste Ready)
// =============================================================================

/// Minimal integration for your existing codebase
///
/// Copy this function into your bot:
///
/// ```rust,ignore
/// use shred_decoder::{ShredPipeline, PipelineEvent};
/// use shred_decoder::pump::{PumpDetector, PumpEvent};
///
/// fn integrate_shred_decoder(
///     shred_rx: crossbeam::channel::Receiver<Vec<u8>>,
///     create_tx: crossbeam::channel::Sender<[u8; 32]>,
/// ) {
///     let mut pipeline = ShredPipeline::new();
///     let detector = PumpDetector::new();
///
///     while let Ok(packet) = shred_rx.recv() {
///         match unsafe { pipeline.ingest(&packet) } {
///             PipelineEvent::BatchReady { slot, batch_idx } => {
///                 if let Some(data) = pipeline.get_batch(slot, batch_idx) {
///                     if let Some(event) = detector.scan_first_create(data, slot) {
///                         // Send mint to your trading engine
///                         let _ = create_tx.send(*event.mint());
///                     }
///                 }
///             }
///             _ => {}
///         }
///     }
/// }
/// ```
#[allow(dead_code)]
fn minimal_integration_example() {
    // This is a no-op, just for documentation
}
