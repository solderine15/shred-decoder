# Shred Decoder - Pump.fun Sniper Integration

Ultra-fast Solana shred decoder with pump.fun token detection. Designed for same-slot sniping from raw Jito shredstream data.

## What This Does

1. Receives raw UDP shred packets from Jito shredstream-proxy
2. Decodes shreds (handles FEC/Reed-Solomon recovery when needed)
3. Scans assembled block data for pump.fun create instructions
4. Extracts everything needed to build a buy transaction

## Quick Start

Test with live shreds:
```bash
cargo run --release --bin benchmark
```

---

## Integration Guide

### Step 1: Add Dependency

```toml
[dependencies]
shred-decoder = { path = "/path/to/shred-decoder" }
```

### Step 2: Setup (once at startup)

```rust
use shred_decoder::{ShredPipeline, PipelineEvent};
use shred_decoder::pump::{PumpDetector, PumpConfig};

let mut pipeline = ShredPipeline::new();
let detector = PumpDetector::with_config(PumpConfig::snipe());
```

### Step 3: Main Loop

```rust
use std::net::UdpSocket;

let socket = UdpSocket::bind("0.0.0.0:20000")?;
let mut buf = [0u8; 2048];

loop {
    let len = socket.recv(&mut buf)?;

    match unsafe { pipeline.ingest(&buf[..len]) } {
        PipelineEvent::BatchReady { slot, batch_idx } => {
            if let Some(data) = pipeline.get_batch(slot, batch_idx) {
                if let Some(event) = detector.scan_first_create(data, slot) {
                    // FOUND A CREATE - snipe it!
                    let mint = event.mint();
                    let accounts = event.buy_accounts().unwrap();
                    let creator_sol = event.creator_buy_sol();
                    let creator_tokens = event.creator_buy_tokens();

                    // Build and send your buy tx here
                }
            }
        }
        _ => {}
    }
}
```

---

## API Reference

### PumpConfig Options

```rust
// Default - fastest, extracts only what's needed for buy
PumpConfig::snipe()

// If you need creator address (for whitelist checks)
PumpConfig::snipe_with_creator()

// Absolute minimum - only mint + accounts
PumpConfig::fast()

// Full extraction - includes name, symbol, uri, signature
PumpConfig::full()
```

### PumpEvent Methods

```rust
event.mint()               // -> &[u8; 32]  Token mint address
event.buy_accounts()       // -> Option<&PumpBuyAccounts>  Pre-derived PDAs
event.creator_buy_sol()    // -> Option<u64>  Creator's SOL spent
event.creator_buy_tokens() // -> Option<u64>  Creator's tokens received
event.creator()            // -> Option<&[u8; 32]>  (only with snipe_with_creator)
event.is_token_2022()      // -> bool  True for Token-2022 tokens
```

### PumpBuyAccounts

All accounts pre-derived for building a buy instruction:

```rust
accounts.mint              // Token mint
accounts.bonding_curve     // Bonding curve PDA
accounts.bonding_curve_ata // Bonding curve's token account
accounts.global_state      // Pump global state
accounts.fee_recipient     // Fee recipient
accounts.token_program     // SPL Token or Token-2022
accounts.system_program    // System program
accounts.pump_program      // Pump.fun program
```

### Bonding Curve Math

```rust
use shred_decoder::pump::BondingCurveState;

// Calculate state after creator's buy
let state = BondingCurveState::after_creator_buy(creator_sol, creator_tokens);

// Calculate tokens you get for X SOL
let tokens_out = state.calculate_tokens_out(sol_amount);

// Build buy instruction data (24 bytes)
let ix_data = shred_decoder::pump::build_buy_instruction_data(token_amount, max_sol);
```

---

## Minimal Copy-Paste Example

```rust
use std::net::UdpSocket;
use shred_decoder::{ShredPipeline, PipelineEvent};
use shred_decoder::pump::{PumpDetector, PumpConfig};

fn main() -> std::io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:20000")?;
    let mut pipeline = ShredPipeline::new();
    let detector = PumpDetector::with_config(PumpConfig::snipe());
    let mut buf = [0u8; 2048];

    loop {
        let len = socket.recv(&mut buf)?;

        if let PipelineEvent::BatchReady { slot, batch_idx } =
            unsafe { pipeline.ingest(&buf[..len]) }
        {
            if let Some(data) = pipeline.get_batch(slot, batch_idx) {
                if let Some(event) = detector.scan_first_create(data, slot) {
                    let mint = bs58::encode(event.mint()).into_string();
                    println!("NEW TOKEN: {} slot {}", mint, slot);

                    let accounts = event.buy_accounts().unwrap();
                    // Build tx with accounts.bonding_curve, etc.
                }
            }
        }
    }
}
```

---

## Pipeline Events

```rust
PipelineEvent::BatchReady { slot, batch_idx }  // Scan this for pump events
PipelineEvent::BlockComplete { slot, size }    // Full block done
PipelineEvent::FecDecoded { slot, fec_idx }    // RS recovery happened
PipelineEvent::Duplicate                       // Already had this shred
PipelineEvent::Invalid                         // Bad packet
```

---

## Prerequisites

Jito shredstream-proxy running and forwarding to your machine:

```bash
./jito-shredstream-proxy \
  --block-engine-url <JITO_BLOCK_ENGINE> \
  --auth-keypair ~/keypair.json \
  --dest-ip-ports <YOUR_IP>:20000
```

---

## Troubleshooting

**No shreds received:** Check shredstream-proxy is forwarding to correct IP:port

**Need creator address:** Use `PumpConfig::snipe_with_creator()`

**High parse failures:** Normal to have some, if >10% check network

---

## Technical Details

### Performance
- Sub-microsecond detection when create is early in batch
- ~2-3 microseconds for typical 100-tx batch
- No heap allocations in hot path
- All addresses pre-computed at compile time

### Shred Decoding
- Lagrange O(N²) Reed-Solomon erasure decoding
- SIMD GF(2^8) arithmetic
- Handles both Legacy and Merkle authentication
- Proper FEC set grouping

### Pump Detection
- Scans for 8-byte Anchor discriminators
- First-byte filter before full compare
- Unsafe pointer arithmetic (no bounds checks in hot loop)
- Pre-derived PDAs using const bytes

## License

MIT
