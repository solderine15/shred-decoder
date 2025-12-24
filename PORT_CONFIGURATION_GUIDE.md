# How to Change the gRPC Port (and UDP Port)

## Method 1: Edit the Source Code (Original Version)

### For gRPC Port
In `src/main.rs`, change line 251:
```rust
// Original
let addr = "0.0.0.0:50051".parse()?;

// Change to your desired port, e.g., 9090
let addr = "0.0.0.0:9090".parse()?;
```

Also update the log message on line 218:
```rust
// Original
info!("gRPC Service Port: 50051");

// Change to match
info!("gRPC Service Port: 9090");
```

### For UDP Port
In `src/main.rs`, change line 169:
```rust
// Original
let udp_handle = start_udp_receiver(8002, packet_tx, shutdown.clone());

// Change to your desired port, e.g., 9000
let udp_handle = start_udp_receiver(9000, packet_tx, shutdown.clone());
```

And update the log message on line 217:
```rust
// Original
info!("UDP Input Port: 8002");

// Change to match
info!("UDP Input Port: 9000");
```

Then rebuild:
```bash
cargo build --release
```

---

## Method 2: Use the Enhanced Configurable Version (Recommended)

Replace your `src/main.rs` with the enhanced version: `main_configurable.rs`
Update your `Cargo.toml` to include `clap` dependency.

### Usage with Command-Line Arguments

```bash
# Use default ports (UDP: 8002, gRPC: 50051)
./target/release/shred-decoder

# Change gRPC port only
./target/release/shred-decoder --grpc-port 9090

# Change UDP port only
./target/release/shred-decoder --udp-port 9000

# Change both ports
./target/release/shred-decoder --udp-port 9000 --grpc-port 9090

# Short form
./target/release/shred-decoder -u 9000 -g 9090

# With custom log level
./target/release/shred-decoder -g 9090 -l debug
```

### Usage with Environment Variables

```bash
# Set via environment variables
export SHRED_UDP_PORT=9000
export SHRED_GRPC_PORT=9090
export RUST_LOG=debug
./target/release/shred-decoder

# Or inline
SHRED_GRPC_PORT=9090 ./target/release/shred-decoder
```

### View Help

```bash
./target/release/shred-decoder --help
```

---

## Method 3: Create a Configuration File Approach

Create a simple wrapper script `run.sh`:

```bash
#!/bin/bash
# Configuration
UDP_PORT=${UDP_PORT:-8002}
GRPC_PORT=${GRPC_PORT:-50051}
LOG_LEVEL=${LOG_LEVEL:-info}

echo "Starting Shred Decoder"
echo "UDP Port: $UDP_PORT"
echo "gRPC Port: $GRPC_PORT"

SHRED_UDP_PORT=$UDP_PORT \
SHRED_GRPC_PORT=$GRPC_PORT \
RUST_LOG=$LOG_LEVEL \
./target/release/shred-decoder
```

Then create a config file `.env`:
```bash
UDP_PORT=9000
GRPC_PORT=9090
LOG_LEVEL=info
```

And run:
```bash
source .env && ./run.sh
```

---

## Method 4: Docker Configuration

If using Docker, update your `docker-compose.yml`:

```yaml
version: '3.8'

services:
  shred-decoder:
    build: .
    container_name: shred-decoder
    ports:
      - "9000:9000/udp"  # Changed UDP port
      - "9090:9090"      # Changed gRPC port
    environment:
      - SHRED_UDP_PORT=9000    # Internal port
      - SHRED_GRPC_PORT=9090   # Internal port
      - RUST_LOG=info
    restart: unless-stopped
```

---

## Method 5: Using a Config File (TOML)

For a more permanent solution, you can modify the code to read from a config file:

1. Add `toml` and `serde` to `Cargo.toml`:
```toml
toml = "0.8"
serde = { version = "1.0", features = ["derive"] }
```

2. Create `config.toml`:
```toml
udp_port = 9000
grpc_port = 9090
log_level = "info"
```

3. Add config loading to main.rs:
```rust
use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
struct Config {
    udp_port: u16,
    grpc_port: u16,
    log_level: String,
}

// In main()
let config_str = fs::read_to_string("config.toml")
    .unwrap_or_else(|_| {
        r#"
        udp_port = 8002
        grpc_port = 50051
        log_level = "info"
        "#.to_string()
    });

let config: Config = toml::from_str(&config_str)?;
```

---

## Client Configuration

Don't forget to update your client to connect to the new gRPC port:

In `src/client.rs`:
```rust
// Original
let mut client = ShredDecoderClient::connect("http://127.0.0.1:50051").await?;

// Change to your new port
let mut client = ShredDecoderClient::connect("http://127.0.0.1:9090").await?;
```

Or make it configurable:
```rust
let grpc_addr = std::env::var("GRPC_SERVER")
    .unwrap_or_else(|_| "http://127.0.0.1:50051".to_string());
let mut client = ShredDecoderClient::connect(grpc_addr).await?;
```

---

## Testing the New Ports

### Test UDP Reception
```bash
# Send test packet to new UDP port
echo "test" | nc -u localhost 9000
```

### Test gRPC Connection
```bash
# Using grpcurl
grpcurl -plaintext localhost:9090 list

# Or test with the client
GRPC_SERVER=http://127.0.0.1:9090 cargo run --bin client
```

---

## Common Port Choices

### Standard Ports
- **50051**: Common gRPC default
- **9090**: Alternative gRPC port
- **8080**: HTTP/gRPC alternative
- **5000-5999**: Common microservice range

### Avoid These Ports
- **80, 443**: Reserved for HTTP/HTTPS
- **22**: SSH
- **3000-3999**: Often used by development servers
- **5432, 3306, 27017**: Database ports
- **8000-8002**: Solana RPC/WebSocket ports

---

## Firewall Configuration

If running on a server, remember to open the new ports:

### UFW (Ubuntu)
```bash
sudo ufw allow 9090/tcp  # gRPC
sudo ufw allow 9000/udp  # Shreds
```

### iptables
```bash
sudo iptables -A INPUT -p tcp --dport 9090 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 9000 -j ACCEPT
```

### AWS Security Group
Add inbound rules:
- Type: Custom TCP, Port: 9090, Source: Your IP/Range
- Type: Custom UDP, Port: 9000, Source: Validator IPs

---

## Quick Setup Script

Create `setup-ports.sh`:
```bash
#!/bin/bash

GRPC_PORT=${1:-50051}
UDP_PORT=${2:-8002}

echo "Configuring ports: UDP=$UDP_PORT, gRPC=$GRPC_PORT"

# Update main.rs (simple sed replacement)
sed -i "s/0.0.0.0:50051/0.0.0.0:$GRPC_PORT/g" src/main.rs
sed -i "s/gRPC Service Port: [0-9]*/gRPC Service Port: $GRPC_PORT/g" src/main.rs
sed -i "s/start_udp_receiver([0-9]*/start_udp_receiver($UDP_PORT/g" src/main.rs
sed -i "s/UDP Input Port: [0-9]*/UDP Input Port: $UDP_PORT/g" src/main.rs

echo "Updated source files. Building..."
cargo build --release

echo "Done! Run with: ./target/release/shred-decoder"
echo "Ports configured: UDP=$UDP_PORT, gRPC=$GRPC_PORT"
```

Usage:
```bash
./setup-ports.sh 9090 9000  # Sets gRPC to 9090, UDP to 9000
```
