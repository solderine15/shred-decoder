#!/bin/bash

# Simple script to update ports in shred-decoder source code
# Usage: ./update_ports.sh [GRPC_PORT] [UDP_PORT]

GRPC_PORT=${1:-50051}
UDP_PORT=${2:-8002}

echo "========================================="
echo "Shred Decoder Port Configuration Script"
echo "========================================="
echo ""
echo "Configuring ports:"
echo "  gRPC Port: $GRPC_PORT"
echo "  UDP Port:  $UDP_PORT"
echo ""

# Check if src/main.rs exists
if [ ! -f "src/main.rs" ]; then
    echo "Error: src/main.rs not found!"
    echo "Please run this script from the shred-decoder project root."
    exit 1
fi

# Create backup
echo "Creating backup of src/main.rs..."
cp src/main.rs src/main.rs.bak

# Update gRPC port
echo "Updating gRPC port to $GRPC_PORT..."
sed -i.tmp "s/0\.0\.0\.0:50051/0.0.0.0:$GRPC_PORT/g" src/main.rs
sed -i.tmp "s/gRPC Service Port: [0-9]\+/gRPC Service Port: $GRPC_PORT/g" src/main.rs
sed -i.tmp "s/localhost:50051/localhost:$GRPC_PORT/g" src/main.rs

# Update UDP port
echo "Updating UDP port to $UDP_PORT..."
sed -i.tmp "s/start_udp_receiver(8002/start_udp_receiver($UDP_PORT/g" src/main.rs
sed -i.tmp "s/UDP Input Port: 8002/UDP Input Port: $UDP_PORT/g" src/main.rs
sed -i.tmp "s/UDP Port: 8002/UDP Port: $UDP_PORT/g" src/main.rs

# Clean up temp files
rm -f src/main.rs.tmp

# Update client if it exists
if [ -f "src/client.rs" ]; then
    echo "Updating client.rs..."
    cp src/client.rs src/client.rs.bak
    sed -i.tmp "s/127\.0\.0\.1:50051/127.0.0.1:$GRPC_PORT/g" src/client.rs
    sed -i.tmp "s/localhost:50051/localhost:$GRPC_PORT/g" src/client.rs
    rm -f src/client.rs.tmp
fi

# Update test_sender if it exists  
if [ -f "src/test_sender.rs" ]; then
    echo "Updating test_sender.rs..."
    cp src/test_sender.rs src/test_sender.rs.bak
    sed -i.tmp "s/127\.0\.0\.1:8002/127.0.0.1:$UDP_PORT/g" src/test_sender.rs
    sed -i.tmp "s/localhost:8002/localhost:$UDP_PORT/g" src/test_sender.rs
    rm -f src/test_sender.rs.tmp
fi

echo ""
echo "✅ Source files updated successfully!"
echo ""
echo "Next steps:"
echo "1. Build the project:   cargo build --release"
echo "2. Run the service:     ./target/release/shred-decoder"
echo "3. Test UDP:           echo 'test' | nc -u localhost $UDP_PORT"
echo "4. Test gRPC:          grpcurl -plaintext localhost:$GRPC_PORT list"
echo ""
echo "To restore original files: cp src/main.rs.bak src/main.rs"
echo ""
