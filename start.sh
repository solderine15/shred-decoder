#!/bin/bash

# Quick start script for Shred Decoder Service

set -e

echo "🚀 Shred Decoder Service - Quick Start"
echo "======================================"

# Check if Rust is installed
if ! command -v cargo &> /dev/null; then
    echo "❌ Rust is not installed. Please install from https://rustup.rs/"
    exit 1
fi

echo "✅ Rust is installed"

# Build the project
echo "📦 Building the project..."
cargo build --release

# Check if build was successful
if [ ! -f "target/release/shred-decoder" ]; then
    echo "❌ Build failed. Please check the error messages above."
    exit 1
fi

echo "✅ Build successful"

# Create a tmux session or use separate terminals
if command -v tmux &> /dev/null; then
    echo "📺 Starting services in tmux session..."
    
    # Kill existing session if it exists
    tmux kill-session -t shred-decoder 2>/dev/null || true
    
    # Create new session
    tmux new-session -d -s shred-decoder -n main
    
    # Start the main service
    tmux send-keys -t shred-decoder:main "RUST_LOG=info ./target/release/shred-decoder" Enter
    
    # Create pane for test sender
    tmux split-window -t shred-decoder:main -h
    tmux send-keys -t shred-decoder:main.1 "echo 'Press Enter to start test sender...'; read; cargo run --release --bin test-sender" Enter
    
    # Create pane for client
    tmux split-window -t shred-decoder:main -v
    tmux send-keys -t shred-decoder:main.2 "echo 'Press Enter to start client...'; read; cargo run --release --bin client" Enter
    
    # Attach to session
    echo "✅ Services started in tmux session 'shred-decoder'"
    echo "📝 Commands:"
    echo "   - Attach to session: tmux attach -t shred-decoder"
    echo "   - Detach: Ctrl+B, then D"
    echo "   - Kill session: tmux kill-session -t shred-decoder"
    echo ""
    echo "Attaching to session in 3 seconds..."
    sleep 3
    tmux attach -t shred-decoder
else
    echo "📺 Starting service (install tmux for better experience)..."
    echo ""
    echo "Run these commands in separate terminals:"
    echo ""
    echo "Terminal 1 - Main Service:"
    echo "  RUST_LOG=info ./target/release/shred-decoder"
    echo ""
    echo "Terminal 2 - Test Sender (optional):"
    echo "  cargo run --release --bin test-sender"
    echo ""
    echo "Terminal 3 - Client (optional):"
    echo "  cargo run --release --bin client"
    echo ""
    echo "Starting main service now..."
    RUST_LOG=info ./target/release/shred-decoder
fi
