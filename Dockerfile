# Build stage
FROM rust:1.75 as builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY proto ./proto
COPY src ./src
COPY build.rs ./

RUN cargo build --release --bin shred-decoder

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/target/release/shred-decoder /app/

# Expose ports
EXPOSE 8002/udp  # UDP input for shreds
EXPOSE 50051     # gRPC service

# Set environment for logging
ENV RUST_LOG=info

# Run the service
CMD ["./shred-decoder"]
