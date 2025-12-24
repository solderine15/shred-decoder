use anyhow::Result;
use solana_entry::entry::Entry as SolanaEntry;
use tonic::Request;

// Include the generated proto code
pub mod shredstream {
    tonic::include_proto!("shredstream");
}

use shredstream::{
    shred_decoder_client::ShredDecoderClient, GetStatsRequest, SubscribeEntriesRequest,
};

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    // Connect to the gRPC server
    let mut client = ShredDecoderClient::connect("http://127.0.0.1:50051").await?;

    println!("Connected to Shred Decoder Service");

    // Get initial stats
    let stats_response = client.get_stats(Request::new(GetStatsRequest {})).await?;
    let stats = stats_response.into_inner();
    
    println!("Current Stats:");
    println!("  Total Shreds Received: {}", stats.total_shreds_received);
    println!("  Total Entries Decoded: {}", stats.total_entries_decoded);
    println!("  Total Slots Processed: {}", stats.total_slots_processed);
    println!("  FEC Recoveries: {}", stats.fec_recoveries);
    println!("  Current Slot: {}", stats.current_slot);
    println!("  Shreds/sec: {}", stats.shreds_per_second);
    println!();

    // Subscribe to entry stream
    println!("Subscribing to entry stream...");
    let mut stream = client
        .subscribe_entries(Request::new(SubscribeEntriesRequest {
            slot_filter: vec![], // No filter, receive all slots
        }))
        .await?
        .into_inner();

    // Process incoming entries
    while let Some(entry) = stream.message().await? {
        // Deserialize the entries
        match bincode::deserialize::<Vec<SolanaEntry>>(&entry.entries) {
            Ok(entries) => {
                println!(
                    "Slot {}: {} entries, {} transactions (timestamp: {}ms)",
                    entry.slot,
                    entries.len(),
                    entry.transaction_count,
                    entry.timestamp_ms
                );

                // Print first few transaction signatures
                for (i, solana_entry) in entries.iter().take(3).enumerate() {
                    println!("  Entry {}: {} transactions", i, solana_entry.transactions.len());
                    for (j, tx) in solana_entry.transactions.iter().take(2).enumerate() {
                        if let Some(sig) = tx.signatures.first() {
                            println!("    Tx {}: {}", j, sig);
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to deserialize entries: {}", e);
            }
        }
    }

    Ok(())
}
