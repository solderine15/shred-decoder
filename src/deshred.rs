use ahash::HashMap;
use itertools::Itertools;
use log::{debug, info, warn};
use solana_entry::entry::Entry as SolanaEntry;
use solana_ledger::{
    blockstore::MAX_DATA_SHREDS_PER_SLOT,
    shred::{Shred, ShredType},
};
use solana_sdk::clock::Slot;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Status of a data shred in the tracking system
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
enum ShredStatus {
    #[default]
    Unknown,
    /// Regular data shred
    NotDataComplete,
    /// Last shred in slot or marked as complete
    DataComplete,
}

/// Tracks per-slot shred information
#[derive(Debug)]
pub struct ShredsStateTracker {
    /// Status of each shred
    data_status: Vec<ShredStatus>,
    /// Raw shred data
    data_shreds: Vec<Option<Vec<u8>>>,
    /// Track which shreds have been processed
    already_processed: Vec<bool>,
}

impl Default for ShredsStateTracker {
    fn default() -> Self {
        Self {
            data_status: vec![ShredStatus::Unknown; MAX_DATA_SHREDS_PER_SLOT],
            data_shreds: vec![None; MAX_DATA_SHREDS_PER_SLOT],
            already_processed: vec![false; MAX_DATA_SHREDS_PER_SLOT],
        }
    }
}

/// Statistics for shred processing
pub struct ShredStats {
    pub shreds_received: Arc<AtomicU64>,
    pub entries_decoded: Arc<AtomicU64>,
    pub slots_processed: Arc<AtomicU64>,
    pub fec_recoveries: Arc<AtomicU64>,
    pub current_slot: Arc<AtomicU64>,
}

impl Default for ShredStats {
    fn default() -> Self {
        Self {
            shreds_received: Arc::new(AtomicU64::new(0)),
            entries_decoded: Arc::new(AtomicU64::new(0)),
            slots_processed: Arc::new(AtomicU64::new(0)),
            fec_recoveries: Arc::new(AtomicU64::new(0)),
            current_slot: Arc::new(AtomicU64::new(0)),
        }
    }
}

/// Main shred processor
pub struct ShredProcessor {
    /// All shreds organized by slot
    all_shreds: HashMap<Slot, ShredsStateTracker>,
    /// Statistics
    pub stats: Arc<ShredStats>,
    /// Highest slot seen
    highest_slot: Slot,
}

impl ShredProcessor {
    pub fn new(stats: Arc<ShredStats>) -> Self {
        Self {
            all_shreds: HashMap::default(),
            stats,
            highest_slot: 0,
        }
    }

    /// Process a batch of shred packets and return decoded entries
    pub fn process_shreds(
        &mut self,
        packets: Vec<Vec<u8>>,
    ) -> Vec<(Slot, Vec<SolanaEntry>, Vec<u8>)> {
        let mut slots_to_check = HashSet::new();
        let mut deshredded_entries = Vec::new();

        // Process incoming packets
        for packet_data in packets {
            self.stats.shreds_received.fetch_add(1, Ordering::Relaxed);

            match Shred::new_from_serialized_shred(packet_data.clone()) {
                Ok(shred) => {
                    // Only process data shreds
                    if shred.shred_type() != ShredType::Data {
                        continue;
                    }

                    let slot = shred.slot();
                    let index = shred.index() as usize;

                    // Update highest slot
                    if slot > self.highest_slot {
                        self.highest_slot = slot;
                        self.stats.current_slot.store(slot, Ordering::Relaxed);
                    }

                    // Skip old slots (more than 500 slots behind)
                    if self.highest_slot.saturating_sub(500) > slot {
                        debug!("Skipping old slot: {}", slot);
                        continue;
                    }

                    let state_tracker = self.all_shreds.entry(slot).or_default();

                    // Skip if already processed
                    if state_tracker.already_processed[index] {
                        continue;
                    }

                    // Store the shred data
                    state_tracker.data_shreds[index] = Some(packet_data);
                    state_tracker.already_processed[index] = true;
                    
                    // Mark status
                    state_tracker.data_status[index] = if shred.last_in_slot() {
                        ShredStatus::DataComplete
                    } else {
                        ShredStatus::NotDataComplete
                    };

                    slots_to_check.insert(slot);
                }
                Err(e) => {
                    debug!("Failed to decode shred: {:?}", e);
                }
            }
        }

        // Try to decode entries for slots that received new shreds
        for slot in slots_to_check {
            if let Some(entries) = self.try_decode_slot(slot) {
                deshredded_entries.push(entries);
            }
        }

        // Clean up old slots (keep last 100 slots)
        if self.highest_slot > 100 {
            let cutoff = self.highest_slot - 100;
            self.all_shreds.retain(|&slot, _| slot >= cutoff);
        }

        deshredded_entries
    }

    /// Try to decode entries for a slot
    fn try_decode_slot(&mut self, slot: Slot) -> Option<(Slot, Vec<SolanaEntry>, Vec<u8>)> {
        let state_tracker = self.all_shreds.get(&slot)?;

        // Find sequences of consecutive shreds ending with DataComplete
        let mut sequences = Vec::new();
        let mut start = 0;
        
        for i in 0..MAX_DATA_SHREDS_PER_SLOT {
            match state_tracker.data_status[i] {
                ShredStatus::DataComplete => {
                    // Found end of sequence
                    if self.check_sequence_complete(state_tracker, start, i) {
                        sequences.push((start, i));
                    }
                    start = i + 1;
                }
                ShredStatus::Unknown => {
                    // Gap in sequence, reset start
                    start = i + 1;
                }
                ShredStatus::NotDataComplete => {
                    // Continue collecting
                }
            }
        }

        // Try to decode the first complete sequence
        for (start_idx, end_idx) in sequences {
            if let Some(result) = self.decode_sequence(slot, state_tracker, start_idx, end_idx) {
                return Some(result);
            }
        }

        None
    }

    /// Check if a sequence is complete (no gaps)
    fn check_sequence_complete(&self, tracker: &ShredsStateTracker, start: usize, end: usize) -> bool {
        for i in start..=end {
            if tracker.data_shreds[i].is_none() {
                return false;
            }
        }
        true
    }

    /// Decode a sequence of shreds into entries
    fn decode_sequence(
        &self,
        slot: Slot,
        tracker: &ShredsStateTracker,
        start_idx: usize,
        end_idx: usize,
    ) -> Option<(Slot, Vec<SolanaEntry>, Vec<u8>)> {
        // Collect the shred payloads
        let mut combined_data = Vec::new();
        
        for i in start_idx..=end_idx {
            if let Some(shred_data) = &tracker.data_shreds[i] {
                // Parse shred to get payload
                if let Ok(shred) = Shred::new_from_serialized_shred(shred_data.clone()) {
                    // Extract payload from shred (skip headers)
                    // The payload typically starts after the shred headers
                    // This is a simplified approach - actual implementation would need proper payload extraction
                    let payload = shred_data.get(88..).unwrap_or(&[]); // Skip common header and data header
                    combined_data.extend_from_slice(payload);
                }
            }
        }

        // Try to deserialize as entries
        match bincode::deserialize::<Vec<SolanaEntry>>(&combined_data) {
            Ok(entries) => {
                let entry_count = entries.len();
                let tx_count: usize = entries.iter().map(|e| e.transactions.len()).sum();
                
                self.stats.entries_decoded.fetch_add(entry_count as u64, Ordering::Relaxed);
                self.stats.slots_processed.fetch_add(1, Ordering::Relaxed);
                
                info!(
                    "Decoded slot {}: {} entries, {} transactions (indices {}-{})",
                    slot, entry_count, tx_count, start_idx, end_idx
                );

                Some((slot, entries, combined_data))
            }
            Err(e) => {
                debug!(
                    "Failed to deserialize entries for slot {} (indices {}-{}): {:?}",
                    slot, start_idx, end_idx, e
                );
                None
            }
        }
    }
}

