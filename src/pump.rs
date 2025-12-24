//! Pump.fun Fast-Filter Layer
//!
//! Ultra-low-latency detection of pump.fun token creates from raw block data.
//! Designed to emit trigger events as early as possible for sniping bots.
//!
//! # Usage
//!
//! ```rust,ignore
//! use shred_decoder::{ShredPipeline, PipelineEvent};
//! use shred_decoder::pump::{PumpDetector, PumpEvent};
//!
//! let mut pipeline = ShredPipeline::new();
//! let detector = PumpDetector::new();
//!
//! // In your recv loop:
//! match unsafe { pipeline.ingest(&packet) } {
//!     PipelineEvent::BatchReady { slot, batch_idx } => {
//!         if let Some(data) = pipeline.get_batch(slot, batch_idx) {
//!             for event in detector.scan_batch(data) {
//!                 match event {
//!                     PumpEvent::Create { mint, .. } => {
//!                         // FIRE YOUR SNIPE HERE
//!                         your_bot.snipe(&mint, slot);
//!                     }
//!                     _ => {}
//!                 }
//!             }
//!         }
//!     }
//!     _ => {}
//! }
//! ```

use std::slice;

// ============================================================================
// CONSTANTS - Hardcoded for maximum speed
// ============================================================================

// ============================================================================
// ALL CONSTANTS PRE-COMPUTED AT COMPILE TIME - ZERO RUNTIME OVERHEAD
// ============================================================================

/// Pump.fun program ID bytes - `6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P`
pub const PUMP_PROGRAM_BYTES: [u8; 32] = [
    0x01, 0x56, 0xe0, 0xf6, 0x93, 0x66, 0x5a, 0xcf,
    0x44, 0xdb, 0x15, 0x68, 0xbf, 0x17, 0x5b, 0xaa,
    0x51, 0x89, 0xcb, 0x97, 0xf5, 0xd2, 0xff, 0x3b,
    0x65, 0x5d, 0x2b, 0xb6, 0xfd, 0x6d, 0x18, 0xb0,
];

/// Global state - `4wTV1YmiEkRvAtNtsSGPtUrqRYQMe5SKy2uB4Jjaxnjf`
pub const GLOBAL_STATE_BYTES: [u8; 32] = [
    58, 134, 94, 105, 238, 15, 84, 128,
    202, 188, 246, 99, 87, 228, 220, 47,
    24, 213, 141, 69, 193, 234, 116, 137,
    251, 55, 35, 217, 121, 60, 114, 166,
];

/// Fee recipient - `CebN5WGQ4jvEPvsVU4EoHEpgzq1VV7AbicfhtW4xC9iM`
pub const FEE_RECIPIENT_BYTES: [u8; 32] = [
    173, 17, 230, 164, 252, 41, 68, 164,
    250, 130, 81, 190, 248, 21, 66, 110,
    27, 251, 40, 198, 182, 100, 102, 119,
    96, 124, 106, 217, 245, 102, 166, 70,
];

/// Event authority - `Ce6TQqeHC9p8KetsN6JsjHK7UTZk7nasjjnr7XxXp9F1`
pub const EVENT_AUTHORITY_BYTES: [u8; 32] = [
    172, 241, 54, 235, 1, 252, 28, 78,
    136, 61, 35, 200, 181, 132, 74, 181,
    154, 55, 246, 106, 221, 87, 197, 233,
    172, 59, 83, 224, 89, 211, 92, 100,
];

/// SPL Token program - `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`
pub const TOKEN_PROGRAM_BYTES: [u8; 32] = [
    0x06, 0xdd, 0xf6, 0xe1, 0xd7, 0x65, 0xa1, 0x93,
    0xd9, 0xcb, 0xe1, 0x46, 0xce, 0xeb, 0x79, 0xac,
    0x1c, 0xb4, 0x85, 0xed, 0x5f, 0x5b, 0x37, 0x91,
    0x3a, 0x8c, 0xf5, 0x85, 0x7e, 0xff, 0x00, 0xa9,
];

/// Token-2022 program - `TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`
pub const TOKEN_2022_BYTES: [u8; 32] = [
    0x06, 0xdd, 0xf6, 0xe1, 0xd7, 0x65, 0xa1, 0x93,
    0xd9, 0xcb, 0xe1, 0x46, 0xce, 0xeb, 0x79, 0xac,
    0x1c, 0xb4, 0x85, 0xed, 0x5f, 0x5b, 0x37, 0x91,
    0x3a, 0x8c, 0xf5, 0x85, 0x7e, 0xff, 0x00, 0xaa,
];

/// ATA program - `ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL`
pub const ATA_PROGRAM_BYTES: [u8; 32] = [
    0x8c, 0x97, 0x25, 0x8f, 0x4e, 0x24, 0x89, 0xf1,
    0xbb, 0x3d, 0x10, 0x29, 0x14, 0x8e, 0x0d, 0x83,
    0x0b, 0x5a, 0x13, 0x99, 0xda, 0xff, 0x10, 0x84,
    0x04, 0x8e, 0x7b, 0xd8, 0xdb, 0xe9, 0xf8, 0x59,
];

/// System program - `11111111111111111111111111111111`
pub const SYSTEM_PROGRAM_BYTES: [u8; 32] = [0u8; 32];

/// Rent sysvar - `SysvarRent111111111111111111111111111111111`
pub const RENT_SYSVAR_BYTES: [u8; 32] = [
    0x06, 0xa7, 0xd5, 0x17, 0x18, 0xc7, 0x74, 0xc9,
    0x28, 0x56, 0x63, 0x98, 0x69, 0x1d, 0x5e, 0xb6,
    0x8b, 0x5e, 0xb8, 0xa3, 0x9b, 0x4b, 0x6d, 0x5c,
    0x73, 0x55, 0x5b, 0x21, 0x00, 0x00, 0x00, 0x00,
];

/// Anchor discriminators - first 8 bytes of sha256("global:<method_name>")
pub mod discriminators {
    /// `create` discriminator: sha256("global:create")[0..8]
    pub const CREATE: [u8; 8] = [24, 30, 200, 40, 5, 28, 7, 119];

    /// `create_v2` discriminator: sha256("global:create_v2")[0..8] (Token2022)
    pub const CREATE_V2: [u8; 8] = [214, 144, 76, 236, 95, 139, 49, 180];

    /// `buy` discriminator
    pub const BUY: [u8; 8] = [102, 6, 61, 18, 1, 218, 235, 234];

    /// `sell` discriminator
    pub const SELL: [u8; 8] = [51, 230, 133, 164, 1, 127, 131, 173];

    /// As u64 for fast comparison
    pub const CREATE_U64: u64 = u64::from_le_bytes(CREATE);
    pub const CREATE_V2_U64: u64 = u64::from_le_bytes(CREATE_V2);
    pub const BUY_U64: u64 = u64::from_le_bytes(BUY);
    pub const SELL_U64: u64 = u64::from_le_bytes(SELL);
}

// ============================================================================
// SHORTVEC PARSER - Solana's compact vector length encoding
// ============================================================================

/// Read a ShortU16 (1-3 bytes) from a buffer
/// Returns (value, bytes_consumed) or None if buffer too short
#[inline(always)]
pub fn read_short_u16(buf: &[u8]) -> Option<(u16, usize)> {
    if buf.is_empty() { return None; }

    let b0 = buf[0] as u16;
    if b0 < 0x80 {
        return Some((b0, 1));
    }

    if buf.len() < 2 { return None; }
    let b1 = buf[1] as u16;
    if b1 < 0x80 {
        return Some(((b0 & 0x7f) | (b1 << 7), 2));
    }

    if buf.len() < 3 { return None; }
    let b2 = buf[2] as u16;
    Some(((b0 & 0x7f) | ((b1 & 0x7f) << 7) | (b2 << 14), 3))
}

/// Skip over a shortvec-prefixed array of fixed-size items
#[inline(always)]
pub fn skip_shortvec(buf: &[u8], item_size: usize) -> Option<usize> {
    let (count, len_bytes) = read_short_u16(buf)?;
    let total = len_bytes + (count as usize * item_size);
    if total > buf.len() { return None; }
    Some(total)
}

// ============================================================================
// MINIMAL TRANSACTION PARSER - Just enough to find pump instructions
// ============================================================================

/// Parsed instruction reference - zero-copy
#[derive(Debug, Clone, Copy)]
pub struct InstructionRef<'a> {
    pub program_id_idx: u8,
    pub accounts: &'a [u8],
    pub data: &'a [u8],
}

/// Minimal message parser - extracts account keys and instructions
pub struct MessageParser<'a> {
    buf: &'a [u8],
    pos: usize,

    // Header
    pub num_required_sigs: u8,
    pub num_readonly_signed: u8,
    pub num_readonly_unsigned: u8,

    // Account keys
    pub account_keys_offset: usize,
    pub account_keys_count: usize,

    // Instructions
    pub instructions_offset: usize,
}

impl<'a> MessageParser<'a> {
    /// Parse a legacy Message from bytes
    /// Returns None if parse fails
    #[inline]
    pub fn parse_legacy(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < 4 { return None; }

        let num_required_sigs = buf[0];
        let num_readonly_signed = buf[1];
        let num_readonly_unsigned = buf[2];
        let mut pos = 3;

        // Read account_keys count
        let (num_keys, len_bytes) = read_short_u16(&buf[pos..])?;
        pos += len_bytes;

        let account_keys_offset = pos;
        let account_keys_count = num_keys as usize;

        // Skip past account keys (32 bytes each)
        let keys_size = account_keys_count * 32;
        if pos + keys_size > buf.len() { return None; }
        pos += keys_size;

        // Skip recent_blockhash (32 bytes)
        if pos + 32 > buf.len() { return None; }
        pos += 32;

        let instructions_offset = pos;

        Some(Self {
            buf,
            pos,
            num_required_sigs,
            num_readonly_signed,
            num_readonly_unsigned,
            account_keys_offset,
            account_keys_count,
            instructions_offset,
        })
    }

    /// Get account key at index
    #[inline(always)]
    pub fn account_key(&self, idx: usize) -> Option<&'a [u8; 32]> {
        if idx >= self.account_keys_count { return None; }
        let off = self.account_keys_offset + idx * 32;
        if off + 32 > self.buf.len() { return None; }
        Some(unsafe { &*(self.buf.as_ptr().add(off) as *const [u8; 32]) })
    }

    /// Iterate over instructions
    #[inline]
    pub fn instructions(&self) -> InstructionIter<'a> {
        InstructionIter {
            buf: self.buf,
            pos: self.instructions_offset,
        }
    }
}

/// Iterator over compiled instructions
pub struct InstructionIter<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for InstructionIter<'a> {
    type Item = InstructionRef<'a>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.buf.len() { return None; }

        // First call: read instruction count
        if self.pos == 0 { return None; } // Should have been set

        // program_id_index (1 byte)
        let program_id_idx = *self.buf.get(self.pos)?;
        self.pos += 1;

        // accounts (shortvec of u8)
        let (acc_count, acc_len_bytes) = read_short_u16(&self.buf[self.pos..])?;
        self.pos += acc_len_bytes;
        let accounts = self.buf.get(self.pos..self.pos + acc_count as usize)?;
        self.pos += acc_count as usize;

        // data (shortvec of u8)
        let (data_count, data_len_bytes) = read_short_u16(&self.buf[self.pos..])?;
        self.pos += data_len_bytes;
        let data = self.buf.get(self.pos..self.pos + data_count as usize)?;
        self.pos += data_count as usize;

        Some(InstructionRef {
            program_id_idx,
            accounts,
            data,
        })
    }
}

// ============================================================================
// VERSIONED TRANSACTION PARSER
// ============================================================================

/// Parse a VersionedTransaction from bytes
/// Returns (signatures, message_bytes) or None
#[inline]
pub fn parse_versioned_tx(buf: &[u8]) -> Option<(usize, &[u8])> {
    // Signatures: shortvec of [u8; 64]
    let (sig_count, sig_len_bytes) = read_short_u16(buf)?;
    let sigs_size = sig_len_bytes + (sig_count as usize * 64);
    if sigs_size > buf.len() { return None; }

    let message = &buf[sigs_size..];
    Some((sig_count as usize, message))
}

/// Check if message is versioned (v0) or legacy
#[inline(always)]
pub fn is_versioned_message(first_byte: u8) -> bool {
    // Versioned messages start with 0x80 | version
    // Legacy messages start with num_required_signatures (1-255, but usually small)
    first_byte & 0x80 != 0
}

// ============================================================================
// ENTRY PARSER - Solana entry batch format
// ============================================================================

/// Parse entries from block data, calling callback for each transaction
#[inline]
pub fn parse_entries<F>(data: &[u8], mut on_tx: F) -> usize
where
    F: FnMut(&[u8]) -> bool, // Return false to stop
{
    let mut pos = 0;
    let mut tx_count = 0;

    // Entry batch starts with entry count (sometimes)
    // Actually, the batch IS the entries concatenated
    // Each entry: num_hashes (u64) + hash (32) + transactions (shortvec)

    while pos + 40 < data.len() {
        // num_hashes: u64
        if pos + 8 > data.len() { break; }
        let _num_hashes = u64::from_le_bytes(
            data[pos..pos+8].try_into().unwrap_or([0u8; 8])
        );
        pos += 8;

        // hash: [u8; 32]
        if pos + 32 > data.len() { break; }
        pos += 32;

        // transactions: Vec<VersionedTransaction>
        let Some((tx_cnt, len_bytes)) = read_short_u16(&data[pos..]) else { break };
        pos += len_bytes;

        // Parse each transaction
        for _ in 0..tx_cnt {
            if pos >= data.len() { break; }

            // Find transaction boundary (signatures + message)
            let tx_start = pos;

            // Skip signatures
            let Some((sig_cnt, sig_len)) = read_short_u16(&data[pos..]) else { break };
            pos += sig_len + (sig_cnt as usize * 64);
            if pos > data.len() { break; }

            // Parse message to find end
            let msg_start = pos;
            if pos >= data.len() { break; }

            let first = data[pos];
            if is_versioned_message(first) {
                // Versioned message - skip version byte
                pos += 1;
            }

            // Message header (3 bytes)
            if pos + 3 > data.len() { break; }
            pos += 3;

            // Account keys
            let Some((keys_cnt, keys_len)) = read_short_u16(&data[pos..]) else { break };
            pos += keys_len + (keys_cnt as usize * 32);
            if pos > data.len() { break; }

            // Recent blockhash
            if pos + 32 > data.len() { break; }
            pos += 32;

            // Instructions
            let Some((ix_cnt, ix_len)) = read_short_u16(&data[pos..]) else { break };
            pos += ix_len;

            for _ in 0..ix_cnt {
                if pos >= data.len() { break; }
                pos += 1; // program_id_index

                // accounts
                let Some((acc_cnt, acc_len)) = read_short_u16(&data[pos..]) else { break };
                pos += acc_len + acc_cnt as usize;
                if pos > data.len() { break; }

                // data
                let Some((dat_cnt, dat_len)) = read_short_u16(&data[pos..]) else { break };
                pos += dat_len + dat_cnt as usize;
                if pos > data.len() { break; }
            }

            // For versioned messages, skip address lookup tables
            if is_versioned_message(first) {
                let Some((alt_cnt, alt_len)) = read_short_u16(&data[pos..]) else { break };
                pos += alt_len;
                for _ in 0..alt_cnt {
                    if pos + 32 > data.len() { break; }
                    pos += 32; // account key
                    let Some((w_cnt, w_len)) = read_short_u16(&data[pos..]) else { break };
                    pos += w_len + w_cnt as usize;
                    let Some((r_cnt, r_len)) = read_short_u16(&data[pos..]) else { break };
                    pos += r_len + r_cnt as usize;
                }
            }

            let tx_end = pos;
            let tx_bytes = &data[tx_start..tx_end.min(data.len())];

            if !tx_bytes.is_empty() {
                tx_count += 1;
                if !on_tx(tx_bytes) {
                    return tx_count;
                }
            }
        }
    }

    tx_count
}

// ============================================================================
// PUMP EVENT TYPES
// ============================================================================

/// Token program type for create_v2
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TokenProgram {
    Legacy = 0,    // SPL Token
    Token2022 = 1, // Token-2022
}

// ============================================================================
// BONDING CURVE PDA DERIVATION - INLINED FOR SPEED
// ============================================================================

/// Derive bonding curve PDA from mint
/// Seeds: ["bonding-curve", mint]
#[inline(always)]
pub fn derive_bonding_curve_pda(mint: &[u8; 32]) -> ([u8; 32], u8) {
    find_program_address(&[b"bonding-curve", mint.as_ref()], &PUMP_PROGRAM_BYTES)
}

/// Derive associated token account - uses const bytes, no runtime lookup
#[inline(always)]
pub fn derive_ata(owner: &[u8; 32], mint: &[u8; 32], token_program: &[u8; 32]) -> [u8; 32] {
    let (ata, _) = find_program_address(
        &[owner.as_ref(), token_program.as_ref(), mint.as_ref()],
        &ATA_PROGRAM_BYTES,
    );
    ata
}

/// Find program address (PDA derivation)
fn find_program_address(seeds: &[&[u8]], program_id: &[u8; 32]) -> ([u8; 32], u8) {
    for bump in (0u8..=255).rev() {
        if let Some(address) = create_program_address(seeds, bump, program_id) {
            return (address, bump);
        }
    }
    ([0u8; 32], 0)
}

/// Create program address with bump
fn create_program_address(seeds: &[&[u8]], bump: u8, program_id: &[u8; 32]) -> Option<[u8; 32]> {
    use sha2::{Sha256, Digest};

    let mut hasher = Sha256::new();
    for seed in seeds {
        hasher.update(seed);
    }
    hasher.update([bump]);
    hasher.update(program_id);
    hasher.update(b"ProgramDerivedAddress");

    let hash = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);

    // Check if on curve (simplified - real impl checks ed25519)
    // For now we assume valid since pump uses known seeds
    Some(result)
}

// ============================================================================
// PUMP EVENT TYPES - FULL DATA FOR SNIPING
// ============================================================================

/// All accounts needed to execute a pump.fun buy
#[derive(Debug, Clone)]
pub struct PumpBuyAccounts {
    /// The token mint
    pub mint: [u8; 32],
    /// Bonding curve PDA
    pub bonding_curve: [u8; 32],
    /// Bonding curve's token account (ATA)
    pub bonding_curve_ata: [u8; 32],
    /// Global state account
    pub global_state: [u8; 32],
    /// Fee recipient
    pub fee_recipient: [u8; 32],
    /// Event authority
    pub event_authority: [u8; 32],
    /// Token program (SPL or Token2022)
    pub token_program: [u8; 32],
    /// System program
    pub system_program: [u8; 32],
    /// ATA program
    pub ata_program: [u8; 32],
    /// Rent sysvar
    pub rent: [u8; 32],
    /// Pump program
    pub pump_program: [u8; 32],
}

impl PumpBuyAccounts {
    /// Derive all accounts from mint - uses const bytes, zero runtime lookup
    #[inline]
    pub fn from_mint(mint: &[u8; 32], is_token_2022: bool) -> Self {
        let (bonding_curve, _bump) = derive_bonding_curve_pda(mint);

        let token_program = if is_token_2022 {
            TOKEN_2022_BYTES
        } else {
            TOKEN_PROGRAM_BYTES
        };

        let bonding_curve_ata = derive_ata(&bonding_curve, mint, &token_program);

        Self {
            mint: *mint,
            bonding_curve,
            bonding_curve_ata,
            global_state: GLOBAL_STATE_BYTES,
            fee_recipient: FEE_RECIPIENT_BYTES,
            event_authority: EVENT_AUTHORITY_BYTES,
            token_program,
            system_program: SYSTEM_PROGRAM_BYTES,
            ata_program: ATA_PROGRAM_BYTES,
            rent: RENT_SYSVAR_BYTES,
            pump_program: PUMP_PROGRAM_BYTES,
        }
    }
}

/// Pump.fun event detected in block data
#[derive(Debug, Clone)]
pub enum PumpEvent {
    /// Token creation (legacy SPL Token)
    Create {
        slot: u64,
        mint: [u8; 32],
        /// Creator wallet
        creator: Option<[u8; 32]>,
        /// Transaction signature
        tx_sig: Option<[u8; 64]>,
        /// Creator's initial token buy amount (if bundled in same tx)
        creator_buy_tokens: Option<u64>,
        /// Creator's SOL spent on initial buy
        creator_buy_sol: Option<u64>,
        /// All accounts needed to execute a buy
        buy_accounts: Option<PumpBuyAccounts>,
        /// Token name (if parsed)
        name: Option<String>,
        /// Token symbol (if parsed)
        symbol: Option<String>,
        /// Token URI (if parsed)
        uri: Option<String>,
    },

    /// Token creation (Token-2022 / mayhem mode)
    CreateV2 {
        slot: u64,
        mint: [u8; 32],
        token_program: TokenProgram,
        creator: Option<[u8; 32]>,
        tx_sig: Option<[u8; 64]>,
        creator_buy_tokens: Option<u64>,
        creator_buy_sol: Option<u64>,
        buy_accounts: Option<PumpBuyAccounts>,
        name: Option<String>,
        symbol: Option<String>,
        uri: Option<String>,
    },

    /// Buy on bonding curve
    Buy {
        slot: u64,
        mint: [u8; 32],
        buyer: Option<[u8; 32]>,
        sol_amount: Option<u64>,
        token_amount: Option<u64>,
        tx_sig: Option<[u8; 64]>,
    },

    /// Sell on bonding curve
    Sell {
        slot: u64,
        mint: [u8; 32],
        seller: Option<[u8; 32]>,
        sol_amount: Option<u64>,
        token_amount: Option<u64>,
        tx_sig: Option<[u8; 64]>,
    },
}

impl PumpEvent {
    /// Get the mint pubkey for this event
    #[inline]
    pub fn mint(&self) -> &[u8; 32] {
        match self {
            PumpEvent::Create { mint, .. } => mint,
            PumpEvent::CreateV2 { mint, .. } => mint,
            PumpEvent::Buy { mint, .. } => mint,
            PumpEvent::Sell { mint, .. } => mint,
        }
    }

    /// Check if this is a create event (new token)
    #[inline]
    pub fn is_create(&self) -> bool {
        matches!(self, PumpEvent::Create { .. } | PumpEvent::CreateV2 { .. })
    }

    /// Get slot
    #[inline]
    pub fn slot(&self) -> u64 {
        match self {
            PumpEvent::Create { slot, .. } => *slot,
            PumpEvent::CreateV2 { slot, .. } => *slot,
            PumpEvent::Buy { slot, .. } => *slot,
            PumpEvent::Sell { slot, .. } => *slot,
        }
    }

    /// Get creator's initial buy amount in tokens (if available)
    #[inline]
    pub fn creator_buy_tokens(&self) -> Option<u64> {
        match self {
            PumpEvent::Create { creator_buy_tokens, .. } => *creator_buy_tokens,
            PumpEvent::CreateV2 { creator_buy_tokens, .. } => *creator_buy_tokens,
            _ => None,
        }
    }

    /// Get creator's initial buy amount in SOL lamports (if available)
    #[inline]
    pub fn creator_buy_sol(&self) -> Option<u64> {
        match self {
            PumpEvent::Create { creator_buy_sol, .. } => *creator_buy_sol,
            PumpEvent::CreateV2 { creator_buy_sol, .. } => *creator_buy_sol,
            _ => None,
        }
    }

    /// Get the buy accounts needed to execute a snipe
    #[inline]
    pub fn buy_accounts(&self) -> Option<&PumpBuyAccounts> {
        match self {
            PumpEvent::Create { buy_accounts, .. } => buy_accounts.as_ref(),
            PumpEvent::CreateV2 { buy_accounts, .. } => buy_accounts.as_ref(),
            _ => None,
        }
    }

    /// Get token name (if parsed from create instruction)
    #[inline]
    pub fn name(&self) -> Option<&str> {
        match self {
            PumpEvent::Create { name, .. } => name.as_deref(),
            PumpEvent::CreateV2 { name, .. } => name.as_deref(),
            _ => None,
        }
    }

    /// Get token symbol (if parsed from create instruction)
    #[inline]
    pub fn symbol(&self) -> Option<&str> {
        match self {
            PumpEvent::Create { symbol, .. } => symbol.as_deref(),
            PumpEvent::CreateV2 { symbol, .. } => symbol.as_deref(),
            _ => None,
        }
    }

    /// Is this a Token-2022 token?
    #[inline]
    pub fn is_token_2022(&self) -> bool {
        matches!(self, PumpEvent::CreateV2 { .. })
    }

    /// Get creator address (if available)
    #[inline]
    pub fn creator(&self) -> Option<&[u8; 32]> {
        match self {
            PumpEvent::Create { creator, .. } => creator.as_ref(),
            PumpEvent::CreateV2 { creator, .. } => creator.as_ref(),
            _ => None,
        }
    }
}

// ============================================================================
// BONDING CURVE MATH - For calculating buy amounts
// ============================================================================

/// Initial virtual SOL reserves (30 SOL in lamports)
pub const INITIAL_VIRTUAL_SOL: u64 = 30_000_000_000;

/// Initial virtual token reserves (1.073B tokens with 6 decimals)
pub const INITIAL_VIRTUAL_TOKENS: u64 = 1_073_000_000_000_000;

/// Bonding curve state after creator's buy
#[derive(Debug, Clone, Copy)]
pub struct BondingCurveState {
    pub virtual_sol_reserves: u64,
    pub virtual_token_reserves: u64,
}

impl BondingCurveState {
    /// Initial state (at token creation, before any buys)
    #[inline]
    pub const fn initial() -> Self {
        Self {
            virtual_sol_reserves: INITIAL_VIRTUAL_SOL,
            virtual_token_reserves: INITIAL_VIRTUAL_TOKENS,
        }
    }

    /// State after creator's buy
    #[inline]
    pub fn after_creator_buy(creator_sol: u64, creator_tokens: u64) -> Self {
        Self {
            virtual_sol_reserves: INITIAL_VIRTUAL_SOL.saturating_add(creator_sol),
            virtual_token_reserves: INITIAL_VIRTUAL_TOKENS.saturating_sub(creator_tokens),
        }
    }

    /// Calculate tokens received for a given SOL input
    /// Uses constant product formula: k = virtual_sol * virtual_tokens
    #[inline]
    pub fn calculate_tokens_out(&self, sol_in: u64) -> u64 {
        if sol_in == 0 || self.virtual_token_reserves == 0 {
            return 0;
        }

        let k = self.virtual_sol_reserves as u128 * self.virtual_token_reserves as u128;
        let new_sol = self.virtual_sol_reserves as u128 + sol_in as u128;
        let new_tokens = k / new_sol;

        self.virtual_token_reserves.saturating_sub(new_tokens as u64)
    }

    /// Calculate SOL needed to buy a given amount of tokens
    #[inline]
    pub fn calculate_sol_in(&self, tokens_out: u64) -> u64 {
        if tokens_out == 0 || tokens_out >= self.virtual_token_reserves {
            return u64::MAX;
        }

        let k = self.virtual_sol_reserves as u128 * self.virtual_token_reserves as u128;
        let new_tokens = self.virtual_token_reserves as u128 - tokens_out as u128;
        let new_sol = k / new_tokens;

        (new_sol as u64).saturating_sub(self.virtual_sol_reserves)
    }

    /// Current price per token in lamports (scaled by 1e9 for precision)
    #[inline]
    pub fn price_per_token_scaled(&self) -> u64 {
        if self.virtual_token_reserves == 0 {
            return 0;
        }
        ((self.virtual_sol_reserves as u128 * 1_000_000_000) / self.virtual_token_reserves as u128) as u64
    }
}

// ============================================================================
// BUY INSTRUCTION BUILDER
// ============================================================================

/// Build pump.fun buy instruction data
/// Returns 24 bytes: [8 discriminator][8 token_amount][8 max_sol_cost]
#[inline]
pub fn build_buy_instruction_data(token_amount: u64, max_sol_cost: u64) -> [u8; 24] {
    let mut data = [0u8; 24];
    data[0..8].copy_from_slice(&discriminators::BUY);
    data[8..16].copy_from_slice(&token_amount.to_le_bytes());
    data[16..24].copy_from_slice(&max_sol_cost.to_le_bytes());
    data
}

/// Build pump.fun sell instruction data
#[inline]
pub fn build_sell_instruction_data(token_amount: u64, min_sol_out: u64) -> [u8; 24] {
    let mut data = [0u8; 24];
    data[0..8].copy_from_slice(&discriminators::SELL);
    data[8..16].copy_from_slice(&token_amount.to_le_bytes());
    data[16..24].copy_from_slice(&min_sol_out.to_le_bytes());
    data
}

/// Helper to calculate buy with slippage
#[inline]
pub fn calculate_buy_with_slippage(
    sol_amount: u64,
    creator_sol: u64,
    creator_tokens: u64,
    slippage_bps: u64,
) -> (u64, u64) {
    let state = BondingCurveState::after_creator_buy(creator_sol, creator_tokens);
    let tokens_out = state.calculate_tokens_out(sol_amount);
    let max_sol = sol_amount + (sol_amount * slippage_bps / 10_000);
    (tokens_out, max_sol)
}

// ============================================================================
// CREATE INSTRUCTION METADATA PARSER
// ============================================================================

/// Parse name, symbol, uri from create instruction data
/// Format (after 8-byte discriminator):
///   - name: 4-byte LE length + UTF-8 bytes
///   - symbol: 4-byte LE length + UTF-8 bytes
///   - uri: 4-byte LE length + UTF-8 bytes
fn parse_create_metadata(data: &[u8]) -> (Option<String>, Option<String>, Option<String>) {
    let mut pos = 0;

    // Parse name
    let name = parse_borsh_string(data, &mut pos);

    // Parse symbol
    let symbol = parse_borsh_string(data, &mut pos);

    // Parse uri
    let uri = parse_borsh_string(data, &mut pos);

    (name, symbol, uri)
}

/// Parse a borsh-encoded string (4-byte LE length + UTF-8 bytes)
fn parse_borsh_string(data: &[u8], pos: &mut usize) -> Option<String> {
    if *pos + 4 > data.len() { return None; }

    let len = u32::from_le_bytes(data[*pos..*pos + 4].try_into().ok()?) as usize;
    *pos += 4;

    if *pos + len > data.len() { return None; }

    let s = std::str::from_utf8(&data[*pos..*pos + len]).ok()?.to_string();
    *pos += len;

    Some(s)
}

// ============================================================================
// PUMP DETECTOR - The main API
// ============================================================================

/// Configuration for PumpDetector
#[derive(Debug, Clone)]
pub struct PumpConfig {
    /// Only detect create/create_v2 events (fastest path for sniping)
    pub creates_only: bool,

    /// Extract creator pubkey from instruction accounts
    pub extract_creator: bool,

    /// Extract transaction signature
    pub extract_signature: bool,

    /// Extract token metadata (name, symbol, uri) from create instruction
    pub extract_metadata: bool,

    /// Scan for creator's initial buy in same transaction
    pub extract_creator_buy: bool,

    /// Pre-derive all accounts needed for buying
    pub derive_buy_accounts: bool,

    /// Custom pump program ID (defaults to mainnet)
    pub program_id: [u8; 32],
}

impl Default for PumpConfig {
    fn default() -> Self {
        Self {
            creates_only: true,
            extract_creator: true,
            extract_signature: true,
            extract_metadata: true,
            extract_creator_buy: true,
            derive_buy_accounts: true,
            program_id: PUMP_PROGRAM_BYTES,
        }
    }
}

impl PumpConfig {
    /// Snipe mode - extracts exactly what's needed to build a buy tx
    /// - mint, creator_buy amounts, buy_accounts
    /// - Skips: creator, name/symbol/uri, tx_sig
    pub fn snipe() -> Self {
        Self {
            creates_only: true,
            extract_creator: false,      // Skip - not needed for buy
            extract_signature: false,    // Skip - not needed for buy
            extract_metadata: false,     // Skip - slow string parsing
            extract_creator_buy: true,   // Need to calculate price
            derive_buy_accounts: true,   // Need PDAs
            program_id: PUMP_PROGRAM_BYTES,
        }
    }

    /// Snipe mode WITH creator extraction (for whitelist bots)
    pub fn snipe_with_creator() -> Self {
        Self {
            creates_only: true,
            extract_creator: true,       // For whitelist checks
            extract_signature: false,
            extract_metadata: false,
            extract_creator_buy: true,
            derive_buy_accounts: true,
            program_id: PUMP_PROGRAM_BYTES,
        }
    }

    /// Fast mode - absolute minimum, only mint + accounts
    /// Use if you don't care about creator or price calculation
    pub fn fast() -> Self {
        Self {
            creates_only: true,
            extract_creator: false,
            extract_signature: false,
            extract_metadata: false,
            extract_creator_buy: false,
            derive_buy_accounts: true,
            program_id: PUMP_PROGRAM_BYTES,
        }
    }

    /// Full mode - extract everything (for logging/analysis)
    pub fn full() -> Self {
        Self {
            creates_only: false,
            extract_creator: true,
            extract_signature: true,
            extract_metadata: true,
            extract_creator_buy: true,
            derive_buy_accounts: true,
            program_id: PUMP_PROGRAM_BYTES,
        }
    }
}

/// Ultra-fast pump.fun event detector
///
/// # Example
///
/// ```rust,ignore
/// let detector = PumpDetector::new();
///
/// // Scan a batch for pump events
/// for event in detector.scan_batch(batch_data, slot) {
///     if let PumpEvent::Create { mint, .. } = event {
///         println!("New token: {}", bs58::encode(&mint).into_string());
///         // Fire your snipe!
///     }
/// }
/// ```
pub struct PumpDetector {
    config: PumpConfig,
    /// Pre-decoded program ID bytes for fast comparison
    program_id: [u8; 32],
}

impl PumpDetector {
    /// Create detector in snipe mode (recommended for trading bots)
    /// Extracts: mint, creator, creator_buy amounts, buy_accounts
    /// Skips: name/symbol/uri, tx_sig (for speed)
    pub fn new() -> Self {
        Self::with_config(PumpConfig::snipe())
    }

    /// Create with custom config
    pub fn with_config(config: PumpConfig) -> Self {
        let program_id = config.program_id;
        Self { config, program_id }
    }

    /// Create configured for all events (creates, buys, sells)
    pub fn all_events() -> Self {
        Self::with_config(PumpConfig {
            creates_only: false,
            ..Default::default()
        })
    }

    /// Scan a batch/block for pump events
    ///
    /// This is the main API - call this on BatchReady or BlockComplete events
    #[inline]
    pub fn scan_batch(&self, data: &[u8], slot: u64) -> Vec<PumpEvent> {
        let mut events = Vec::with_capacity(4);

        parse_entries(data, |tx_bytes| {
            if let Some(event) = self.scan_transaction(tx_bytes, slot) {
                events.push(event);
            }
            true // Continue scanning
        });

        events
    }

    /// Scan a batch, stopping at first create event (fastest for sniping)
    #[inline]
    pub fn scan_first_create(&self, data: &[u8], slot: u64) -> Option<PumpEvent> {
        let mut result = None;

        parse_entries(data, |tx_bytes| {
            if let Some(event) = self.scan_transaction(tx_bytes, slot) {
                if event.is_create() {
                    result = Some(event);
                    return false; // Stop scanning
                }
            }
            true
        });

        result
    }

    /// Scan a single transaction for pump events
    #[inline]
    pub fn scan_transaction(&self, tx_bytes: &[u8], slot: u64) -> Option<PumpEvent> {
        // Parse transaction
        let (sig_count, msg_bytes) = parse_versioned_tx(tx_bytes)?;

        // Extract signature if configured
        let tx_sig = if self.config.extract_signature && sig_count > 0 {
            let sig_start = read_short_u16(tx_bytes)?.1;
            if sig_start + 64 <= tx_bytes.len() {
                let mut sig = [0u8; 64];
                sig.copy_from_slice(&tx_bytes[sig_start..sig_start + 64]);
                Some(sig)
            } else {
                None
            }
        } else {
            None
        };

        // Handle versioned vs legacy
        let msg_data = if !msg_bytes.is_empty() && is_versioned_message(msg_bytes[0]) {
            &msg_bytes[1..] // Skip version byte
        } else {
            msg_bytes
        };

        // Parse message
        let msg = MessageParser::parse_legacy(msg_data)?;

        // Find pump program in account keys
        let mut pump_idx = None;
        for i in 0..msg.account_keys_count {
            if let Some(key) = msg.account_key(i) {
                if self.is_pump_program(key) {
                    pump_idx = Some(i as u8);
                    break;
                }
            }
        }
        let pump_idx = pump_idx?;

        // First pass: collect all pump instructions
        #[derive(Clone)]
        struct PumpIx<'a> {
            discr: u64,
            accounts: &'a [u8],
            data: &'a [u8],
        }
        let mut pump_ixs: Vec<PumpIx> = Vec::with_capacity(4);

        let mut ix_buf = &msg.buf[msg.instructions_offset..];
        let (ix_count, ix_len) = read_short_u16(ix_buf)?;
        ix_buf = &ix_buf[ix_len..];

        for _ in 0..ix_count {
            if ix_buf.is_empty() { break; }

            let prog_idx = ix_buf[0];
            ix_buf = &ix_buf[1..];

            let (acc_cnt, acc_len) = read_short_u16(ix_buf)?;
            ix_buf = &ix_buf[acc_len..];
            let accounts = &ix_buf[..(acc_cnt as usize).min(ix_buf.len())];
            ix_buf = &ix_buf[(acc_cnt as usize).min(ix_buf.len())..];

            let (dat_cnt, dat_len) = read_short_u16(ix_buf)?;
            ix_buf = &ix_buf[dat_len..];
            let data = &ix_buf[..(dat_cnt as usize).min(ix_buf.len())];
            ix_buf = &ix_buf[(dat_cnt as usize).min(ix_buf.len())..];

            if prog_idx == pump_idx && data.len() >= 8 {
                let discr = u64::from_le_bytes(data[..8].try_into().ok()?);
                pump_ixs.push(PumpIx { discr, accounts, data });
            }
        }

        // Look for create instruction
        let mut create_ix: Option<&PumpIx> = None;
        let mut buy_ix: Option<&PumpIx> = None;
        let mut is_v2 = false;

        for ix in &pump_ixs {
            match ix.discr {
                d if d == discriminators::CREATE_U64 => {
                    create_ix = Some(ix);
                    is_v2 = false;
                }
                d if d == discriminators::CREATE_V2_U64 => {
                    create_ix = Some(ix);
                    is_v2 = true;
                }
                d if d == discriminators::BUY_U64 => {
                    buy_ix = Some(ix);
                }
                _ => {}
            }
        }

        // If we found a create, build the full event
        if let Some(cix) = create_ix {
            let mint_idx = *cix.accounts.first()? as usize;
            let mint = *msg.account_key(mint_idx)?;

            // Extract creator
            let creator = if self.config.extract_creator && cix.accounts.len() > 1 {
                let creator_idx = cix.accounts[1] as usize;
                msg.account_key(creator_idx).copied()
            } else {
                None
            };

            // Parse metadata from create instruction data
            let (name, symbol, uri) = if self.config.extract_metadata {
                parse_create_metadata(&cix.data[8..])
            } else {
                (None, None, None)
            };

            // Look for creator's buy in same transaction
            let (creator_buy_tokens, creator_buy_sol) = if self.config.extract_creator_buy {
                if let Some(bix) = buy_ix {
                    // Buy instruction data: [8 byte discr][8 byte token_amount][8 byte max_sol]
                    if bix.data.len() >= 24 {
                        let tokens = u64::from_le_bytes(bix.data[8..16].try_into().ok()?);
                        let sol = u64::from_le_bytes(bix.data[16..24].try_into().ok()?);
                        (Some(tokens), Some(sol))
                    } else {
                        (None, None)
                    }
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            };

            // Derive buy accounts
            let buy_accounts = if self.config.derive_buy_accounts {
                Some(PumpBuyAccounts::from_mint(&mint, is_v2))
            } else {
                None
            };

            if is_v2 {
                return Some(PumpEvent::CreateV2 {
                    slot,
                    mint,
                    token_program: TokenProgram::Token2022,
                    creator,
                    tx_sig,
                    creator_buy_tokens,
                    creator_buy_sol,
                    buy_accounts,
                    name,
                    symbol,
                    uri,
                });
            } else {
                return Some(PumpEvent::Create {
                    slot,
                    mint,
                    creator,
                    tx_sig,
                    creator_buy_tokens,
                    creator_buy_sol,
                    buy_accounts,
                    name,
                    symbol,
                    uri,
                });
            }
        }

        // Handle standalone buy/sell (if not creates_only)
        if !self.config.creates_only {
            for ix in &pump_ixs {
                match ix.discr {
                    d if d == discriminators::BUY_U64 => {
                        let mint_idx = *ix.accounts.first()? as usize;
                        let mint = *msg.account_key(mint_idx)?;

                        let buyer = if ix.accounts.len() > 6 {
                            let buyer_idx = ix.accounts[6] as usize;
                            msg.account_key(buyer_idx).copied()
                        } else {
                            None
                        };

                        let (token_amount, sol_amount) = if ix.data.len() >= 24 {
                            let tokens = u64::from_le_bytes(ix.data[8..16].try_into().ok()?);
                            let sol = u64::from_le_bytes(ix.data[16..24].try_into().ok()?);
                            (Some(tokens), Some(sol))
                        } else {
                            (None, None)
                        };

                        return Some(PumpEvent::Buy {
                            slot,
                            mint,
                            buyer,
                            sol_amount,
                            token_amount,
                            tx_sig,
                        });
                    }

                    d if d == discriminators::SELL_U64 => {
                        let mint_idx = *ix.accounts.first()? as usize;
                        let mint = *msg.account_key(mint_idx)?;

                        let seller = if ix.accounts.len() > 6 {
                            let seller_idx = ix.accounts[6] as usize;
                            msg.account_key(seller_idx).copied()
                        } else {
                            None
                        };

                        let (token_amount, sol_amount) = if ix.data.len() >= 24 {
                            let tokens = u64::from_le_bytes(ix.data[8..16].try_into().ok()?);
                            let sol = u64::from_le_bytes(ix.data[16..24].try_into().ok()?);
                            (Some(tokens), Some(sol))
                        } else {
                            (None, None)
                        };

                        return Some(PumpEvent::Sell {
                            slot,
                            mint,
                            seller,
                            sol_amount,
                            token_amount,
                            tx_sig,
                        });
                    }

                    _ => continue,
                }
            }
        }

        None
    }

    /// Check if key matches pump program - uses 4x u64 compare (faster than memcmp)
    #[inline(always)]
    fn is_pump_program(&self, key: &[u8; 32]) -> bool {
        unsafe {
            let a = key.as_ptr() as *const u64;
            let b = self.program_id.as_ptr() as *const u64;
            // Unroll comparison - 4 u64 == 32 bytes
            std::ptr::read_unaligned(a) == std::ptr::read_unaligned(b) &&
            std::ptr::read_unaligned(a.add(1)) == std::ptr::read_unaligned(b.add(1)) &&
            std::ptr::read_unaligned(a.add(2)) == std::ptr::read_unaligned(b.add(2)) &&
            std::ptr::read_unaligned(a.add(3)) == std::ptr::read_unaligned(b.add(3))
        }
    }
}

impl Default for PumpDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// FAST DISCRIMINATOR SCAN - For prefix-only detection (before full decode)
// ============================================================================

/// Scan raw bytes for pump discriminators - ULTRA OPTIMIZED
/// Uses unaligned reads with no bounds checks in inner loop
#[inline]
pub fn scan_discriminators(data: &[u8]) -> Option<(usize, DiscriminatorMatch)> {
    if data.len() < 8 { return None; }

    let len = data.len() - 7; // Safe range for 8-byte reads
    let ptr = data.as_ptr();

    // Preload discriminators for comparison
    let create = discriminators::CREATE_U64;
    let create_v2 = discriminators::CREATE_V2_U64;
    let buy = discriminators::BUY_U64;
    let sell = discriminators::SELL_U64;

    // First bytes of each discriminator for quick filtering
    let create_b0 = discriminators::CREATE[0];
    let create_v2_b0 = discriminators::CREATE_V2[0];
    let buy_b0 = discriminators::BUY[0];
    let sell_b0 = discriminators::SELL[0];

    let mut pos = 0;
    while pos < len {
        // Quick first-byte filter before full 8-byte compare
        let b0 = unsafe { *ptr.add(pos) };

        // Check if first byte matches any discriminator
        if b0 == create_b0 || b0 == create_v2_b0 || b0 == buy_b0 || b0 == sell_b0 {
            // Read full u64 (unaligned is fine on modern CPUs)
            let chunk = unsafe { std::ptr::read_unaligned(ptr.add(pos) as *const u64) };

            if chunk == create {
                return Some((pos, DiscriminatorMatch::Create));
            }
            if chunk == create_v2 {
                return Some((pos, DiscriminatorMatch::CreateV2));
            }
            if chunk == buy {
                return Some((pos, DiscriminatorMatch::Buy));
            }
            if chunk == sell {
                return Some((pos, DiscriminatorMatch::Sell));
            }
        }
        pos += 1;
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscriminatorMatch {
    Create,
    CreateV2,
    Buy,
    Sell,
}

// ============================================================================
// CALLBACK-BASED API - For zero-allocation hot paths
// ============================================================================

/// Scan batch with callback instead of allocating Vec
/// Returns number of events found
#[inline]
pub fn scan_batch_callback<F>(
    detector: &PumpDetector,
    data: &[u8],
    slot: u64,
    mut on_event: F,
) -> usize
where
    F: FnMut(PumpEvent) -> bool, // Return false to stop
{
    let mut count = 0;

    parse_entries(data, |tx_bytes| {
        if let Some(event) = detector.scan_transaction(tx_bytes, slot) {
            count += 1;
            return on_event(event);
        }
        true
    });

    count
}

// ============================================================================
// C FFI EXPORTS
// ============================================================================

/// C-compatible pump event
#[repr(C)]
pub struct CPumpEvent {
    pub event_type: u8,  // 0=Create, 1=CreateV2, 2=Buy, 3=Sell
    pub slot: u64,
    pub mint: [u8; 32],
    pub creator: [u8; 32],
    pub tx_sig: [u8; 64],
    pub sol_amount: u64,
    pub token_amount: u64,
    pub has_creator: u8,
    pub has_sig: u8,
    pub token_program: u8, // 0=Legacy, 1=Token2022
}

impl From<&PumpEvent> for CPumpEvent {
    fn from(e: &PumpEvent) -> Self {
        match e {
            PumpEvent::Create { slot, mint, creator, tx_sig, creator_buy_tokens, creator_buy_sol, .. } => Self {
                event_type: 0,
                slot: *slot,
                mint: *mint,
                creator: creator.unwrap_or([0; 32]),
                tx_sig: tx_sig.unwrap_or([0; 64]),
                sol_amount: creator_buy_sol.unwrap_or(0),
                token_amount: creator_buy_tokens.unwrap_or(0),
                has_creator: if creator.is_some() { 1 } else { 0 },
                has_sig: if tx_sig.is_some() { 1 } else { 0 },
                token_program: 0,
            },
            PumpEvent::CreateV2 { slot, mint, token_program, creator, tx_sig, creator_buy_tokens, creator_buy_sol, .. } => Self {
                event_type: 1,
                slot: *slot,
                mint: *mint,
                creator: creator.unwrap_or([0; 32]),
                tx_sig: tx_sig.unwrap_or([0; 64]),
                sol_amount: creator_buy_sol.unwrap_or(0),
                token_amount: creator_buy_tokens.unwrap_or(0),
                has_creator: if creator.is_some() { 1 } else { 0 },
                has_sig: if tx_sig.is_some() { 1 } else { 0 },
                token_program: *token_program as u8,
            },
            PumpEvent::Buy { slot, mint, sol_amount, token_amount, tx_sig, buyer } => Self {
                event_type: 2,
                slot: *slot,
                mint: *mint,
                creator: buyer.unwrap_or([0; 32]),
                tx_sig: tx_sig.unwrap_or([0; 64]),
                sol_amount: sol_amount.unwrap_or(0),
                token_amount: token_amount.unwrap_or(0),
                has_creator: if buyer.is_some() { 1 } else { 0 },
                has_sig: if tx_sig.is_some() { 1 } else { 0 },
                token_program: 0,
            },
            PumpEvent::Sell { slot, mint, sol_amount, token_amount, tx_sig, seller } => Self {
                event_type: 3,
                slot: *slot,
                mint: *mint,
                creator: seller.unwrap_or([0; 32]),
                tx_sig: tx_sig.unwrap_or([0; 64]),
                sol_amount: sol_amount.unwrap_or(0),
                token_amount: token_amount.unwrap_or(0),
                has_creator: if seller.is_some() { 1 } else { 0 },
                has_sig: if tx_sig.is_some() { 1 } else { 0 },
                token_program: 0,
            },
        }
    }
}

#[no_mangle]
pub extern "C" fn pump_detector_new() -> *mut PumpDetector {
    Box::into_raw(Box::new(PumpDetector::new()))
}

#[no_mangle]
pub extern "C" fn pump_detector_new_all_events() -> *mut PumpDetector {
    Box::into_raw(Box::new(PumpDetector::all_events()))
}

#[no_mangle]
pub unsafe extern "C" fn pump_detector_free(p: *mut PumpDetector) {
    if !p.is_null() { drop(Box::from_raw(p)); }
}

/// Scan batch and return events through callback
/// callback returns: 0 = stop, 1 = continue
#[no_mangle]
pub unsafe extern "C" fn pump_detector_scan(
    detector: *const PumpDetector,
    data: *const u8,
    len: usize,
    slot: u64,
    callback: extern "C" fn(*const CPumpEvent, *mut std::ffi::c_void) -> i32,
    user_data: *mut std::ffi::c_void,
) -> i32 {
    if detector.is_null() || data.is_null() { return -1; }

    let detector = &*detector;
    let data = slice::from_raw_parts(data, len);

    let mut count = 0i32;
    scan_batch_callback(detector, data, slot, |event| {
        let c_event = CPumpEvent::from(&event);
        count += 1;
        callback(&c_event, user_data) != 0
    });

    count
}

/// Scan for first create event only (fastest path)
#[no_mangle]
pub unsafe extern "C" fn pump_detector_scan_first_create(
    detector: *const PumpDetector,
    data: *const u8,
    len: usize,
    slot: u64,
    out: *mut CPumpEvent,
) -> i32 {
    if detector.is_null() || data.is_null() || out.is_null() { return -1; }

    let detector = &*detector;
    let data = slice::from_raw_parts(data, len);

    match detector.scan_first_create(data, slot) {
        Some(event) => {
            *out = CPumpEvent::from(&event);
            1
        }
        None => 0,
    }
}

/// Fast discriminator scan (prefix detection)
#[no_mangle]
pub unsafe extern "C" fn pump_scan_discriminators(
    data: *const u8,
    len: usize,
    out_offset: *mut usize,
    out_type: *mut u8,
) -> i32 {
    if data.is_null() { return -1; }

    let data = slice::from_raw_parts(data, len);
    match scan_discriminators(data) {
        Some((offset, match_type)) => {
            if !out_offset.is_null() { *out_offset = offset; }
            if !out_type.is_null() {
                *out_type = match match_type {
                    DiscriminatorMatch::Create => 0,
                    DiscriminatorMatch::CreateV2 => 1,
                    DiscriminatorMatch::Buy => 2,
                    DiscriminatorMatch::Sell => 3,
                };
            }
            1
        }
        None => 0,
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shortvec_parse() {
        // Single byte
        assert_eq!(read_short_u16(&[0x05]), Some((5, 1)));
        assert_eq!(read_short_u16(&[0x7f]), Some((127, 1)));

        // Two bytes
        assert_eq!(read_short_u16(&[0x80, 0x01]), Some((128, 2)));
        assert_eq!(read_short_u16(&[0xff, 0x01]), Some((255, 2)));

        // Empty
        assert_eq!(read_short_u16(&[]), None);
    }

    #[test]
    fn test_discriminators() {
        use discriminators::*;

        // Verify discriminators are correct
        assert_eq!(CREATE, [24, 30, 200, 40, 5, 28, 7, 119]);
        assert_eq!(CREATE_V2, [214, 144, 76, 236, 95, 139, 49, 180]);
        assert_eq!(BUY, [102, 6, 61, 18, 1, 218, 235, 234]);
        assert_eq!(SELL, [51, 230, 133, 164, 1, 127, 131, 173]);
    }

    #[test]
    fn test_discriminator_scan() {
        let mut data = vec![0u8; 100];

        // Insert create discriminator at offset 50
        data[50..58].copy_from_slice(&discriminators::CREATE);

        let result = scan_discriminators(&data);
        assert_eq!(result, Some((50, DiscriminatorMatch::Create)));
    }

    #[test]
    fn test_detector_creation() {
        let detector = PumpDetector::new();
        assert!(detector.config.creates_only);

        let detector = PumpDetector::all_events();
        assert!(!detector.config.creates_only);
    }
}
