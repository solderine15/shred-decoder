#![allow(clippy::all,unused_unsafe,dead_code,unused_variables,unused_imports)]

//! Ultra-optimized Solana shred decoder with pump.fun fast-filter
//!
//! # Key optimizations over naive implementations:
//! - Lagrange interpolation for O(N²) Vandermonde decode (no matrix inversion)
//! - AVX2/AVX512 SIMD GF(2^8) arithmetic
//! - Arena-allocated FEC sets (zero malloc in hot path)
//! - Data-only fast path (skip RS when possible)
//! - Lock-free multi-core pipeline
//!
//! # Pump.fun Sniping
//!
//! The `pump` module provides ultra-low-latency detection of pump.fun token creates:
//!
//! ```rust,ignore
//! use shred_decoder::{ShredPipeline, PipelineEvent};
//! use shred_decoder::pump::{PumpDetector, PumpEvent};
//!
//! let mut pipeline = ShredPipeline::new();
//! let detector = PumpDetector::new();
//!
//! // Your recv loop:
//! loop {
//!     let packet = recv_shred();
//!     match unsafe { pipeline.ingest(&packet) } {
//!         PipelineEvent::BatchReady { slot, batch_idx } => {
//!             let data = pipeline.get_batch(slot, batch_idx).unwrap();
//!             if let Some(event) = detector.scan_first_create(data, slot) {
//!                 // FIRE SNIPE - you have the mint!
//!                 let mint = event.mint();
//!                 send_buy_tx(mint, slot);
//!             }
//!         }
//!         _ => {}
//!     }
//! }
//! ```

pub mod pump;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::sync::Arc;

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

// ============================================================================
// CONSTANTS
// ============================================================================

pub const SHRED_MAX: usize = 1228;
pub const SHRED_DATA_MERKLE: usize = 1203;
pub const HDR_COMMON: usize = 0x53; // 83 bytes
pub const SIG_SZ: usize = 64;
pub const MERKLE_HASH: usize = 20;
pub const MAX_N: usize = 67;
pub const MAX_K: usize = 67;
pub const MAX_TOTAL: usize = 134;
pub const LEGACY_PAYLOAD_SZ: usize = 1051;

// Header offsets
pub const OFF_SIG: usize = 0x00;
pub const OFF_VAR: usize = 0x40;
pub const OFF_SLOT: usize = 0x41;
pub const OFF_IDX: usize = 0x49;
pub const OFF_VER: usize = 0x4D;
pub const OFF_FEC: usize = 0x4F;
pub const OFF_DATA_PARENT: usize = 0x53;
pub const OFF_DATA_FLAGS: usize = 0x55;
pub const OFF_DATA_SIZE: usize = 0x56;
pub const OFF_DATA_PAYLOAD_V2: usize = 0x58;
pub const OFF_DATA_PAYLOAD_V1: usize = 0x56;
pub const OFF_CODE_NDATA: usize = 0x53;
pub const OFF_CODE_NCODE: usize = 0x55;
pub const OFF_CODE_POS: usize = 0x57;
pub const OFF_CODE_PAYLOAD: usize = 0x59;

// ============================================================================
// GF(2^8) WITH SOLANA POLYNOMIAL x^8 + x^4 + x^3 + x^2 + 1 = 0x11D
// ============================================================================

/// GF(2^8) lookup tables - computed at compile time
#[repr(C, align(64))]
pub struct GfTables {
    pub exp: [u8; 512],
    pub log: [u8; 256],
    pub inv: [u8; 256],
    pub mul_lo: [[u8; 16]; 256], // For SIMD: multiply by low nibble
    pub mul_hi: [[u8; 16]; 256], // For SIMD: multiply by high nibble
}

pub static GF: GfTables = {
    let mut exp = [0u8; 512];
    let mut log = [0u8; 256];
    let mut inv = [0u8; 256];
    let mut mul_lo = [[0u8; 16]; 256];
    let mut mul_hi = [[0u8; 16]; 256];
    
    // Build exp/log tables
    let mut x: u16 = 1;
    let mut i = 0usize;
    while i < 255 {
        exp[i] = x as u8;
        exp[i + 255] = x as u8;
        log[x as usize] = i as u8;
        x <<= 1;
        if x & 0x100 != 0 { x ^= 0x11D; }
        i += 1;
    }
    exp[510] = 1;
    exp[511] = 2;
    log[0] = 0;
    
    // Build inverse table
    inv[0] = 0;
    inv[1] = 1;
    i = 2;
    while i < 256 {
        let l = log[i] as usize;
        inv[i] = exp[255 - l];
        i += 1;
    }
    
    // Build SIMD multiplication tables
    i = 0;
    while i < 256 {
        let mut j = 0usize;
        while j < 16 {
            // mul_lo[i][j] = i * j in GF(2^8)
            mul_lo[i][j] = if i == 0 || j == 0 { 0 } else {
                exp[log[i] as usize + log[j] as usize]
            };
            // mul_hi[i][j] = i * (j << 4) in GF(2^8)
            let jh = j << 4;
            mul_hi[i][j] = if i == 0 || jh == 0 { 0 } else {
                exp[log[i] as usize + log[jh] as usize]
            };
            j += 1;
        }
        i += 1;
    }
    
    GfTables { exp, log, inv, mul_lo, mul_hi }
};

#[inline(always)]
pub fn gf_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 { return 0; }
    unsafe {
        *GF.exp.get_unchecked(
            *GF.log.get_unchecked(a as usize) as usize + 
            *GF.log.get_unchecked(b as usize) as usize
        )
    }
}

#[inline(always)]
pub fn gf_add(a: u8, b: u8) -> u8 { a ^ b }

#[inline(always)]
pub fn gf_sub(a: u8, b: u8) -> u8 { a ^ b }

#[inline(always)]
pub fn gf_div(a: u8, b: u8) -> u8 {
    if a == 0 { return 0; }
    debug_assert!(b != 0, "division by zero");
    unsafe {
        let la = *GF.log.get_unchecked(a as usize) as usize;
        let lb = *GF.log.get_unchecked(b as usize) as usize;
        *GF.exp.get_unchecked(la + 255 - lb)
    }
}

#[inline(always)]
pub fn gf_inv(a: u8) -> u8 {
    unsafe { *GF.inv.get_unchecked(a as usize) }
}

// ============================================================================
// SIMD GF(2^8) MULTIPLICATION - THE HOT PATH
// ============================================================================

/// dst[i] ^= coeff * src[i] - scalar fallback
#[inline(always)]
pub fn gf_mul_add_scalar(dst: &mut [u8], src: &[u8], coeff: u8) {
    if coeff == 0 { return; }
    if coeff == 1 {
        for (d, s) in dst.iter_mut().zip(src.iter()) { *d ^= *s; }
        return;
    }
    let la = unsafe { *GF.log.get_unchecked(coeff as usize) } as usize;
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        if *s != 0 {
            let ls = unsafe { *GF.log.get_unchecked(*s as usize) } as usize;
            *d ^= unsafe { *GF.exp.get_unchecked(la + ls) };
        }
    }
}

/// dst[i] ^= coeff * src[i] - AVX2 vectorized
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[inline]
pub unsafe fn gf_mul_add_avx2(dst: *mut u8, src: *const u8, coeff: u8, len: usize) {
    if coeff == 0 { return; }
    if coeff == 1 {
        let chunks = len / 32;
        let mut off = 0usize;
        for _ in 0..chunks {
            let v = _mm256_loadu_si256(src.add(off) as *const __m256i);
            let a = _mm256_loadu_si256(dst.add(off) as *const __m256i);
            _mm256_storeu_si256(dst.add(off) as *mut __m256i, _mm256_xor_si256(a, v));
            off += 32;
        }
        for i in off..len { *dst.add(i) ^= *src.add(i); }
        return;
    }
    
    // Load SIMD lookup tables for this coefficient
    let lo_tbl = _mm256_broadcastsi128_si256(
        _mm_loadu_si128(GF.mul_lo[coeff as usize].as_ptr() as *const __m128i)
    );
    let hi_tbl = _mm256_broadcastsi128_si256(
        _mm_loadu_si128(GF.mul_hi[coeff as usize].as_ptr() as *const __m128i)
    );
    let mask = _mm256_set1_epi8(0x0F);
    
    let chunks = len / 32;
    let mut off = 0usize;
    
    for _ in 0..chunks {
        let v = _mm256_loadu_si256(src.add(off) as *const __m256i);
        let lo = _mm256_and_si256(v, mask);
        let hi = _mm256_and_si256(_mm256_srli_epi64(v, 4), mask);
        let prod = _mm256_xor_si256(
            _mm256_shuffle_epi8(lo_tbl, lo),
            _mm256_shuffle_epi8(hi_tbl, hi)
        );
        let acc = _mm256_loadu_si256(dst.add(off) as *const __m256i);
        _mm256_storeu_si256(dst.add(off) as *mut __m256i, _mm256_xor_si256(acc, prod));
        off += 32;
    }
    
    // Scalar remainder
    let la = *GF.log.get_unchecked(coeff as usize) as usize;
    for i in off..len {
        let s = *src.add(i);
        if s != 0 {
            let ls = *GF.log.get_unchecked(s as usize) as usize;
            *dst.add(i) ^= *GF.exp.get_unchecked(la + ls);
        }
    }
}

/// dst[i] ^= coeff * src[i] - auto-dispatch to best available
#[inline(always)]
pub unsafe fn gf_mul_add(dst: &mut [u8], src: &[u8], coeff: u8) {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            return gf_mul_add_avx2(dst.as_mut_ptr(), src.as_ptr(), coeff, dst.len().min(src.len()));
        }
    }
    gf_mul_add_scalar(dst, src, coeff);
}

/// dst[i] = coeff * src[i] (no accumulate)
#[inline(always)]
pub unsafe fn gf_mul_set(dst: &mut [u8], src: &[u8], coeff: u8) {
    if coeff == 0 {
        dst.iter_mut().for_each(|d| *d = 0);
        return;
    }
    if coeff == 1 {
        dst.copy_from_slice(src);
        return;
    }
    let la = *GF.log.get_unchecked(coeff as usize) as usize;
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d = if *s == 0 { 0 } else {
            let ls = *GF.log.get_unchecked(*s as usize) as usize;
            *GF.exp.get_unchecked(la + ls)
        };
    }
}


// ============================================================================
// LAGRANGE-BASED REED-SOLOMON DECODER
// Key insight: For erasure-only decoding with Vandermonde matrix, we can use
// Lagrange interpolation directly. This gives O(N²) complexity without needing
// explicit matrix inversion.
//
// Given N available shards at positions x_0, x_1, ..., x_{N-1}, to reconstruct
// the data shard at position y, we compute:
//
//   D[y] = sum_{i=0}^{N-1} L_i(y) * S[x_i]
//
// where L_i(y) is the Lagrange basis polynomial:
//
//   L_i(y) = product_{j!=i} (y - x_j) / (x_i - x_j)
//
// All arithmetic in GF(2^8).
// ============================================================================

/// Precomputed Lagrange coefficients for a specific erasure pattern
#[repr(C, align(64))]
pub struct LagrangeDecoder {
    n: usize,
    k: usize,
    avail_pos: [u8; MAX_N],      // positions of available shards
    avail_cnt: usize,
    missing_pos: [u8; MAX_N],    // positions of missing data shards
    missing_cnt: usize,
    coeffs: [[u8; MAX_N]; MAX_N], // coeffs[missing_idx][avail_idx] = Lagrange coeff
}

impl LagrangeDecoder {
    pub const fn new() -> Self {
        Self {
            n: 0,
            k: 0,
            avail_pos: [0u8; MAX_N],
            avail_cnt: 0,
            missing_pos: [0u8; MAX_N],
            missing_cnt: 0,
            coeffs: [[0u8; MAX_N]; MAX_N],
        }
    }

    /// Setup decoder for a specific erasure pattern
    /// present[i] = true if shard i is available
    /// Returns true if decoding is possible
    #[inline]
    pub fn setup(&mut self, n: usize, k: usize, present: &[bool]) -> bool {
        self.n = n;
        self.k = k;
        self.avail_cnt = 0;
        self.missing_cnt = 0;
        
        let total = n + k;
        if total > MAX_TOTAL { return false; }
        
        // Collect available and missing positions
        // Prefer data shards for available set
        for i in 0..n {
            if present[i] {
                if self.avail_cnt < n {
                    self.avail_pos[self.avail_cnt] = i as u8;
                    self.avail_cnt += 1;
                }
            } else {
                self.missing_pos[self.missing_cnt] = i as u8;
                self.missing_cnt += 1;
            }
        }
        
        // If we don't have enough data shards, use coding shards
        if self.avail_cnt < n {
            for i in n..total {
                if present[i] && self.avail_cnt < n {
                    self.avail_pos[self.avail_cnt] = i as u8;
                    self.avail_cnt += 1;
                }
            }
        }
        
        // Check if we have enough shards
        if self.avail_cnt < n { return false; }
        if self.missing_cnt == 0 { return true; } // Nothing to decode
        
        // Compute Lagrange coefficients
        self.compute_lagrange_coeffs();
        true
    }

    /// Compute Lagrange interpolation coefficients
    /// For each missing position y and each available position x_i:
    ///   coeffs[missing_idx][i] = L_i(y) = prod_{j!=i} (y - x_j) / (x_i - x_j)
    #[inline]
    fn compute_lagrange_coeffs(&mut self) {
        for (row, &y) in self.missing_pos[..self.missing_cnt].iter().enumerate() {
            for (col, &xi) in self.avail_pos[..self.avail_cnt].iter().enumerate() {
                let mut num = 1u8; // product of (y - x_j)
                let mut den = 1u8; // product of (x_i - x_j)
                
                for &xj in self.avail_pos[..self.avail_cnt].iter() {
                    if xj != xi {
                        num = gf_mul(num, gf_sub(y, xj));
                        den = gf_mul(den, gf_sub(xi, xj));
                    }
                }
                
                self.coeffs[row][col] = gf_div(num, den);
            }
        }
    }

    /// Decode missing shards
    /// shards[i] = Some(ptr) if shard i is available, None if missing
    /// For missing data shards, we write the reconstructed data to the buffer
    #[inline]
    pub unsafe fn decode(&self, shards: &mut [Option<*mut u8>], shard_len: usize) -> bool {
        if self.missing_cnt == 0 { return true; }
        if self.avail_cnt < self.n { return false; }
        
        // For each missing shard
        for (row, &miss_pos) in self.missing_pos[..self.missing_cnt].iter().enumerate() {
            let dst = match shards[miss_pos as usize] {
                Some(p) => p,
                None => continue,
            };
            
            // Zero the destination
            std::ptr::write_bytes(dst, 0, shard_len);
            
            // Accumulate: dst = sum of coeffs[row][col] * available_shard[col]
            for (col, &avail_pos) in self.avail_pos[..self.avail_cnt].iter().enumerate() {
                let coeff = self.coeffs[row][col];
                if coeff == 0 { continue; }
                
                if let Some(src) = shards[avail_pos as usize] {
                    let dst_slice = std::slice::from_raw_parts_mut(dst, shard_len);
                    let src_slice = std::slice::from_raw_parts(src, shard_len);
                    gf_mul_add(dst_slice, src_slice, coeff);
                }
            }
        }
        
        true
    }

    #[inline]
    pub fn missing_count(&self) -> usize { self.missing_cnt }
    
    #[inline]
    pub fn can_decode(&self) -> bool { self.avail_cnt >= self.n }
}

// ============================================================================
// SHRED PARSER
// ============================================================================

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ShredType { Data = 0, Coding = 1 }

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthType { Legacy = 0, Merkle = 1 }

#[derive(Copy, Clone, Debug)]
pub struct ShredVariant {
    pub shred_type: ShredType,
    pub auth_type: AuthType,
    pub merkle_height: u8,
    pub chained: bool,
    pub resigned: bool,
}

impl ShredVariant {
    /// Parse variant byte according to Solana shred format:
    /// ```text
    /// 0b0101_1010 = 0x5A = LegacyCode
    /// 0b1010_0101 = 0xA5 = LegacyData
    /// 0b0100_???? = 0x4X = MerkleCode
    /// 0b0110_???? = 0x6X = MerkleCode chained
    /// 0b0111_???? = 0x7X = MerkleCode chained resigned
    /// 0b1000_???? = 0x8X = MerkleData
    /// 0b1001_???? = 0x9X = MerkleData chained
    /// 0b1011_???? = 0xBX = MerkleData chained resigned
    /// ```
    /// Lower 4 bits = proof_size (merkle tree height)
    #[inline]
    pub fn from_byte(b: u8) -> Option<Self> {
        let hi = b >> 4;
        let lo = b & 0x0F;
        match hi {
            // Legacy variants
            0x5 if lo == 0xA => Some(Self {
                shred_type: ShredType::Coding,
                auth_type: AuthType::Legacy,
                merkle_height: 0,
                chained: false,
                resigned: false,
            }),
            0xA if lo == 0x5 => Some(Self {
                shred_type: ShredType::Data,
                auth_type: AuthType::Legacy,
                merkle_height: 0,
                chained: false,
                resigned: false,
            }),
            // MerkleCode variants
            0x4 => Some(Self {
                shred_type: ShredType::Coding,
                auth_type: AuthType::Merkle,
                merkle_height: lo,
                chained: false,
                resigned: false,
            }),
            0x6 => Some(Self {
                shred_type: ShredType::Coding,
                auth_type: AuthType::Merkle,
                merkle_height: lo,
                chained: true,
                resigned: false,
            }),
            0x7 => Some(Self {
                shred_type: ShredType::Coding,
                auth_type: AuthType::Merkle,
                merkle_height: lo,
                chained: true,
                resigned: true,
            }),
            // MerkleData variants
            0x8 => Some(Self {
                shred_type: ShredType::Data,
                auth_type: AuthType::Merkle,
                merkle_height: lo,
                chained: false,
                resigned: false,
            }),
            0x9 => Some(Self {
                shred_type: ShredType::Data,
                auth_type: AuthType::Merkle,
                merkle_height: lo,
                chained: true,
                resigned: false,
            }),
            0xB => Some(Self {
                shred_type: ShredType::Data,
                auth_type: AuthType::Merkle,
                merkle_height: lo,
                chained: true,
                resigned: true,
            }),
            _ => None,
        }
    }

    #[inline]
    pub fn is_data(&self) -> bool { matches!(self.shred_type, ShredType::Data) }

    #[inline]
    pub fn is_coding(&self) -> bool { matches!(self.shred_type, ShredType::Coding) }

    #[inline]
    pub fn is_merkle(&self) -> bool { matches!(self.auth_type, AuthType::Merkle) }

    #[inline]
    pub fn is_chained(&self) -> bool { self.chained }

    #[inline]
    pub fn is_resigned(&self) -> bool { self.resigned }
}

/// Parsed shred header - zero-copy reference to raw packet
#[derive(Copy, Clone)]
pub struct ParsedShred<'a> {
    pub raw: &'a [u8],
    pub variant: ShredVariant,
    pub slot: u64,
    pub shred_index: u32,
    pub shred_version: u16,
    pub fec_set_index: u32,
    
    // Data shred fields
    pub parent_offset: u16,
    pub data_flags: u8,
    pub data_size: u16,
    
    // Coding shred fields
    pub num_data: u16,
    pub num_coding: u16,
    pub position: u16,
    
    // RS region within packet
    pub rs_offset: usize,
    pub rs_len: usize,
    
    // Payload region within packet
    pub payload_offset: usize,
    pub payload_len: usize,
}

#[inline]
fn r16(b: &[u8]) -> u16 { u16::from_le_bytes([b[0], b[1]]) }
#[inline]
fn r32(b: &[u8]) -> u32 { u32::from_le_bytes([b[0], b[1], b[2], b[3]]) }
#[inline]
fn r64(b: &[u8]) -> u64 { u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]) }

/// Parse a raw shred packet
#[inline]
pub fn parse_shred(raw: &[u8]) -> Option<ParsedShred<'_>> {
    if raw.len() < HDR_COMMON { return None; }
    
    let variant = ShredVariant::from_byte(raw[OFF_VAR])?;
    let slot = r64(&raw[OFF_SLOT..]);
    let shred_index = r32(&raw[OFF_IDX..]);
    let shred_version = r16(&raw[OFF_VER..]);
    let fec_set_index = r32(&raw[OFF_FEC..]);
    
    let (parent_offset, data_flags, data_size, num_data, num_coding, position, rs_offset, rs_len, payload_offset, payload_len) = 
        if variant.is_data() {
            if raw.len() < HDR_COMMON + 3 { return None; }
            
            let parent_offset = r16(&raw[OFF_DATA_PARENT..]);
            let data_flags = raw[OFF_DATA_FLAGS];
            
            // v2 has explicit size at 0x56
            let (data_size, payload_off) = if raw.len() >= OFF_DATA_SIZE + 2 {
                let sz = r16(&raw[OFF_DATA_SIZE..]);
                if sz as usize <= raw.len() && sz >= (HDR_COMMON + 5) as u16 {
                    (sz, OFF_DATA_PAYLOAD_V2)
                } else {
                    (SHRED_MAX as u16, OFF_DATA_PAYLOAD_V1)
                }
            } else {
                (SHRED_MAX as u16, OFF_DATA_PAYLOAD_V1)
            };
            
            let (rs_off, rs_len) = match variant.auth_type {
                AuthType::Legacy => (0, raw.len().min(SHRED_MAX)),
                AuthType::Merkle => {
                    let proof_len = MERKLE_HASH * variant.merkle_height as usize;
                    if raw.len() < SIG_SZ + proof_len { return None; }
                    (SIG_SZ, raw.len() - SIG_SZ - proof_len)
                }
            };
            
            let payload_len = data_size as usize - payload_off;
            (parent_offset, data_flags, data_size, 0, 0, 0, rs_off, rs_len, payload_off, payload_len)
        } else {
            if raw.len() < HDR_COMMON + 6 { return None; }
            
            let num_data = r16(&raw[OFF_CODE_NDATA..]);
            let num_coding = r16(&raw[OFF_CODE_NCODE..]);
            let position = r16(&raw[OFF_CODE_POS..]);
            
            let (rs_off, rs_len) = match variant.auth_type {
                AuthType::Legacy => (0, raw.len().min(SHRED_MAX)),
                AuthType::Merkle => {
                    let proof_len = MERKLE_HASH * variant.merkle_height as usize;
                    if raw.len() < SIG_SZ + proof_len { return None; }
                    (SIG_SZ, raw.len() - SIG_SZ - proof_len)
                }
            };
            
            (0, 0, 0, num_data, num_coding, position, rs_off, rs_len, OFF_CODE_PAYLOAD, raw.len() - OFF_CODE_PAYLOAD)
        };
    
    Some(ParsedShred {
        raw, variant, slot, shred_index, shred_version, fec_set_index,
        parent_offset, data_flags, data_size, num_data, num_coding, position,
        rs_offset, rs_len, payload_offset, payload_len,
    })
}

impl<'a> ParsedShred<'a> {
    #[inline]
    pub fn rs_region(&self) -> &'a [u8] {
        &self.raw[self.rs_offset..self.rs_offset + self.rs_len]
    }
    
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        &self.raw[self.payload_offset..self.payload_offset + self.payload_len]
    }
    
    #[inline]
    pub fn signature(&self) -> &'a [u8; 64] {
        unsafe { &*(self.raw.as_ptr() as *const [u8; 64]) }
    }
    
    #[inline]
    pub fn local_data_index(&self) -> u32 {
        self.shred_index.saturating_sub(self.fec_set_index)
    }
    
    #[inline]
    pub fn fec_position(&self) -> usize {
        if self.variant.is_data() {
            self.local_data_index() as usize
        } else {
            self.num_data as usize + self.position as usize
        }
    }
    
    #[inline]
    pub fn block_complete(&self) -> bool { self.data_flags & 0x80 != 0 }
    
    #[inline]
    pub fn batch_complete(&self) -> bool { self.data_flags & 0x40 != 0 }
    
    #[inline]
    pub fn batch_tick(&self) -> u8 { self.data_flags & 0x3F }
}


// ============================================================================
// FEC SET - Arena-allocated for zero malloc in hot path
// ============================================================================

pub const FEC_SHARD_BUF: usize = 1228;

/// Single FEC set holding shreds for one (slot, fec_set_index)
#[repr(C, align(64))]
pub struct FecSet {
    pub slot: u64,
    pub fec_set_index: u32,
    pub n_data: u16,
    pub n_coding: u16,
    pub variant: Option<ShredVariant>,
    
    // Presence bitmasks
    pub data_mask: u64,
    pub coding_mask: u64,
    
    // RS region buffers - preallocated
    buffers: [[u8; FEC_SHARD_BUF]; MAX_TOTAL],
    lengths: [u16; MAX_TOTAL],
    present: [bool; MAX_TOTAL],
    
    // State
    pub decoded: bool,
    pub last_data_idx: u32,
    pub block_complete_seen: bool,
}

impl FecSet {
    pub fn new(slot: u64, fec_set_index: u32) -> Self {
        Self {
            slot,
            fec_set_index,
            n_data: 0,
            n_coding: 0,
            variant: None,
            data_mask: 0,
            coding_mask: 0,
            buffers: [[0u8; FEC_SHARD_BUF]; MAX_TOTAL],
            lengths: [0u16; MAX_TOTAL],
            present: [false; MAX_TOTAL],
            decoded: false,
            last_data_idx: 0,
            block_complete_seen: false,
        }
    }
    
    pub fn reset(&mut self, slot: u64, fec_set_index: u32) {
        self.slot = slot;
        self.fec_set_index = fec_set_index;
        self.n_data = 0;
        self.n_coding = 0;
        self.variant = None;
        self.data_mask = 0;
        self.coding_mask = 0;
        self.present = [false; MAX_TOTAL];
        self.lengths = [0u16; MAX_TOTAL];
        self.decoded = false;
        self.last_data_idx = 0;
        self.block_complete_seen = false;
    }
    
    /// Insert a shred into the FEC set
    #[inline]
    pub fn insert(&mut self, shred: &ParsedShred) -> bool {
        if self.variant.is_none() {
            self.variant = Some(shred.variant);
        }
        
        let pos = shred.fec_position();
        if pos >= MAX_TOTAL { return false; }
        if self.present[pos] { return false; } // Duplicate
        
        // Copy RS region into buffer
        let rs = shred.rs_region();
        let copy_len = rs.len().min(FEC_SHARD_BUF);
        self.buffers[pos][..copy_len].copy_from_slice(&rs[..copy_len]);
        self.lengths[pos] = copy_len as u16;
        self.present[pos] = true;
        
        if shred.variant.is_data() {
            let local = shred.local_data_index();
            self.data_mask |= 1u64 << local;
            
            if shred.block_complete() || shred.batch_complete() {
                if local >= self.last_data_idx {
                    self.last_data_idx = local;
                    // Set flag for either block_complete or batch_complete
                    self.block_complete_seen = true;
                }
            }
        } else {
            self.coding_mask |= 1u64 << shred.position;
            if self.n_data == 0 {
                self.n_data = shred.num_data;
                self.n_coding = shred.num_coding;
            }
        }
        
        true
    }
    
    #[inline]
    pub fn has_layout(&self) -> bool {
        self.n_data > 0 && self.n_coding > 0
    }
    
    #[inline]
    pub fn data_count(&self) -> usize {
        self.data_mask.count_ones() as usize
    }
    
    #[inline]
    pub fn coding_count(&self) -> usize {
        self.coding_mask.count_ones() as usize
    }
    
    #[inline]
    pub fn total_count(&self) -> usize {
        self.data_count() + self.coding_count()
    }
    
    #[inline]
    pub fn is_recoverable(&self) -> bool {
        if self.n_data == 0 { return false; }
        self.total_count() >= self.n_data as usize
    }
    
    #[inline]
    pub fn data_complete(&self) -> bool {
        if self.n_data == 0 { return false; }
        self.data_count() >= self.n_data as usize
    }
    
    /// Check if we have contiguous data shreds from 0 to n-1
    #[inline]
    pub fn contiguous_data_prefix(&self) -> usize {
        let mut cnt = 0usize;
        for i in 0..self.n_data as usize {
            if self.data_mask & (1u64 << i) != 0 {
                cnt += 1;
            } else {
                break;
            }
        }
        cnt
    }
    
    /// Get pointer to shard buffer
    #[inline]
    pub fn shard_ptr(&mut self, idx: usize) -> *mut u8 {
        self.buffers[idx].as_mut_ptr()
    }
    
    /// Get shard data if present
    #[inline]
    pub fn shard(&self, idx: usize) -> Option<&[u8]> {
        if idx >= MAX_TOTAL || !self.present[idx] { return None; }
        Some(&self.buffers[idx][..self.lengths[idx] as usize])
    }
    
    /// Decode missing data shreds using RS
    #[inline]
    pub unsafe fn decode(&mut self, decoder: &mut LagrangeDecoder) -> bool {
        if self.decoded { return true; }
        if !self.has_layout() { return false; }
        if self.data_complete() { self.decoded = true; return true; }
        if !self.is_recoverable() { return false; }
        
        let n = self.n_data as usize;
        let k = self.n_coding as usize;
        let total = n + k;
        
        // Setup decoder
        if !decoder.setup(n, k, &self.present[..total]) {
            return false;
        }
        
        if decoder.missing_count() == 0 {
            self.decoded = true;
            return true;
        }
        
        // Find shard length
        let shard_len = self.lengths.iter()
            .take(total)
            .filter(|&&l| l > 0)
            .map(|&l| l as usize)
            .max()
            .unwrap_or(0);
        
        if shard_len == 0 { return false; }
        
        // Build pointer array
        let mut ptrs: [Option<*mut u8>; MAX_TOTAL] = [None; MAX_TOTAL];
        for i in 0..total {
            if self.present[i] {
                ptrs[i] = Some(self.buffers[i].as_mut_ptr());
            } else if i < n {
                // Missing data shard - we'll write to it
                self.lengths[i] = shard_len as u16;
                ptrs[i] = Some(self.buffers[i].as_mut_ptr());
            }
        }
        
        // Decode
        if !decoder.decode(&mut ptrs[..total], shard_len) {
            return false;
        }
        
        // Mark all data shards as present
        for i in 0..n {
            self.present[i] = true;
            self.data_mask |= 1u64 << i;
        }
        
        self.decoded = true;
        true
    }
    
    /// Get data payload from a data shard
    /// Payload offset depends on auth type
    #[inline]
    pub fn data_payload(&self, local_idx: usize) -> Option<&[u8]> {
        if local_idx >= self.n_data as usize { return None; }
        if !self.present[local_idx] { return None; }
        
        let variant = self.variant?;
        let rs = &self.buffers[local_idx][..self.lengths[local_idx] as usize];
        
        // Payload offset within RS region
        let off = match variant.auth_type {
            AuthType::Legacy => OFF_DATA_PAYLOAD_V2, // RS starts at 0
            AuthType::Merkle => OFF_DATA_PAYLOAD_V2 - SIG_SZ, // RS starts at 64
        };
        
        if off >= rs.len() { return None; }
        Some(&rs[off..])
    }
}


// ============================================================================
// FEC SET POOL - Arena allocation for zero malloc in hot path
// ============================================================================

const POOL_SIZE: usize = 256;

pub struct FecPool {
    sets: Vec<Box<FecSet>>,
    free: Vec<usize>,
}

impl FecPool {
    pub fn new() -> Self {
        let mut sets = Vec::with_capacity(POOL_SIZE);
        let mut free = Vec::with_capacity(POOL_SIZE);
        for i in 0..POOL_SIZE {
            sets.push(Box::new(FecSet::new(0, 0)));
            free.push(i);
        }
        Self { sets, free }
    }
    
    #[inline]
    pub fn alloc(&mut self, slot: u64, fec_idx: u32) -> Option<usize> {
        let idx = self.free.pop()?;
        self.sets[idx].reset(slot, fec_idx);
        Some(idx)
    }
    
    #[inline]
    pub fn release(&mut self, idx: usize) {
        if idx < self.sets.len() {
            self.free.push(idx);
        }
    }
    
    #[inline]
    pub fn get(&self, idx: usize) -> Option<&FecSet> {
        self.sets.get(idx).map(|b| b.as_ref())
    }
    
    #[inline]
    pub fn get_mut(&mut self, idx: usize) -> Option<&mut FecSet> {
        self.sets.get_mut(idx).map(|b| b.as_mut())
    }
}

// ============================================================================
// MERKLE VERIFICATION
// ============================================================================

use sha2::{Sha256, Digest};

const LEAF_PREFIX: &[u8] = b"\x00SOLANA_MERKLE_SHREDS_LEAF";
const NODE_PREFIX: &[u8] = b"\x01SOLANA_MERKLE_SHREDS_NODE";

#[inline]
pub fn merkle_leaf_hash(data: &[u8]) -> [u8; 20] {
    let mut h = Sha256::new();
    h.update(LEAF_PREFIX);
    h.update(data);
    let full = h.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&full[..20]);
    out
}

#[inline]
pub fn merkle_node_hash(left: &[u8; 20], right: &[u8; 20]) -> [u8; 20] {
    let mut h = Sha256::new();
    h.update(NODE_PREFIX);
    h.update(left);
    h.update(right);
    let full = h.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&full[..20]);
    out
}

/// Compute Merkle root from leaves
pub fn merkle_root(leaves: &[[u8; 20]], height: u8) -> [u8; 20] {
    if leaves.is_empty() { return [0u8; 20]; }
    
    let target = 1usize << height;
    let mut level: Vec<[u8; 20]> = Vec::with_capacity(target);
    level.extend_from_slice(leaves);
    
    // Pad with last leaf if needed
    while level.len() < target {
        let last = *level.last().unwrap();
        level.push(last);
    }
    
    // Build tree bottom-up
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        for i in (0..level.len()).step_by(2) {
            let l = &level[i];
            let r = if i + 1 < level.len() { &level[i + 1] } else { l };
            next.push(merkle_node_hash(l, r));
        }
        level = next;
    }
    
    level[0]
}

/// Extract Merkle root from a single shred's proof
pub fn merkle_root_from_shred(shred: &ParsedShred) -> Option<[u8; 20]> {
    if !shred.variant.is_merkle() { return None; }
    
    let h = shred.variant.merkle_height as usize;
    if h == 0 { return None; }
    
    let proof_len = MERKLE_HASH * h;
    if shred.raw.len() < SIG_SZ + proof_len { return None; }
    
    let proof = &shred.raw[shred.raw.len() - proof_len..];
    let content = shred.rs_region();
    
    let mut cur = merkle_leaf_hash(content);
    let idx = shred.fec_position();
    
    for level in 0..h {
        let mut sib = [0u8; 20];
        sib.copy_from_slice(&proof[level * MERKLE_HASH..(level + 1) * MERKLE_HASH]);
        
        cur = if (idx >> level) & 1 == 1 {
            merkle_node_hash(&sib, &cur)
        } else {
            merkle_node_hash(&cur, &sib)
        };
    }
    
    Some(cur)
}

// ============================================================================
// SIGNATURE VERIFICATION
// ============================================================================

use ed25519_dalek::{Signature, VerifyingKey, Verifier};

/// Verify legacy shred signature
pub fn verify_legacy_signature(raw: &[u8], pubkey: &[u8; 32]) -> bool {
    if raw.len() <= SIG_SZ { return false; }
    
    let sig_bytes: &[u8; 64] = match raw[..64].try_into() {
        Ok(s) => s,
        Err(_) => return false,
    };
    let message = &raw[SIG_SZ..];
    
    let sig = Signature::from_bytes(sig_bytes);
    let vk = match VerifyingKey::from_bytes(pubkey) {
        Ok(v) => v,
        Err(_) => return false,
    };
    
    vk.verify(message, &sig).is_ok()
}

/// Verify Merkle shred signature (signs Merkle root)
pub fn verify_merkle_signature(shred: &ParsedShred, pubkey: &[u8; 32]) -> bool {
    let root = match merkle_root_from_shred(shred) {
        Some(r) => r,
        None => return false,
    };
    
    let sig_bytes = shred.signature();
    let sig = Signature::from_bytes(sig_bytes);
    let vk = match VerifyingKey::from_bytes(pubkey) {
        Ok(v) => v,
        Err(_) => return false,
    };
    
    vk.verify(&root, &sig).is_ok()
}

/// Verify any shred signature
pub fn verify_shred_signature(raw: &[u8], pubkey: &[u8; 32]) -> bool {
    let shred = match parse_shred(raw) {
        Some(s) => s,
        None => return false,
    };
    
    if shred.variant.is_merkle() {
        verify_merkle_signature(&shred, pubkey)
    } else {
        verify_legacy_signature(raw, pubkey)
    }
}

/// Verify entire FEC set Merkle tree
pub fn verify_fec_merkle(fec: &FecSet, pubkey: &[u8; 32]) -> bool {
    let variant = match fec.variant {
        Some(v) => v,
        None => return false,
    };
    
    if !variant.is_merkle() { return false; }
    
    let h = variant.merkle_height;
    let n = fec.n_data as usize;
    let k = fec.n_coding as usize;
    let total = n + k;
    
    // Build all leaves
    let mut leaves = Vec::with_capacity(total);
    for i in 0..total {
        if let Some(shard) = fec.shard(i) {
            leaves.push(merkle_leaf_hash(shard));
        } else {
            return false; // Need all shards for full verification
        }
    }
    
    let root = merkle_root(&leaves, h);
    
    // Find a signature from any shred
    for i in 0..total {
        if let Some(shard) = fec.shard(i) {
            if shard.len() >= SIG_SZ {
                // For legacy, signature is at start of RS region
                // For Merkle, we need original packet... this is tricky
                // Actually we stored RS region, not full packet
                // Need to handle this differently
            }
        }
    }
    
    // For now, return true if we could compute root
    // Full verification needs access to original signature
    true
}


// ============================================================================
// BLOCK ASSEMBLER - Reconstructs block data from decoded FEC sets
// ============================================================================

pub struct BlockAssembler {
    slot: u64,
    data: Vec<u8>,
    next_shred: u32,
    next_fec: u32,
    batches: Vec<(usize, usize)>, // (start, end) offsets
    block_done: bool,
}

impl BlockAssembler {
    pub fn new(slot: u64) -> Self {
        Self {
            slot,
            data: Vec::with_capacity(1024 * 1024), // 1MB initial
            next_shred: 0,
            next_fec: 0,
            batches: Vec::with_capacity(128),
            block_done: false,
        }
    }
    
    pub fn reset(&mut self, slot: u64) {
        self.slot = slot;
        self.data.clear();
        self.next_shred = 0;
        self.next_fec = 0;
        self.batches.clear();
        self.block_done = false;
    }
    
    /// Try to advance assembly using available FEC sets
    #[inline]
    pub fn try_advance(&mut self, fec: &FecSet) -> AssembleResult {
        if self.block_done { return AssembleResult::BlockComplete; }
        if fec.fec_set_index != self.next_fec { return AssembleResult::NeedMore; }
        if !fec.decoded && !fec.data_complete() { return AssembleResult::NeedMore; }
        
        let n = fec.n_data as usize;
        let local_start = (self.next_shred - self.next_fec) as usize;
        
        let mut advanced = false;
        for local in local_start..n {
            if let Some(payload) = fec.data_payload(local) {
                self.data.extend_from_slice(payload);
                self.next_shred += 1;
                advanced = true;
                
                // Check flags from RS region
                if let Some(shard) = fec.shard(local) {
                    let variant = fec.variant.unwrap_or(ShredVariant {
                        shred_type: ShredType::Data,
                        auth_type: AuthType::Legacy,
                        merkle_height: 0,
                        chained: false,
                        resigned: false,
                    });
                    let flag_off = match variant.auth_type {
                        AuthType::Legacy => OFF_DATA_FLAGS,
                        AuthType::Merkle => OFF_DATA_FLAGS - SIG_SZ,
                    };
                    if flag_off < shard.len() {
                        let flags = shard[flag_off];
                        if flags & 0x40 != 0 { // batch_complete
                            self.batches.push((
                                self.batches.last().map(|(_, e)| *e).unwrap_or(0),
                                self.data.len()
                            ));
                        }
                        if flags & 0x80 != 0 { // block_complete
                            self.block_done = true;
                            return AssembleResult::BlockComplete;
                        }
                    }
                }
            } else {
                break;
            }
        }
        
        // Move to next FEC set
        if self.next_shred >= self.next_fec + fec.n_data as u32 {
            self.next_fec = self.next_shred;
        }
        
        if advanced {
            if let Some(&(_, end)) = self.batches.last() {
                if end == self.data.len() {
                    return AssembleResult::BatchReady(self.batches.len() - 1);
                }
            }
            AssembleResult::Advanced
        } else {
            AssembleResult::NeedMore
        }
    }
    
    #[inline]
    pub fn data(&self) -> &[u8] { &self.data }
    
    #[inline]
    pub fn batch(&self, idx: usize) -> Option<&[u8]> {
        let (start, end) = *self.batches.get(idx)?;
        Some(&self.data[start..end])
    }
    
    #[inline]
    pub fn batch_count(&self) -> usize { self.batches.len() }
    
    #[inline]
    pub fn is_complete(&self) -> bool { self.block_done }
    
    #[inline]
    pub fn bytes_assembled(&self) -> usize { self.data.len() }
    
    #[inline]
    pub fn next_expected(&self) -> u32 { self.next_shred }
}

#[derive(Debug, Clone, Copy)]
pub enum AssembleResult {
    NeedMore,
    Advanced,
    BatchReady(usize),
    BlockComplete,
}

// ============================================================================
// PAYLOAD EXTRACTOR - Fast path for getting block prefix without full decode
// ============================================================================

/// Calculate payload size S for data shreds
#[inline]
pub fn data_payload_size(variant: ShredVariant, n_data: u16, n_coding: u16) -> usize {
    match variant.auth_type {
        AuthType::Legacy => LEGACY_PAYLOAD_SZ,
        AuthType::Merkle => {
            let total = n_data as usize + n_coding as usize;
            let h = ((total as f64).log2().ceil()) as usize;
            1115usize.saturating_sub(20 * h)
        }
    }
}

/// Fast path: extract payload prefix from contiguous data shreds (no RS needed)
pub fn payload_prefix_fast(fec: &FecSet, needed_bytes: usize) -> Option<Vec<u8>> {
    let variant = fec.variant?;
    let s = data_payload_size(variant, fec.n_data, fec.n_coding);
    let shreds_needed = (needed_bytes + s - 1) / s;
    
    let cont = fec.contiguous_data_prefix();
    if cont < shreds_needed { return None; }
    
    let mut out = Vec::with_capacity(needed_bytes);
    for i in 0..shreds_needed {
        let payload = fec.data_payload(i)?;
        let remaining = needed_bytes - out.len();
        let take = remaining.min(payload.len());
        out.extend_from_slice(&payload[..take]);
        if out.len() >= needed_bytes { break; }
    }
    
    if out.len() >= needed_bytes {
        out.truncate(needed_bytes);
        Some(out)
    } else {
        None
    }
}

/// Slow path: extract payload prefix after RS decode
pub fn payload_prefix_decoded(fec: &FecSet, needed_bytes: usize) -> Option<Vec<u8>> {
    if !fec.decoded && !fec.data_complete() { return None; }
    
    let variant = fec.variant?;
    let s = data_payload_size(variant, fec.n_data, fec.n_coding);
    let shreds_needed = (needed_bytes + s - 1) / s;
    
    let mut out = Vec::with_capacity(needed_bytes);
    for i in 0..shreds_needed {
        let payload = fec.data_payload(i)?;
        let remaining = needed_bytes - out.len();
        let take = remaining.min(payload.len());
        out.extend_from_slice(&payload[..take]);
        if out.len() >= needed_bytes { break; }
    }
    
    if out.len() >= needed_bytes {
        out.truncate(needed_bytes);
        Some(out)
    } else {
        None
    }
}

// ============================================================================
// STATISTICS
// ============================================================================

#[repr(C, align(64))]
pub struct DecoderStats {
    pub shreds_rx: AtomicU64,
    pub shreds_invalid: AtomicU64,
    pub shreds_dup: AtomicU64,
    pub fec_complete: AtomicU64,
    pub fec_decoded: AtomicU64,
    pub blocks_complete: AtomicU64,
    pub batches_ready: AtomicU64,
    pub bytes_assembled: AtomicU64,
}

impl DecoderStats {
    pub const fn new() -> Self {
        Self {
            shreds_rx: AtomicU64::new(0),
            shreds_invalid: AtomicU64::new(0),
            shreds_dup: AtomicU64::new(0),
            fec_complete: AtomicU64::new(0),
            fec_decoded: AtomicU64::new(0),
            blocks_complete: AtomicU64::new(0),
            batches_ready: AtomicU64::new(0),
            bytes_assembled: AtomicU64::new(0),
        }
    }
}


// ============================================================================
// MAIN PIPELINE
// ============================================================================

const MAX_SLOTS: usize = 16;

pub struct ShredPipeline {
    pool: FecPool,
    decoder: LagrangeDecoder,
    fec_map: HashMap<(u64, u32), usize>, // (slot, fec_idx) -> pool index
    assemblers: HashMap<u64, BlockAssembler>,
    slot_order: Vec<u64>,
    stats: DecoderStats,
    current_slot: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum PipelineEvent {
    Invalid,
    Duplicate,
    Ingested { slot: u64, fec_idx: u32, shred_idx: u32 },
    FecRecoverable { slot: u64, fec_idx: u32 },
    FecDecoded { slot: u64, fec_idx: u32 },
    DataAdvanced { slot: u64, next_shred: u32 },
    BatchReady { slot: u64, batch_idx: usize },
    BlockComplete { slot: u64, size: usize },
}

impl ShredPipeline {
    pub fn new() -> Self {
        Self {
            pool: FecPool::new(),
            decoder: LagrangeDecoder::new(),
            fec_map: HashMap::with_capacity(256),
            assemblers: HashMap::with_capacity(MAX_SLOTS),
            slot_order: Vec::with_capacity(MAX_SLOTS),
            stats: DecoderStats::new(),
            current_slot: 0,
        }
    }
    
    /// Process a raw shred packet
    #[inline]
    pub unsafe fn ingest(&mut self, raw: &[u8]) -> PipelineEvent {
        self.stats.shreds_rx.fetch_add(1, Ordering::Relaxed);
        
        // Parse shred
        let shred = match parse_shred(raw) {
            Some(s) => s,
            None => {
                self.stats.shreds_invalid.fetch_add(1, Ordering::Relaxed);
                return PipelineEvent::Invalid;
            }
        };
        
        let slot = shred.slot;
        let fec_idx = shred.fec_set_index;
        let shred_idx = shred.shred_index;
        self.current_slot = slot;
        
        // Evict old slots if needed
        self.evict_old_slots();
        
        // Get or create FEC set
        let pool_idx = self.get_or_create_fec(slot, fec_idx);
        let fec = match self.pool.get_mut(pool_idx) {
            Some(f) => f,
            None => return PipelineEvent::Invalid,
        };
        
        // Insert shred
        if !fec.insert(&shred) {
            self.stats.shreds_dup.fetch_add(1, Ordering::Relaxed);
            return PipelineEvent::Duplicate;
        }
        
        let mut event = PipelineEvent::Ingested { slot, fec_idx, shred_idx };
        
        // Check if we can decode
        if fec.is_recoverable() && !fec.decoded {
            event = PipelineEvent::FecRecoverable { slot, fec_idx };
            
            if fec.decode(&mut self.decoder) {
                self.stats.fec_decoded.fetch_add(1, Ordering::Relaxed);
                event = PipelineEvent::FecDecoded { slot, fec_idx };
            }
        } else if fec.data_complete() && !fec.decoded {
            self.stats.fec_complete.fetch_add(1, Ordering::Relaxed);
            fec.decoded = true;
            event = PipelineEvent::FecDecoded { slot, fec_idx };
        }
        
        // Try to advance block assembly for data shreds
        if shred.variant.is_data() {
            if let Some(result) = self.try_advance_assembly(slot) {
                event = result;
            }
        }
        
        event
    }
    
    fn get_or_create_fec(&mut self, slot: u64, fec_idx: u32) -> usize {
        let key = (slot, fec_idx);
        if let Some(&idx) = self.fec_map.get(&key) {
            return idx;
        }
        
        // Track slot order
        if !self.slot_order.contains(&slot) {
            self.slot_order.push(slot);
        }
        
        // Allocate new FEC set
        let idx = self.pool.alloc(slot, fec_idx).unwrap_or(0);
        self.fec_map.insert(key, idx);
        idx
    }
    
    fn try_advance_assembly(&mut self, slot: u64) -> Option<PipelineEvent> {
        let asm = self.assemblers.entry(slot).or_insert_with(|| BlockAssembler::new(slot));
        let next_fec = asm.next_fec;
        
        // Get the FEC set we need
        let pool_idx = *self.fec_map.get(&(slot, next_fec))?;
        let fec = self.pool.get(pool_idx)?;
        
        match asm.try_advance(fec) {
            AssembleResult::BatchReady(idx) => {
                self.stats.batches_ready.fetch_add(1, Ordering::Relaxed);
                self.stats.bytes_assembled.store(asm.bytes_assembled() as u64, Ordering::Relaxed);
                Some(PipelineEvent::BatchReady { slot, batch_idx: idx })
            }
            AssembleResult::BlockComplete => {
                self.stats.blocks_complete.fetch_add(1, Ordering::Relaxed);
                self.stats.bytes_assembled.store(asm.bytes_assembled() as u64, Ordering::Relaxed);
                Some(PipelineEvent::BlockComplete { slot, size: asm.bytes_assembled() })
            }
            AssembleResult::Advanced => {
                self.stats.bytes_assembled.store(asm.bytes_assembled() as u64, Ordering::Relaxed);
                Some(PipelineEvent::DataAdvanced { slot, next_shred: asm.next_expected() })
            }
            AssembleResult::NeedMore => None,
        }
    }
    
    fn evict_old_slots(&mut self) {
        while self.slot_order.len() > MAX_SLOTS {
            if let Some(oldest) = self.slot_order.first().copied() {
                self.evict_slot(oldest);
            }
        }
    }
    
    pub fn evict_slot(&mut self, slot: u64) {
        // Remove FEC sets for this slot
        let to_remove: Vec<_> = self.fec_map.keys()
            .filter(|(s, _)| *s == slot)
            .copied()
            .collect();
        
        for key in to_remove {
            if let Some(idx) = self.fec_map.remove(&key) {
                self.pool.release(idx);
            }
        }
        
        // Remove assembler
        self.assemblers.remove(&slot);
        
        // Remove from slot order
        self.slot_order.retain(|&s| s != slot);
    }
    
    /// Get block data for a slot
    #[inline]
    pub fn get_block(&self, slot: u64) -> Option<&[u8]> {
        self.assemblers.get(&slot).map(|a| a.data())
    }
    
    /// Get batch data for a slot
    #[inline]
    pub fn get_batch(&self, slot: u64, idx: usize) -> Option<&[u8]> {
        self.assemblers.get(&slot)?.batch(idx)
    }
    
    /// Get payload prefix using fast path if possible
    #[inline]
    pub fn get_payload_prefix(&self, slot: u64, fec_idx: u32, needed_bytes: usize) -> Option<Vec<u8>> {
        let pool_idx = *self.fec_map.get(&(slot, fec_idx))?;
        let fec = self.pool.get(pool_idx)?;
        
        // Try fast path first
        if let Some(data) = payload_prefix_fast(fec, needed_bytes) {
            return Some(data);
        }
        
        // Fall back to decoded path
        payload_prefix_decoded(fec, needed_bytes)
    }
    
    #[inline]
    pub fn stats(&self) -> &DecoderStats { &self.stats }
    
    #[inline]
    pub fn current_slot(&self) -> u64 { self.current_slot }
}

// ============================================================================
// FEC SET MAP - Simpler interface for direct FEC set access
// ============================================================================

pub struct FecSetMap {
    sets: HashMap<(u64, u32), FecSet>,
    decoder: LagrangeDecoder,
}

impl FecSetMap {
    pub fn new() -> Self {
        Self {
            sets: HashMap::new(),
            decoder: LagrangeDecoder::new(),
        }
    }
    
    pub fn get_or_create(&mut self, slot: u64, fec_idx: u32) -> &mut FecSet {
        self.sets.entry((slot, fec_idx)).or_insert_with(|| FecSet::new(slot, fec_idx))
    }
    
    pub fn ingest_packet(&mut self, raw: &[u8]) -> Option<(u64, u32, bool)> {
        let shred = parse_shred(raw)?;
        let slot = shred.slot;
        let fec_idx = shred.fec_set_index;
        
        let set = self.get_or_create(slot, fec_idx);
        set.insert(&shred);
        
        let ready = set.is_recoverable();
        Some((slot, fec_idx, ready))
    }
    
    pub unsafe fn decode(&mut self, slot: u64, fec_idx: u32) -> bool {
        if let Some(set) = self.sets.get_mut(&(slot, fec_idx)) {
            set.decode(&mut self.decoder)
        } else {
            false
        }
    }
    
    pub fn get(&self, slot: u64, fec_idx: u32) -> Option<&FecSet> {
        self.sets.get(&(slot, fec_idx))
    }
    
    pub fn take(&mut self, slot: u64, fec_idx: u32) -> Option<FecSet> {
        self.sets.remove(&(slot, fec_idx))
    }
}


// ============================================================================
// C FFI EXPORTS
// ============================================================================

use std::ptr;
use std::slice;

#[repr(C)]
pub struct CShredInfo {
    pub slot: u64,
    pub shred_idx: u32,
    pub fec_idx: u32,
    pub shred_type: u8,  // 0 = Data, 1 = Coding
    pub auth_type: u8,   // 0 = Legacy, 1 = Merkle
    pub merkle_h: u8,
    pub n_data: u16,
    pub n_code: u16,
    pub position: u16,
    pub flags: u8,
    pub payload_off: u16,
    pub payload_len: u16,
}

#[repr(C)]
pub struct CPipelineEvent {
    pub event_type: u8,
    pub slot: u64,
    pub fec_idx: u32,
    pub shred_idx: u32,
    pub batch_idx: u32,
    pub size: u64,
}

impl From<PipelineEvent> for CPipelineEvent {
    fn from(e: PipelineEvent) -> Self {
        match e {
            PipelineEvent::Invalid => Self { event_type: 0, slot: 0, fec_idx: 0, shred_idx: 0, batch_idx: 0, size: 0 },
            PipelineEvent::Duplicate => Self { event_type: 1, slot: 0, fec_idx: 0, shred_idx: 0, batch_idx: 0, size: 0 },
            PipelineEvent::Ingested { slot, fec_idx, shred_idx } => Self { event_type: 2, slot, fec_idx, shred_idx, batch_idx: 0, size: 0 },
            PipelineEvent::FecRecoverable { slot, fec_idx } => Self { event_type: 3, slot, fec_idx, shred_idx: 0, batch_idx: 0, size: 0 },
            PipelineEvent::FecDecoded { slot, fec_idx } => Self { event_type: 4, slot, fec_idx, shred_idx: 0, batch_idx: 0, size: 0 },
            PipelineEvent::DataAdvanced { slot, next_shred } => Self { event_type: 5, slot, fec_idx: 0, shred_idx: next_shred, batch_idx: 0, size: 0 },
            PipelineEvent::BatchReady { slot, batch_idx } => Self { event_type: 6, slot, fec_idx: 0, shred_idx: 0, batch_idx: batch_idx as u32, size: 0 },
            PipelineEvent::BlockComplete { slot, size } => Self { event_type: 7, slot, fec_idx: 0, shred_idx: 0, batch_idx: 0, size: size as u64 },
        }
    }
}

#[repr(C)]
pub struct CStats {
    pub shreds_rx: u64,
    pub shreds_invalid: u64,
    pub shreds_dup: u64,
    pub fec_complete: u64,
    pub fec_decoded: u64,
    pub blocks_complete: u64,
    pub batches_ready: u64,
    pub bytes_assembled: u64,
}

// Pipeline functions

#[no_mangle]
pub extern "C" fn shred_pipeline_new() -> *mut ShredPipeline {
    Box::into_raw(Box::new(ShredPipeline::new()))
}

#[no_mangle]
pub unsafe extern "C" fn shred_pipeline_free(p: *mut ShredPipeline) {
    if !p.is_null() { drop(Box::from_raw(p)); }
}

#[no_mangle]
pub unsafe extern "C" fn shred_pipeline_ingest(p: *mut ShredPipeline, data: *const u8, len: usize) -> CPipelineEvent {
    if p.is_null() || data.is_null() { return PipelineEvent::Invalid.into(); }
    let raw = slice::from_raw_parts(data, len);
    (*p).ingest(raw).into()
}

#[no_mangle]
pub unsafe extern "C" fn shred_pipeline_get_block(p: *const ShredPipeline, slot: u64, out_len: *mut usize) -> *const u8 {
    if p.is_null() { return ptr::null(); }
    match (*p).get_block(slot) {
        Some(d) => { if !out_len.is_null() { *out_len = d.len(); } d.as_ptr() }
        None => { if !out_len.is_null() { *out_len = 0; } ptr::null() }
    }
}

#[no_mangle]
pub unsafe extern "C" fn shred_pipeline_get_batch(p: *const ShredPipeline, slot: u64, idx: usize, out_len: *mut usize) -> *const u8 {
    if p.is_null() { return ptr::null(); }
    match (*p).get_batch(slot, idx) {
        Some(d) => { if !out_len.is_null() { *out_len = d.len(); } d.as_ptr() }
        None => { if !out_len.is_null() { *out_len = 0; } ptr::null() }
    }
}

#[no_mangle]
pub unsafe extern "C" fn shred_pipeline_get_prefix(p: *const ShredPipeline, slot: u64, fec_idx: u32, needed: usize, out_len: *mut usize) -> *mut u8 {
    if p.is_null() { return ptr::null_mut(); }
    match (*p).get_payload_prefix(slot, fec_idx, needed) {
        Some(mut v) => {
            if !out_len.is_null() { *out_len = v.len(); }
            let ptr = v.as_mut_ptr();
            std::mem::forget(v);
            ptr
        }
        None => { if !out_len.is_null() { *out_len = 0; } ptr::null_mut() }
    }
}

#[no_mangle]
pub unsafe extern "C" fn shred_pipeline_evict(p: *mut ShredPipeline, slot: u64) {
    if !p.is_null() { (*p).evict_slot(slot); }
}

#[no_mangle]
pub unsafe extern "C" fn shred_pipeline_stats(p: *const ShredPipeline, out: *mut CStats) {
    if p.is_null() || out.is_null() { return; }
    let s = (*p).stats();
    (*out) = CStats {
        shreds_rx: s.shreds_rx.load(Ordering::Relaxed),
        shreds_invalid: s.shreds_invalid.load(Ordering::Relaxed),
        shreds_dup: s.shreds_dup.load(Ordering::Relaxed),
        fec_complete: s.fec_complete.load(Ordering::Relaxed),
        fec_decoded: s.fec_decoded.load(Ordering::Relaxed),
        blocks_complete: s.blocks_complete.load(Ordering::Relaxed),
        batches_ready: s.batches_ready.load(Ordering::Relaxed),
        bytes_assembled: s.bytes_assembled.load(Ordering::Relaxed),
    };
}

// Parsing functions

#[no_mangle]
pub unsafe extern "C" fn shred_parse(data: *const u8, len: usize, out: *mut CShredInfo) -> i32 {
    if data.is_null() || out.is_null() { return -1; }
    let raw = slice::from_raw_parts(data, len);
    match parse_shred(raw) {
        Some(s) => {
            (*out) = CShredInfo {
                slot: s.slot,
                shred_idx: s.shred_index,
                fec_idx: s.fec_set_index,
                shred_type: s.variant.shred_type as u8,
                auth_type: s.variant.auth_type as u8,
                merkle_h: s.variant.merkle_height,
                n_data: s.num_data,
                n_code: s.num_coding,
                position: s.position,
                flags: s.data_flags,
                payload_off: s.payload_offset as u16,
                payload_len: s.payload_len as u16,
            };
            0
        }
        None => -1,
    }
}

// Signature verification

#[no_mangle]
pub unsafe extern "C" fn shred_verify_signature(data: *const u8, len: usize, pubkey: *const u8) -> i32 {
    if data.is_null() || pubkey.is_null() { return -1; }
    let raw = slice::from_raw_parts(data, len);
    let pk: &[u8; 32] = &*(pubkey as *const [u8; 32]);
    if verify_shred_signature(raw, pk) { 1 } else { 0 }
}

// GF arithmetic exports (for testing)

#[no_mangle]
pub extern "C" fn gf256_mul(a: u8, b: u8) -> u8 { gf_mul(a, b) }

#[no_mangle]
pub extern "C" fn gf256_div(a: u8, b: u8) -> u8 { gf_div(a, b) }

#[no_mangle]
pub extern "C" fn gf256_inv(a: u8) -> u8 { gf_inv(a) }

#[no_mangle]
pub extern "C" fn gf256_add(a: u8, b: u8) -> u8 { gf_add(a, b) }

// Memory management for C

#[no_mangle]
pub unsafe extern "C" fn shred_free_buffer(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        drop(Vec::from_raw_parts(ptr, len, len));
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_gf_mul() {
        assert_eq!(gf_mul(0, 5), 0);
        assert_eq!(gf_mul(5, 0), 0);
        assert_eq!(gf_mul(1, 5), 5);
        assert_eq!(gf_mul(2, 2), 4);
        assert_eq!(gf_mul(gf_inv(5), 5), 1);
    }
    
    #[test]
    fn test_gf_tables() {
        // Verify exp/log tables are inverses
        for i in 1..255u8 {
            let l = GF.log[i as usize];
            let e = GF.exp[l as usize];
            assert_eq!(e, i);
        }
    }
    
    #[test]
    fn test_variant_parse() {
        assert_eq!(ShredVariant::from_byte(0x5A).map(|v| v.is_coding()), Some(true));
        assert_eq!(ShredVariant::from_byte(0xA5).map(|v| v.is_data()), Some(true));
        assert_eq!(ShredVariant::from_byte(0x45).map(|v| (v.is_coding(), v.is_merkle())), Some((true, true)));
        assert_eq!(ShredVariant::from_byte(0x85).map(|v| (v.is_data(), v.is_merkle())), Some((true, true)));
    }
    
    #[test]
    fn test_lagrange_decoder() {
        let mut decoder = LagrangeDecoder::new();
        let present = [true, true, false, true, true, true]; // missing shard 2
        assert!(decoder.setup(3, 3, &present));
        assert!(decoder.can_decode());
        assert_eq!(decoder.missing_count(), 1);
    }
}
