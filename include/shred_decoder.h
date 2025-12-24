/**
 * Ultra-optimized Solana Shred Decoder
 * 
 * Features:
 * - Lagrange-based O(N²) Reed-Solomon erasure decoding
 * - AVX2/AVX512 SIMD GF(2^8) arithmetic
 * - Arena-allocated FEC sets (zero malloc in hot path)
 * - Data-only fast path (skip RS when possible)
 * - Merkle + Ed25519 signature verification
 */

#ifndef SHRED_DECODER_H
#define SHRED_DECODER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Shred types */
#define SHRED_TYPE_DATA   0
#define SHRED_TYPE_CODING 1

/* Auth types */
#define AUTH_TYPE_LEGACY 0
#define AUTH_TYPE_MERKLE 1

/* Pipeline event types */
#define EVENT_INVALID        0
#define EVENT_DUPLICATE      1
#define EVENT_INGESTED       2
#define EVENT_FEC_RECOVERABLE 3
#define EVENT_FEC_DECODED    4
#define EVENT_DATA_ADVANCED  5
#define EVENT_BATCH_READY    6
#define EVENT_BLOCK_COMPLETE 7

/* Parsed shred info */
typedef struct {
    uint64_t slot;
    uint32_t shred_idx;
    uint32_t fec_idx;
    uint8_t  shred_type;
    uint8_t  auth_type;
    uint8_t  merkle_h;
    uint16_t n_data;
    uint16_t n_code;
    uint16_t position;
    uint8_t  flags;
    uint16_t payload_off;
    uint16_t payload_len;
} CShredInfo;

/* Pipeline event */
typedef struct {
    uint8_t  event_type;
    uint64_t slot;
    uint32_t fec_idx;
    uint32_t shred_idx;
    uint32_t batch_idx;
    uint64_t size;
} CPipelineEvent;

/* Decoder statistics */
typedef struct {
    uint64_t shreds_rx;
    uint64_t shreds_invalid;
    uint64_t shreds_dup;
    uint64_t fec_complete;
    uint64_t fec_decoded;
    uint64_t blocks_complete;
    uint64_t batches_ready;
    uint64_t bytes_assembled;
} CStats;

/* Opaque pipeline handle */
typedef struct ShredPipeline ShredPipeline;

/* ============================================================================
 * Pipeline API
 * ============================================================================ */

/**
 * Create a new shred pipeline
 * @return Pipeline handle (must be freed with shred_pipeline_free)
 */
ShredPipeline* shred_pipeline_new(void);

/**
 * Free a pipeline
 * @param p Pipeline handle
 */
void shred_pipeline_free(ShredPipeline* p);

/**
 * Ingest a raw shred packet
 * @param p Pipeline handle
 * @param data Raw packet data
 * @param len Packet length
 * @return Pipeline event indicating result
 */
CPipelineEvent shred_pipeline_ingest(ShredPipeline* p, const uint8_t* data, size_t len);

/**
 * Get assembled block data
 * @param p Pipeline handle
 * @param slot Slot number
 * @param out_len Output: data length
 * @return Pointer to block data (valid until slot evicted)
 */
const uint8_t* shred_pipeline_get_block(const ShredPipeline* p, uint64_t slot, size_t* out_len);

/**
 * Get batch data
 * @param p Pipeline handle
 * @param slot Slot number
 * @param idx Batch index
 * @param out_len Output: data length
 * @return Pointer to batch data (valid until slot evicted)
 */
const uint8_t* shred_pipeline_get_batch(const ShredPipeline* p, uint64_t slot, size_t idx, size_t* out_len);

/**
 * Get payload prefix (fast path if possible)
 * @param p Pipeline handle
 * @param slot Slot number
 * @param fec_idx FEC set index
 * @param needed Number of bytes needed
 * @param out_len Output: actual length
 * @return Pointer to data (must be freed with shred_free_buffer)
 */
uint8_t* shred_pipeline_get_prefix(const ShredPipeline* p, uint64_t slot, uint32_t fec_idx, size_t needed, size_t* out_len);

/**
 * Evict a slot from the pipeline
 * @param p Pipeline handle
 * @param slot Slot number
 */
void shred_pipeline_evict(ShredPipeline* p, uint64_t slot);

/**
 * Get pipeline statistics
 * @param p Pipeline handle
 * @param out Output stats struct
 */
void shred_pipeline_stats(const ShredPipeline* p, CStats* out);

/* ============================================================================
 * Parsing API
 * ============================================================================ */

/**
 * Parse a shred packet
 * @param data Raw packet data
 * @param len Packet length
 * @param out Output shred info
 * @return 0 on success, -1 on error
 */
int shred_parse(const uint8_t* data, size_t len, CShredInfo* out);

/* ============================================================================
 * Signature Verification
 * ============================================================================ */

/**
 * Verify shred signature
 * @param data Raw packet data
 * @param len Packet length
 * @param pubkey 32-byte Ed25519 public key
 * @return 1 if valid, 0 if invalid, -1 on error
 */
int shred_verify_signature(const uint8_t* data, size_t len, const uint8_t* pubkey);

/* ============================================================================
 * GF(2^8) Arithmetic (for testing/integration)
 * ============================================================================ */

uint8_t gf256_mul(uint8_t a, uint8_t b);
uint8_t gf256_div(uint8_t a, uint8_t b);
uint8_t gf256_inv(uint8_t a);
uint8_t gf256_add(uint8_t a, uint8_t b);

/* ============================================================================
 * Memory Management
 * ============================================================================ */

/**
 * Free a buffer allocated by the library
 * @param ptr Buffer pointer
 * @param len Buffer length
 */
void shred_free_buffer(uint8_t* ptr, size_t len);

/* ============================================================================
 * Pump.fun Detection API
 * ============================================================================ */

/* Pump event types */
#define PUMP_EVENT_CREATE    0
#define PUMP_EVENT_CREATE_V2 1
#define PUMP_EVENT_BUY       2
#define PUMP_EVENT_SELL      3

/* Token program types */
#define TOKEN_PROGRAM_LEGACY    0
#define TOKEN_PROGRAM_TOKEN2022 1

/* Pump event structure */
typedef struct {
    uint8_t  event_type;      /* PUMP_EVENT_* */
    uint64_t slot;
    uint8_t  mint[32];
    uint8_t  creator[32];
    uint8_t  tx_sig[64];
    uint64_t sol_amount;
    uint64_t token_amount;
    uint8_t  has_creator;     /* 1 if creator is valid */
    uint8_t  has_sig;         /* 1 if tx_sig is valid */
    uint8_t  token_program;   /* TOKEN_PROGRAM_* */
} CPumpEvent;

/* Opaque pump detector handle */
typedef struct PumpDetector PumpDetector;

/* Callback type for pump event scanning */
typedef int (*pump_event_callback)(const CPumpEvent* event, void* user_data);

/**
 * Create a new pump detector (creates only mode - fastest)
 * @return Detector handle (must be freed with pump_detector_free)
 */
PumpDetector* pump_detector_new(void);

/**
 * Create a new pump detector for all events (creates, buys, sells)
 * @return Detector handle (must be freed with pump_detector_free)
 */
PumpDetector* pump_detector_new_all_events(void);

/**
 * Free a pump detector
 * @param p Detector handle
 */
void pump_detector_free(PumpDetector* p);

/**
 * Scan batch/block data for pump events
 * @param detector Detector handle
 * @param data Block/batch data
 * @param len Data length
 * @param slot Slot number
 * @param callback Called for each event found (return 0 to stop, 1 to continue)
 * @param user_data Passed to callback
 * @return Number of events found, or -1 on error
 */
int pump_detector_scan(
    const PumpDetector* detector,
    const uint8_t* data,
    size_t len,
    uint64_t slot,
    pump_event_callback callback,
    void* user_data
);

/**
 * Scan for first create event only (fastest path for sniping)
 * @param detector Detector handle
 * @param data Block/batch data
 * @param len Data length
 * @param slot Slot number
 * @param out Output: the create event if found
 * @return 1 if found, 0 if not found, -1 on error
 */
int pump_detector_scan_first_create(
    const PumpDetector* detector,
    const uint8_t* data,
    size_t len,
    uint64_t slot,
    CPumpEvent* out
);

/**
 * Fast discriminator scan (for prefix detection before full decode)
 * @param data Raw bytes to scan
 * @param len Data length
 * @param out_offset Output: offset where discriminator was found
 * @param out_type Output: discriminator type (PUMP_EVENT_*)
 * @return 1 if found, 0 if not found, -1 on error
 */
int pump_scan_discriminators(
    const uint8_t* data,
    size_t len,
    size_t* out_offset,
    uint8_t* out_type
);

#ifdef __cplusplus
}
#endif

#endif /* SHRED_DECODER_H */
