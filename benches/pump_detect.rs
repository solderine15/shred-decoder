//! Pump.fun detection benchmarks
//!
//! Compares our optimized pump detection vs naive approaches

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use shred_decoder::pump::{self, PumpDetector, PumpConfig, discriminators};

/// Create realistic block data with embedded pump.fun create instruction
fn create_test_block_data(num_txs: usize, pump_tx_idx: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(num_txs * 500);

    for i in 0..num_txs {
        // Entry header: num_hashes (8) + hash (32)
        data.extend_from_slice(&1u64.to_le_bytes()); // num_hashes
        data.extend_from_slice(&[0xAB; 32]); // hash

        // Transactions count (shortvec - 1 byte for small counts)
        data.push(1); // 1 transaction per entry

        // Transaction: signatures (shortvec + 64 bytes each)
        data.push(1); // 1 signature
        data.extend_from_slice(&[0xCC; 64]); // signature

        // Message header
        data.push(1); // num_required_signatures
        data.push(0); // num_readonly_signed
        data.push(1); // num_readonly_unsigned

        // Account keys (shortvec + 32 bytes each)
        data.push(5); // 5 accounts

        if i == pump_tx_idx {
            // This tx has pump program
            data.extend_from_slice(&pump::PUMP_PROGRAM_BYTES); // program
        } else {
            data.extend_from_slice(&[0x11; 32]); // random program
        }
        data.extend_from_slice(&[0x22; 32]); // account 1
        data.extend_from_slice(&[0x33; 32]); // account 2
        data.extend_from_slice(&[0x44; 32]); // account 3
        data.extend_from_slice(&[0x55; 32]); // account 4

        // Recent blockhash
        data.extend_from_slice(&[0xBB; 32]);

        // Instructions (shortvec)
        data.push(1); // 1 instruction

        // Instruction
        data.push(0); // program_id_index = 0
        data.push(3); // 3 accounts
        data.push(1); data.push(2); data.push(3); // account indices

        if i == pump_tx_idx {
            // Pump create instruction data
            let ix_data_len = 8 + 32 + 100; // discriminator + mint + other data
            data.push(ix_data_len as u8);
            data.extend_from_slice(&discriminators::CREATE); // discriminator
            data.extend_from_slice(&[0xEE; 32]); // mint address
            data.extend_from_slice(&[0xFF; 100]); // remaining data
        } else {
            data.push(10); // 10 bytes of random data
            data.extend_from_slice(&[0xDD; 10]);
        }
    }

    data
}

fn bench_discriminator_scan(c: &mut Criterion) {
    let data = create_test_block_data(100, 50);

    c.bench_function("discriminator_scan_100tx", |b| {
        b.iter(|| {
            pump::scan_discriminators(black_box(&data))
        })
    });
}

fn bench_pump_detector_scan(c: &mut Criterion) {
    let data = create_test_block_data(100, 50);
    let detector = PumpDetector::new();

    c.bench_function("pump_detector_scan_first_100tx", |b| {
        b.iter(|| {
            detector.scan_first_create(black_box(&data), 12345)
        })
    });
}

fn bench_pump_detector_full(c: &mut Criterion) {
    let data = create_test_block_data(100, 50);
    let detector = PumpDetector::with_config(PumpConfig::snipe());

    c.bench_function("pump_detector_snipe_100tx", |b| {
        b.iter(|| {
            detector.scan_first_create(black_box(&data), 12345)
        })
    });
}

fn bench_varying_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("pump_scan_by_size");

    for num_txs in [10, 50, 100, 500].iter() {
        let data = create_test_block_data(*num_txs, num_txs / 2);
        let detector = PumpDetector::new();

        group.bench_with_input(
            BenchmarkId::new("txs", num_txs),
            &data,
            |b, data| {
                b.iter(|| detector.scan_first_create(black_box(data), 12345))
            },
        );
    }

    group.finish();
}

fn bench_early_vs_late_match(c: &mut Criterion) {
    let mut group = c.benchmark_group("pump_match_position");

    let num_txs = 100;
    for pos in [0, 25, 50, 75, 99].iter() {
        let data = create_test_block_data(num_txs, *pos);
        let detector = PumpDetector::new();

        group.bench_with_input(
            BenchmarkId::new("pos", pos),
            &data,
            |b, data| {
                b.iter(|| detector.scan_first_create(black_box(data), 12345))
            },
        );
    }

    group.finish();
}

fn bench_no_match(c: &mut Criterion) {
    // Create data with no pump transactions
    let mut data = Vec::with_capacity(50000);
    for _ in 0..100 {
        data.extend_from_slice(&1u64.to_le_bytes());
        data.extend_from_slice(&[0xAB; 32]);
        data.push(1);
        data.push(1);
        data.extend_from_slice(&[0xCC; 64]);
        data.push(1); data.push(0); data.push(1);
        data.push(3);
        data.extend_from_slice(&[0x11; 32]);
        data.extend_from_slice(&[0x22; 32]);
        data.extend_from_slice(&[0x33; 32]);
        data.extend_from_slice(&[0xBB; 32]);
        data.push(1);
        data.push(0);
        data.push(2);
        data.push(1); data.push(2);
        data.push(10);
        data.extend_from_slice(&[0xDD; 10]);
    }

    let detector = PumpDetector::new();

    c.bench_function("pump_scan_no_match_100tx", |b| {
        b.iter(|| {
            detector.scan_first_create(black_box(&data), 12345)
        })
    });
}

fn bench_raw_discriminator_compare(c: &mut Criterion) {
    // Bench raw u64 discriminator comparison (our approach)
    let data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
    let target = discriminators::CREATE_U64;

    c.bench_function("u64_discriminator_scan_10kb", |b| {
        b.iter(|| {
            let mut found = None;
            for i in 0..data.len().saturating_sub(8) {
                let chunk = u64::from_le_bytes([
                    data[i], data[i+1], data[i+2], data[i+3],
                    data[i+4], data[i+5], data[i+6], data[i+7],
                ]);
                if chunk == target {
                    found = Some(i);
                    break;
                }
            }
            black_box(found)
        })
    });

    // Bench slice comparison (naive approach)
    let target_bytes = discriminators::CREATE;

    c.bench_function("slice_discriminator_scan_10kb", |b| {
        b.iter(|| {
            let mut found = None;
            for i in 0..data.len().saturating_sub(8) {
                if &data[i..i+8] == &target_bytes {
                    found = Some(i);
                    break;
                }
            }
            black_box(found)
        })
    });
}

criterion_group!(
    benches,
    bench_discriminator_scan,
    bench_pump_detector_scan,
    bench_pump_detector_full,
    bench_varying_sizes,
    bench_early_vs_late_match,
    bench_no_match,
    bench_raw_discriminator_compare,
);
criterion_main!(benches);
