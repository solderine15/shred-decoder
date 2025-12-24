use criterion::{black_box, criterion_group, criterion_main, Criterion};
use shred_decoder::*;

fn bench_gf_mul(c: &mut Criterion) {
    c.bench_function("gf_mul", |b| {
        b.iter(|| {
            for i in 0u8..=255 {
                for j in 0u8..=255 {
                    black_box(gf_mul(i, j));
                }
            }
        })
    });
}

fn bench_gf_mul_add_scalar(c: &mut Criterion) {
    let mut dst = vec![0u8; 1228];
    let src = vec![0xABu8; 1228];
    
    c.bench_function("gf_mul_add_scalar_1228", |b| {
        b.iter(|| {
            gf_mul_add_scalar(black_box(&mut dst), black_box(&src), 0x53);
        })
    });
}

fn bench_lagrange_setup(c: &mut Criterion) {
    let mut decoder = LagrangeDecoder::new();
    // Simulate 32 data, 32 coding, 2 missing data shards
    let mut present = [true; 64];
    present[5] = false;
    present[17] = false;
    
    c.bench_function("lagrange_setup_32_32_2miss", |b| {
        b.iter(|| {
            decoder.setup(black_box(32), black_box(32), black_box(&present));
        })
    });
}

fn bench_lagrange_decode(c: &mut Criterion) {
    let mut decoder = LagrangeDecoder::new();
    let mut present = [true; 64];
    present[5] = false;
    present[17] = false;
    decoder.setup(32, 32, &present);
    
    // Create mock shard data
    let mut shards: Vec<Vec<u8>> = (0..64).map(|_| vec![0xABu8; 1164]).collect();
    
    c.bench_function("lagrange_decode_32_32_2miss", |b| {
        b.iter(|| {
            let mut ptrs: [Option<*mut u8>; 134] = [None; 134];
            for (i, shard) in shards.iter_mut().enumerate() {
                if i < 64 {
                    ptrs[i] = Some(shard.as_mut_ptr());
                }
            }
            unsafe { decoder.decode(&mut ptrs[..64], 1164); }
        })
    });
}

criterion_group!(benches, bench_gf_mul, bench_gf_mul_add_scalar, bench_lagrange_setup, bench_lagrange_decode);
criterion_main!(benches);
