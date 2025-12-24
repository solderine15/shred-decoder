//! Verification script for pump.fun integration
//!
//! Run: cargo run --release --example verify_integration

use shred_decoder::pump::{
    self, PumpDetector, PUMP_PROGRAM_BYTES, discriminators,
    GLOBAL_STATE_BYTES, FEE_RECIPIENT_BYTES, TOKEN_PROGRAM_BYTES,
    ATA_PROGRAM_BYTES, SYSTEM_PROGRAM_BYTES,
};

fn main() {
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║         PUMP.FUN SHRED DECODER - VERIFICATION              ║");
    println!("╚════════════════════════════════════════════════════════════╝\n");

    // 1. Verify all const bytes
    println!("1. CONST BYTES VERIFICATION");
    println!("   ────────────────────────────────────────");

    let checks = [
        ("PUMP_PROGRAM", "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P", &PUMP_PROGRAM_BYTES),
        ("GLOBAL_STATE", "4wTV1YmiEkRvAtNtsSGPtUrqRYQMe5SKy2uB4Jjaxnjf", &GLOBAL_STATE_BYTES),
        ("FEE_RECIPIENT", "CebN5WGQ4jvEPvsVU4EoHEpgzq1VV7AbicfhtW4xC9iM", &FEE_RECIPIENT_BYTES),
        ("TOKEN_PROGRAM", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", &TOKEN_PROGRAM_BYTES),
        ("ATA_PROGRAM", "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL", &ATA_PROGRAM_BYTES),
        ("SYSTEM_PROGRAM", "11111111111111111111111111111111", &SYSTEM_PROGRAM_BYTES),
    ];

    let mut all_ok = true;
    for (name, b58, bytes) in checks.iter() {
        let decoded = bs58::decode(b58).into_vec().unwrap();
        let matches = decoded.as_slice() == bytes.as_slice();
        if matches {
            println!("   {} ✓", name);
        } else {
            println!("   {} ✗ MISMATCH!", name);
            println!("      Expected: {:?}", &decoded[..]);
            println!("      Got:      {:?}", &bytes[..]);
            all_ok = false;
        }
    }

    // 2. Verify Discriminators
    println!("\n2. DISCRIMINATOR VERIFICATION");
    println!("   ────────────────────────────────────────");

    // These are sha256("global:<name>")[0..8]
    let expected_create = compute_discriminator("global:create");
    let expected_create_v2 = compute_discriminator("global:create_v2");
    let expected_buy = compute_discriminator("global:buy");
    let expected_sell = compute_discriminator("global:sell");

    println!("   create:    hardcoded={:?}", discriminators::CREATE);
    println!("              computed= {:?} {}", expected_create,
             if expected_create == discriminators::CREATE { "✓" } else { "✗ MISMATCH!" });

    println!("   create_v2: hardcoded={:?}", discriminators::CREATE_V2);
    println!("              computed= {:?} {}", expected_create_v2,
             if expected_create_v2 == discriminators::CREATE_V2 { "✓" } else { "✗ MISMATCH!" });

    println!("   buy:       hardcoded={:?}", discriminators::BUY);
    println!("              computed= {:?} {}", expected_buy,
             if expected_buy == discriminators::BUY { "✓" } else { "✗ MISMATCH!" });

    println!("   sell:      hardcoded={:?}", discriminators::SELL);
    println!("              computed= {:?} {}", expected_sell,
             if expected_sell == discriminators::SELL { "✓" } else { "✗ MISMATCH!" });

    // 3. Test Detector Creation
    println!("\n3. DETECTOR CREATION");
    println!("   ────────────────────────────────────────");

    let detector = PumpDetector::new();
    println!("   PumpDetector::new() - ✓ Created (creates_only mode)");

    let detector_all = PumpDetector::all_events();
    println!("   PumpDetector::all_events() - ✓ Created (all events mode)");

    // 4. Test discriminator scanning
    println!("\n4. DISCRIMINATOR SCAN TEST");
    println!("   ────────────────────────────────────────");

    let mut test_data = vec![0u8; 100];
    test_data[42..50].copy_from_slice(&discriminators::CREATE);

    if let Some((offset, match_type)) = pump::scan_discriminators(&test_data) {
        println!("   Found CREATE discriminator at offset {} - ✓", offset);
    } else {
        println!("   ✗ Failed to find discriminator!");
    }

    // 5. Integration readiness
    println!("\n5. INTEGRATION READINESS");
    println!("   ────────────────────────────────────────");

    let all_ok = all_ok
        && expected_create == discriminators::CREATE
        && expected_create_v2 == discriminators::CREATE_V2
        && expected_buy == discriminators::BUY
        && expected_sell == discriminators::SELL;

    if all_ok {
        println!("   ✓ ALL CHECKS PASSED - Ready for integration!");
        println!("\n   Your friend can use this API:");
        println!("   ┌──────────────────────────────────────────────────────┐");
        println!("   │ let detector = PumpDetector::new();                  │");
        println!("   │                                                      │");
        println!("   │ // In shred recv loop:                               │");
        println!("   │ if let Some(event) = detector.scan_first_create(     │");
        println!("   │     batch_data, slot                                 │");
        println!("   │ ) {{                                                  │");
        println!("   │     let mint = event.mint();                         │");
        println!("   │     // BUILD AND SEND SNIPE TX HERE                  │");
        println!("   │ }}                                                    │");
        println!("   └──────────────────────────────────────────────────────┘");
    } else {
        println!("   ✗ SOME CHECKS FAILED - See above for details");
    }

    println!("\n════════════════════════════════════════════════════════════════\n");
}

fn compute_discriminator(name: &str) -> [u8; 8] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(name.as_bytes());
    let result = hasher.finalize();
    let mut disc = [0u8; 8];
    disc.copy_from_slice(&result[..8]);
    disc
}
