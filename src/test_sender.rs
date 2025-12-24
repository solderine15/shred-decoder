use std::fs::File;
use std::io::Read;
use std::net::UdpSocket;
use std::path::Path;
use std::thread;
use std::time::Duration;

/// Simple test sender that can send either dummy packets or real shred data
fn main() {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    
    let socket = UdpSocket::bind("0.0.0.0:0").expect("Failed to bind socket");
    println!("Test sender started, sending to localhost:8002");

    // Check if we have a test shred file
    let test_file = Path::new("test_shreds.bin");
    
    if test_file.exists() {
        println!("Found test_shreds.bin, sending real shred data...");
        send_real_shreds(&socket, test_file);
    } else {
        println!("No test_shreds.bin found, sending dummy packets...");
        println!("To use real shreds, save them to test_shreds.bin");
        send_dummy_packets(&socket);
    }
}

/// Send dummy packets for basic connectivity testing
fn send_dummy_packets(socket: &UdpSocket) {
    let mut packet_count = 0u64;
    let mut last_report = std::time::Instant::now();
    
    loop {
        // Create a dummy packet (won't decode but tests UDP reception)
        // Real shreds are typically 1228 bytes
        let mut packet = vec![0u8; 1228];
        
        // Add some variation to the data
        packet[0] = (packet_count % 256) as u8;
        packet[1] = ((packet_count >> 8) % 256) as u8;
        
        match socket.send_to(&packet, "127.0.0.1:8002") {
            Ok(_) => {
                packet_count += 1;
                
                // Report stats every second
                if last_report.elapsed() >= Duration::from_secs(1) {
                    println!("Sent {} packets", packet_count);
                    last_report = std::time::Instant::now();
                }
            }
            Err(e) => {
                eprintln!("Failed to send packet: {}", e);
                thread::sleep(Duration::from_millis(100));
            }
        }
        
        // Send at a reasonable rate (100 packets/sec)
        thread::sleep(Duration::from_millis(10));
    }
}

/// Send real shred data from a file
fn send_real_shreds(socket: &UdpSocket, path: &Path) {
    let mut file = File::open(path).expect("Failed to open shred file");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("Failed to read shred file");
    
    println!("Loaded {} bytes of shred data", buffer.len());
    
    // Assume the file contains concatenated shreds of 1228 bytes each
    const SHRED_SIZE: usize = 1228;
    let shred_count = buffer.len() / SHRED_SIZE;
    println!("Found {} shreds in file", shred_count);
    
    let mut sent_count = 0;
    let mut last_report = std::time::Instant::now();
    
    // Send shreds in a loop
    loop {
        for chunk in buffer.chunks(SHRED_SIZE) {
            if chunk.len() == SHRED_SIZE {
                match socket.send_to(chunk, "127.0.0.1:8002") {
                    Ok(_) => {
                        sent_count += 1;
                        
                        if last_report.elapsed() >= Duration::from_secs(1) {
                            println!("Sent {} shreds", sent_count);
                            last_report = std::time::Instant::now();
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to send shred: {}", e);
                    }
                }
                
                // Simulate realistic shred rate (adjust as needed)
                thread::sleep(Duration::from_micros(100));
            }
        }
        
        // Pause before repeating
        println!("Completed sending {} shreds, restarting...", shred_count);
        thread::sleep(Duration::from_secs(1));
    }
}
