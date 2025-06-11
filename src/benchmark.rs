use crate::SipMessage;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::thread;
use std::time::Instant;

/// Benchmark function to measure SIP message parsing performance
pub fn benchmark_sip_parsing() {
    // Get the number of available CPU cores
    let num_cores = num_cpus::get();
    println!("Running benchmark on {} CPU cores", num_cores);
    // Simple SIP message for benchmarking
    let simple_message = "\
INVITE sip:bob@biloxi.com SIP/2.0\r
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r
Max-Forwards: 70\r
To: Bob <sip:bob@biloxi.com>\r
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r
Call-ID: a84b4c76e66710@pc33.atlanta.com\r
CSeq: 314159 INVITE\r
Contact: <sip:alice@pc33.atlanta.com>\r
Content-Length: 0\r\n\r\n";

    const ITERATIONS: usize = 10_000_000;

    println!(
        "\n\nBenchmarking SIP message parsing over {} iterations...",
        ITERATIONS
    );

    // Start timing
    let start = Instant::now();

    // Counter for 'B' starting display names in the To header
    // let mut b_count = 0;
    // Check the simple message format
    println!("\nSIP message for benchmarking:\n{}", simple_message);

    // Create a counter for successful parses (useful for verification)
    let successful_parses = AtomicUsize::new(0);

    // Run the first iteration separately to check the results
    {
        let mut message = SipMessage::new_from_str(simple_message);
        let _ = message.parse_headers();
        let to_result = message.to();
        println!("To header after explicit call: {:?}", to_result);
    }

    // Run the benchmark serially (for compatibility)
    println!("Note: This function uses a serial implementation now. Use run_comprehensive_benchmark for parallel execution.");

    for _ in 0..ITERATIONS {
        let mut message = SipMessage::new_from_str(simple_message);
        if message.parse_headers().is_ok() && message.to().is_ok() {
            successful_parses.fetch_add(1, Ordering::Relaxed);
        }
    }

    // Report successful parses as a sanity check
    println!(
        "\nSuccessful parses: {}",
        successful_parses.load(Ordering::Relaxed)
    );

    // Calculate elapsed time
    let duration = start.elapsed();

    // Print results
    println!("Time elapsed: {:?}", duration);
    println!("Average time per parse: {:?}", duration / ITERATIONS as u32);
    println!(
        "Parses per second: {:.2}",
        ITERATIONS as f64 / duration.as_secs_f64()
    );

    // Calculate throughput in MB/s
    let message_size = simple_message.len();
    let total_bytes = ITERATIONS * message_size;
    let throughput_mbps = (total_bytes as f64 / 1_000_000.0) / duration.as_secs_f64();
    println!("Message size: {} bytes", message_size);
    println!("Throughput: {:.2} MB/s", throughput_mbps);
}

/// Run a comprehensive benchmark that tests different aspects of SIP parsing
pub fn run_comprehensive_benchmark() {
    println!(">>>> Running Manual Thread-Based SIP Parsing Benchmark <<<<");

    // Get the number of available CPU cores
    let num_cores = num_cpus::get();
    println!("Running on {} CPU cores", num_cores);

    // Benchmark with different message types and sizes
    benchmark_manual_threads(BenchmarkType::ParsingOnly);
    benchmark_manual_threads(BenchmarkType::HeaderAccess);
    benchmark_manual_threads(BenchmarkType::ComplexMessage);
}

/// Enum to specify which type of benchmark to run
#[derive(Copy, Clone)]
enum BenchmarkType {
    ParsingOnly,
    HeaderAccess,
    ComplexMessage,
}

/// Benchmark using manual thread creation - one thread per core
fn benchmark_manual_threads(benchmark_type: BenchmarkType) {
    // Constants
    const ITERATIONS_PER_THREAD: usize = 1_000_000;

    // Print benchmark type
    let (title, message) = match benchmark_type {
        BenchmarkType::ParsingOnly => (
            "Parsing Only (no header access)",
            create_simple_sip_message(),
        ),
        BenchmarkType::HeaderAccess => ("Header Access", create_simple_sip_message()),
        BenchmarkType::ComplexMessage => ("Complex SIP Message", create_complex_sip_message()),
    };

    println!("\n--- Benchmark: {} ---", title);

    // Get the number of available CPU cores
    let num_cores = num_cpus::get();
    let total_iterations = ITERATIONS_PER_THREAD * num_cores;
    println!(
        "Running {} iterations ({} per thread on {} threads)",
        total_iterations, ITERATIONS_PER_THREAD, num_cores
    );

    // Create thread-safe message reference
    let message = Arc::new(message);

    // Create a counter for successful parses
    let successful_parses = Arc::new(AtomicUsize::new(0));

    // Start timing
    let start = Instant::now();

    // Spawn one thread per CPU core
    let mut handles = vec![];
    for _ in 0..num_cores {
        let message_clone = Arc::clone(&message);
        let counter_clone = Arc::clone(&successful_parses);

        let handle = thread::spawn(move || {
            // Run the specified number of iterations in this thread
            for _ in 0..ITERATIONS_PER_THREAD {
                match benchmark_type {
                    BenchmarkType::ParsingOnly => {
                        // Just parse the message
                        let mut sip_message = SipMessage::new_from_str(&message_clone);
                        if sip_message.parse_headers().is_ok() {
                            counter_clone.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    BenchmarkType::HeaderAccess => {
                        // Parse and access headers
                        let mut sip_message = SipMessage::new_from_str(&message_clone);
                        if sip_message.parse_headers().is_ok() {
                            let _ = sip_message.to();
                            let _ = sip_message.from();
                            let _ = sip_message.contact();
                            counter_clone.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    BenchmarkType::ComplexMessage => {
                        // Parse complex message and access headers
                        let mut sip_message = SipMessage::new_from_str(&message_clone);
                        if sip_message.parse_headers().is_ok() {
                            let _ = sip_message.to();
                            let _ = sip_message.from();
                            let _ = sip_message.via();
                            counter_clone.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
        });

        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }

    // Calculate elapsed time
    let duration = start.elapsed();

    // Print results
    print_benchmark_results(duration, total_iterations, message.len());
    println!(
        "Successful parses: {}",
        successful_parses.load(Ordering::Relaxed)
    );
}

/// Helper function to print benchmark results
fn print_benchmark_results(duration: std::time::Duration, iterations: usize, message_size: usize) {
    println!("Time elapsed: {:?}", duration);
    println!("Average time per parse: {:?}", duration / iterations as u32);
    println!(
        "Parses per second: {:.2}",
        iterations as f64 / duration.as_secs_f64()
    );

    // Calculate throughput
    let total_bytes = iterations * message_size;
    let throughput_mbps = (total_bytes as f64 / 1_000_000.0) / duration.as_secs_f64();
    println!("Message size: {} bytes", message_size);
    println!("Throughput: {:.2} MB/s", throughput_mbps);
}

/// Create a simple SIP message for benchmarking
fn create_simple_sip_message() -> String {
    "INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Contact: <sip:alice@pc33.atlanta.com>\r\n\
Content-Length: 0\r\n\r\n"
        .to_string()
}

/// Create a more complex SIP message with more headers and a body
fn create_complex_sip_message() -> String {
    "INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Via: SIP/2.0/TCP server10.biloxi.com;branch=z9hG4bK776asdhds;received=192.0.2.3\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Contact: <sip:alice@pc33.atlanta.com>\r\n\
User-Agent: SoftPhone/1.0\r\n\
Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO\r\n\
Content-Type: application/sdp\r\n\
Content-Length: 158\r\n\r\n\
v=0\r\n\
o=alice 2890844526 2890844526 IN IP4 pc33.atlanta.com\r\n\
s=Session SDP\r\n\
c=IN IP4 pc33.atlanta.com\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 0\r\n\
a=rtpmap:0 PCMU/8000\r\n"
        .to_string()
}
