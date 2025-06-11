use ssbc::*;

fn main() {
    println!("🚀 SSBC SIP Message Pooling Demo");
    
    // Initialize pool with custom configuration
    let config = PoolConfig {
        initial_size: 10,
        max_size: 50,
        pre_allocate: true,
        parser_limits: ssbc::limits::ParserLimits::default(),
    };
    
    let pool = SipMessagePool::new(config);
    println!("✅ Created SIP message pool with {} pre-allocated messages", pool.size());
    
    // Test SIP message from real PCAP
    let sip_invite = r#"INVITE sip:967716910167@197.255.224.99;user=phone SIP/2.0
From: "+2693347248"<sip:+2693347248@197.255.224.100;user=phone>;tag=s26208d1i1z111r290308928
To: "+967716910167"<sip:967716910167@197.255.224.99;user=phone>
Call-ID: 7034cb95-68867afa-17e8fd7-7fc19d58b7d0-6be0ffc5-13c4-7225
CSeq: 1 INVITE
User-Agent: Orchid 3.1.32.6
Via: SIP/2.0/UDP 197.255.224.100:5060;rport;branch=z9hG4bK-5801fe38
Content-Length: 0

"#.replace('\n', "\r\n");

    // Demonstrate pooled message usage
    println!("\n📋 Testing pooled message parsing:");
    let mut pooled_msg = pool.get();
    
    match pooled_msg.parse_from_str(&sip_invite) {
        Ok(_) => {
            println!("✅ Successfully parsed SIP INVITE from Comoros to Yemen");
            if let Some(call_id) = pooled_msg.message().call_id() {
                println!("   Call-ID: {}", call_id);
            }
            if let Ok(Some(method)) = pooled_msg.message_mut().cseq_method() {
                println!("   Method: {}", method);
            }
        },
        Err(e) => println!("❌ Parse error: {}", e),
    }
    
    // Drop pooled message (returns to pool)
    drop(pooled_msg);
    
    // Pool size
    println!("\n📊 Pool Information:");
    println!("   Current pool size: {}", pool.size());
    
    // Demonstrate high-throughput scenario
    println!("\n⚡ High-throughput test (1000 messages):");
    let start = std::time::Instant::now();
    
    for i in 0..1000 {
        let mut msg = pool.get();
        let test_data = sip_invite.replace("7034cb95", &format!("call-{:06}", i));
        if msg.parse_from_str(&test_data).is_ok() {
            // Simulate processing
            let _ = msg.message().call_id();
        }
        // Message automatically returned to pool on drop
    }
    
    let duration = start.elapsed();
    let msg_per_sec = 1000.0 / duration.as_secs_f64();
    
    println!("   Processed 1000 messages in {:?}", duration);
    println!("   Rate: {:.0} messages/second", msg_per_sec);
    
    // Final pool size
    println!("\n📊 Final Pool Information:");
    println!("   Pool size after test: {}", pool.size());
    
    // Test global pool
    println!("\n🌍 Testing global pool:");
    initialize_global_pool(PoolConfig::default());
    
    let mut global_msg = get_pooled_message();
    match global_msg.parse_from_str(&sip_invite) {
        Ok(_) => println!("✅ Global pool parsing successful"),
        Err(e) => println!("❌ Global pool error: {}", e),
    }
    
    println!("   Global pool initialized successfully");
    
    // String pooling is not implemented in this version
    println!("\n📝 String pooling not implemented in simplified version");
    
    println!("\n🎉 Pool demo completed successfully!");
}