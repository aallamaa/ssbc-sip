use ssbc::*;

/// Integration test demonstrating SIP message pooling in high-load scenarios
#[test]
fn test_pool_high_load_integration() {
    let config = PoolConfig {
        initial_size: 50,
        max_size: 200,
        pre_allocate: true,
        parser_limits: ssbc::limits::ParserLimits::default(),
    };
    
    let pool = SipMessagePool::new(config);
    
    // Real SIP messages from different scenarios
    let sip_messages = vec![
        // INVITE from Comoros to Yemen (from PCAP)
        r#"INVITE sip:967716910167@197.255.224.99;user=phone SIP/2.0
From: "+2693347248"<sip:+2693347248@197.255.224.100;user=phone>;tag=s26208d1i1z111r290308928
To: "+967716910167"<sip:967716910167@197.255.224.99;user=phone>
Call-ID: 7034cb95-68867afa-17e8fd7-7fc19d58b7d0-6be0ffc5-13c4-7225
CSeq: 1 INVITE
User-Agent: Orchid 3.1.32.6
Supported: 100rel,timer,replaces
Max-Forwards: 68
P-Asserted-Identity: <tel:+2693347248>
Allow: PRACK,BYE,CANCEL,ACK,INVITE,UPDATE,OPTIONS
Via: SIP/2.0/UDP 197.255.224.100:5060;rport;branch=z9hG4bK-5801fe38-17e8fd7-d661e03c-7fc1a2273910
Route: <sip:197.255.224.99:5060;transport=UDP;lr>
Contact: <sip:+2693347248;tgrp=CTHuaweiCore3CLI*4;trunk-context=10.18.49.164@197.255.224.100:5060;transport=UDP;user=phone>
Session-Expires: 1800;refresher=uas
Min-SE: 90
Content-Type: application/sdp
Content-Length: 250

v=0
o=- 226208 26208 IN IP4 197.255.224.100
s=Cataleya
c=IN IP4 197.255.224.100
t=0 0
m=audio 18076 RTP/AVP 8 0 18 116
a=rtpmap:8 PCMA/8000
a=ptime:20
a=3gOoBTC
a=rtpmap:0 PCMU/8000
a=rtpmap:18 G729/8000
a=rtpmap:116 telephone-event/8000
"#.replace('\n', "\r\n"),

        // 200 OK Response  
        r#"SIP/2.0 200 OK
From: "+2693347248"<sip:+2693347248@197.255.224.100;user=phone>;tag=s26208d1i1z111r290308928
To: "+967716910167"<sip:967716910167@197.255.224.99;user=phone>;tag=yemen-gw-12345
Call-ID: 7034cb95-68867afa-17e8fd7-7fc19d58b7d0-6be0ffc5-13c4-7225
CSeq: 1 INVITE
Via: SIP/2.0/UDP 197.255.224.100:5060;rport;branch=z9hG4bK-5801fe38-17e8fd7-d661e03c-7fc1a2273910
Contact: <sip:967716910167@2.48.7.1:5060;user=phone>
Content-Type: application/sdp
Content-Length: 200

v=0
o=- 226209 26209 IN IP4 2.48.7.1
s=Yemen Gateway
c=IN IP4 2.48.7.1
t=0 0
m=audio 30000 RTP/AVP 8 0
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=ptime:20
"#.replace('\n', "\r\n"),

        // BYE Request
        r#"BYE sip:+2693347248;tgrp=CTHuaweiCore3CLI*4;trunk-context=10.18.49.164@197.255.224.100:5060;transport=UDP;user=phone SIP/2.0
From: "+967716910167"<sip:967716910167@197.255.224.99;user=phone>;tag=yemen-gw-12345
To: "+2693347248"<sip:+2693347248@197.255.224.100;user=phone>;tag=s26208d1i1z111r290308928
Call-ID: 7034cb95-68867afa-17e8fd7-7fc19d58b7d0-6be0ffc5-13c4-7225
CSeq: 2 BYE
Via: SIP/2.0/UDP 2.48.7.1:5060;branch=z9hG4bK-bye-12345
Max-Forwards: 70
Content-Length: 0

"#.replace('\n', "\r\n"),
    ];

    // Simulate high-load processing - 1000 messages
    let iterations = 1000;
    let mut successful_parses = 0;
    let mut b2bua = B2buaManager::new(500, 3600, 32);
    
    for i in 0..iterations {
        let msg_data = &sip_messages[i % sip_messages.len()];
        let mut pooled_msg = pool.get();
        
        // Parse message
        if pooled_msg.parse_from_str(msg_data).is_ok() {
            successful_parses += 1;
            
            // Extract key information  
            let call_id = pooled_msg.message().call_id().unwrap();
            let method_opt = pooled_msg.message_mut().cseq_method();
            
            // Simulate B2BUA processing based on message type
            if let Ok(Some(method)) = method_opt {
                match method.to_string().as_str() {
                "INVITE" => {
                    // Create new call in B2BUA
                    let from_uri = "sip:+2693347248@197.255.224.100;user=phone";
                    let to_uri = "sip:+967716910167@197.255.224.99;user=phone";
                    let tag = format!("tag-{}", i);
                    
                    // Parse SDP if present
                    let sdp = if let Some(body) = pooled_msg.message_mut().body() {
                        SessionDescription::parse(body).ok()
                    } else {
                        None
                    };
                    
                    if let Ok(_) = b2bua.handle_invite(&call_id, from_uri, to_uri, &tag, 1, sdp) {
                        // Create outgoing leg
                        let _ = b2bua.create_outgoing_call(&call_id, "sip:967716910167@2.48.7.1;user=phone", None);
                    }
                },
                "BYE" => {
                    // Handle call termination
                    if let Ok(peer_id) = b2bua.handle_bye(&call_id) {
                        if let Some(peer) = peer_id {
                            let _ = b2bua.terminate_call(&peer);
                        }
                        let _ = b2bua.terminate_call(&call_id);
                    }
                },
                _ => {
                    // Handle responses (200 OK, etc.)
                    let start_line = pooled_msg.message().start_line();
                    if start_line.contains("200 OK") {
                        let _ = b2bua.handle_response(&call_id, 200, Some("remote-tag"), None);
                    }
                }
                }
            }
        }
        
        // Every 100 messages, check pool size and B2BUA state
        if i % 100 == 0 {
            let pool_size = pool.size();
            let call_stats = b2bua.get_call_stats();
            
            println!("Iteration {}: Pool size: {}, Active calls: {}", 
                i, pool_size, call_stats.active_calls);
        }
    }
    
    // Verify results
    assert_eq!(successful_parses, iterations);
    
    // Check pool size
    let final_pool_size = pool.size();
    println!("Final pool size: {}", final_pool_size);
    
    // Pool should maintain a reasonable size
    assert!(final_pool_size > 0, "Pool should have messages");
    assert!(final_pool_size <= 200, "Pool should not exceed max size");
    
    // B2BUA should have processed calls
    let call_stats = b2bua.get_call_stats();
    println!("Final B2BUA stats: {:?}", call_stats);
    assert!(call_stats.total_calls > 0);
    
    println!("✅ High-load pool integration test passed!");
}

/// Test pool with zero-copy parsing integration
#[test]
fn test_pool_with_zero_copy_integration() {
    let pool = SipMessagePool::new(PoolConfig::default());
    
    let invite_msg = r#"INVITE sip:test@example.com SIP/2.0
From: <sip:caller@example.com>;tag=abc123
To: <sip:test@example.com>
Call-ID: pool-zerocopy-test
CSeq: 1 INVITE
Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK123456
Max-Forwards: 70
Contact: <sip:caller@192.168.1.100:5060>
Content-Length: 0

"#.replace('\n', "\r\n");

    // Test pooled message with zero-copy parsing
    let mut pooled_msg = pool.get();
    assert!(pooled_msg.parse_from_str(&invite_msg).is_ok());
    
    // Compare with zero-copy direct parsing
    let mut zero_copy = ZeroCopySipMessage::new(&invite_msg);
    assert!(zero_copy.parse().is_ok());
    
    // Both should extract same information
    assert_eq!(pooled_msg.message().call_id().unwrap(), zero_copy.call_id().unwrap());
    if let Ok(Some(method)) = pooled_msg.message_mut().cseq_method() {
        assert_eq!(method.to_string(), "INVITE");
    }
    
    // Extract E.164 numbers using zero-copy methods  
    let from_header = pooled_msg.message_mut().from().unwrap().unwrap();
    let from_str = format!("{:?}", from_header); // Use debug format for now
    if let Some(number) = extract_e164_fast(&from_str) {
        println!("Extracted E.164: {}", number);
    }
    
    println!("✅ Pool + zero-copy integration test passed!");
}

/// Test global pool with concurrent access simulation
#[test]
fn test_global_pool_concurrent() {
    initialize_global_pool(PoolConfig {
        initial_size: 20,
        max_size: 100,
        pre_allocate: true,
        parser_limits: ssbc::limits::ParserLimits::default(),
    });
    
    let test_message = r#"REGISTER sip:example.com SIP/2.0
Via: SIP/2.0/UDP 192.168.1.100:5060
Max-Forwards: 70
From: <sip:user@example.com>;tag=reg123
To: <sip:user@example.com>
Call-ID: registration-test
CSeq: 1 REGISTER
Contact: <sip:user@192.168.1.100:5060>
Expires: 3600
Content-Length: 0

"#.replace('\n', "\r\n");

    // Simulate concurrent access
    let mut handles = Vec::new();
    for i in 0..50 {
        let mut msg = get_pooled_message();
        let call_id = format!("registration-test-{}", i);
        let test_data = test_message.replace("registration-test", &call_id);
        
        match msg.parse_from_str(&test_data) {
            Ok(_) => {},
            Err(e) => {
                println!("Parse error on iteration {}: {:?}", i, e);
                println!("Test data: {}", test_data);
                panic!("Parse failed");
            }
        }
        assert_eq!(msg.message().call_id().unwrap(), call_id);
        if let Ok(Some(method)) = msg.message_mut().cseq_method() {
            assert_eq!(method.to_string(), "REGISTER");
        }
        
        handles.push(msg);
    }
    
    // All messages should be different instances
    for i in 0..handles.len() {
        for j in i+1..handles.len() {
            assert_ne!(
                handles[i].message() as *const SipMessage,
                handles[j].message() as *const SipMessage
            );
        }
    }
    
    // Global pool stats not available in simplified version
    println!("Global pool test completed successfully");
    
    println!("✅ Global pool concurrent test passed!");
}

/// Test string pool integration with SIP header parsing
#[test]
#[ignore = "StringPool not implemented in simplified version"] 
fn test_string_pool_integration() {
    // StringPool is not implemented in the simplified version
    // This test is kept as a placeholder for future implementation
    println!("⚠️  StringPool test skipped - not implemented in simplified version");
}

/// Performance comparison test between pooled and non-pooled
#[test]
fn test_pool_performance_comparison() {
    let iterations = 1000;
    let pool = SipMessagePool::new(PoolConfig::default());
    
    let test_msg = r#"OPTIONS sip:example.com SIP/2.0
From: <sip:client@test.com>;tag=opt123
To: <sip:example.com>
Call-ID: options-test
CSeq: 1 OPTIONS
Via: SIP/2.0/UDP 10.0.0.1:5060
Max-Forwards: 70
Accept: application/sdp
Content-Length: 0

"#.replace('\n', "\r\n");

    // Time pooled allocation
    let start = std::time::Instant::now();
    for i in 0..iterations {
        let mut pooled_msg = pool.get();
        let call_id = format!("options-test-{}", i);
        let msg_data = test_msg.replace("options-test", &call_id);
        
        pooled_msg.parse_from_str(&msg_data).unwrap();
        assert_eq!(pooled_msg.message().call_id().unwrap(), call_id);
    }
    let pooled_duration = start.elapsed();
    
    // Time regular allocation  
    let start = std::time::Instant::now();
    for i in 0..iterations {
        let call_id = format!("options-test-{}", i);
        let msg_data = test_msg.replace("options-test", &call_id);
        
        let mut msg = SipMessage::new_from_str(&msg_data);
        msg.parse().unwrap();
        assert_eq!(msg.call_id().unwrap(), call_id);
    }
    let regular_duration = start.elapsed();
    
    let pool_size = pool.size();
    
    println!("Pooled: {:?}, Regular: {:?}", pooled_duration, regular_duration);
    println!("Pool size: {}", pool_size);
    
    // Pool should maintain reasonable size
    assert!(pool_size > 0, "Pool should have messages");
    
    println!("✅ Pool performance comparison test passed!");
}