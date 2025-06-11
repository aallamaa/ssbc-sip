use ssbc::*;

/// Integration test demonstrating full B2BUA functionality with real PCAP data
#[test]
fn test_b2bua_complete_call_flow() {
    // Real INVITE message from PCAP analysis
    let invite_msg = r#"INVITE sip:967716910167@197.255.224.99;user=phone SIP/2.0
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
"#.replace('\n', "\r\n");

    // Step 1: Parse the incoming INVITE using SSBC
    let mut sip_msg = SipMessage::new_from_str(&invite_msg);
    assert!(sip_msg.parse_headers().is_ok());

    // Step 2: Extract call information for routing
    let call_id = sip_msg.call_id().unwrap();
    let from_header = sip_msg.from().unwrap().unwrap();
    let to_header = sip_msg.to().unwrap().unwrap();
    
    // Step 3: Extract E.164 numbers for routing decisions  
    let calling_number = "+2693347248"; // From header in PCAP
    let called_number = "+967716910167"; // To header in PCAP
    
    println!("Call from {} to {}", calling_number, called_number);
    
    // Step 4: Analyze routing (Comoros to Yemen)
    let (calling_country, _cc1, tier1) = analyze_e164_number(calling_number);
    let (called_country, _cc2, tier2) = analyze_e164_number(called_number);
    
    assert_eq!(calling_country, "Comoros");
    assert_eq!(called_country, "Yemen");
    assert_eq!(tier1, "Premium");
    assert_eq!(tier2, "Standard");
    
    // Step 5: Parse SDP for media capabilities
    let body = sip_msg.body().unwrap();
    let session_desc = SessionDescription::parse(body).unwrap();
    
    assert_eq!(session_desc.media_descriptions.len(), 1);
    let audio_media = &session_desc.media_descriptions[0];
    assert_eq!(audio_media.media_type, "audio");
    assert_eq!(audio_media.port, 18076);
    
    // Extract codecs
    let codecs = session_desc.extract_codecs();
    assert!(codecs.iter().any(|c| c.name == "PCMA"));
    assert!(codecs.iter().any(|c| c.name == "PCMU"));
    assert!(codecs.iter().any(|c| c.name == "G729"));
    
    // Step 6: Initialize B2BUA
    let mut b2bua = B2buaManager::new(1000, 3600, 32);
    
    // Step 7: Handle incoming call
    let incoming_call_id = b2bua.handle_invite(
        &call_id,
        "sip:+2693347248@197.255.224.100;user=phone",
        "sip:+967716910167@197.255.224.99;user=phone",
        "s26208d1i1z111r290308928",
        1,
        Some(session_desc.clone())
    ).unwrap();
    
    // Step 8: Create outgoing call with modified SDP
    let mut outgoing_sdp = session_desc.clone();
    outgoing_sdp.rewrite_connection_addresses("10.0.0.1"); // B2BUA address
    outgoing_sdp.change_media_port(0, 20000); // New media port
    
    let outgoing_call_id = b2bua.create_outgoing_call(
        &incoming_call_id,
        "sip:967716910167@2.48.7.1;user=phone", // Route to Yemen gateway
        Some(outgoing_sdp)
    ).unwrap();
    
    // Verify call pairing
    assert_eq!(b2bua.get_peer_call_id(&incoming_call_id), Some(&outgoing_call_id));
    
    // Step 9: Simulate call progression
    
    // 100 Trying
    b2bua.handle_response(&outgoing_call_id, 100, None, None).unwrap();
    assert_eq!(b2bua.get_call(&outgoing_call_id).unwrap().dialog.state, CallState::Proceeding);
    
    // 200 OK with SDP answer
    let mut answer_sdp = session_desc.clone();
    answer_sdp.rewrite_connection_addresses("2.48.7.1"); // Yemen gateway
    answer_sdp.change_media_port(0, 30000);
    answer_sdp.filter_codecs(&["PCMA", "PCMU"]); // Filter to compatible codecs
    
    b2bua.handle_response(&outgoing_call_id, 200, Some("yemen-tag"), Some(answer_sdp)).unwrap();
    assert_eq!(b2bua.get_call(&outgoing_call_id).unwrap().dialog.state, CallState::Connecting);
    
    // ACK to establish call
    b2bua.handle_ack(&outgoing_call_id).unwrap();
    assert_eq!(b2bua.get_call(&outgoing_call_id).unwrap().dialog.state, CallState::Connected);
    
    // Propagate 200 OK back to incoming leg
    b2bua.handle_response(&incoming_call_id, 200, Some("local-tag"), None).unwrap();
    b2bua.handle_ack(&incoming_call_id).unwrap();
    assert_eq!(b2bua.get_call(&incoming_call_id).unwrap().dialog.state, CallState::Connected);
    
    // Step 10: Setup media relay
    b2bua.setup_media_relay(&incoming_call_id, &outgoing_call_id, 20000, 30000).unwrap();
    
    // Verify media relay setup
    let incoming_leg = b2bua.get_call(&incoming_call_id).unwrap();
    let outgoing_leg = b2bua.get_call(&outgoing_call_id).unwrap();
    
    assert!(incoming_leg.media_relay.is_some());
    assert!(outgoing_leg.media_relay.is_some());
    
    // Step 11: Get call statistics
    let stats = b2bua.get_call_stats();
    assert_eq!(stats.total_calls, 2);
    assert_eq!(stats.connected_calls, 2);
    assert_eq!(stats.active_calls, 2);
    
    // Step 12: Handle call termination
    let peer_id = b2bua.handle_bye(&incoming_call_id).unwrap();
    assert_eq!(peer_id, Some(outgoing_call_id.clone()));
    
    // Terminate both legs
    b2bua.terminate_call(&incoming_call_id).unwrap();
    b2bua.terminate_call(&outgoing_call_id).unwrap();
    
    // Verify cleanup
    assert!(b2bua.get_call(&incoming_call_id).is_none());
    assert!(b2bua.get_call(&outgoing_call_id).is_none());
    
    println!("✅ Complete B2BUA call flow test passed!");
}

/// Test zero-copy parsing with B2BUA
#[test]
fn test_zero_copy_b2bua_integration() {
    let invite_msg = r#"INVITE sip:test@example.com SIP/2.0
From: <sip:caller@example.com>;tag=abc123
To: <sip:test@example.com>
Call-ID: test-call-integration
CSeq: 1 INVITE
Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK123456
Max-Forwards: 70
Contact: <sip:caller@192.168.1.100:5060>
Content-Length: 0

"#.replace('\n', "\r\n");

    // Parse with zero-copy
    let mut zero_copy_msg = ZeroCopySipMessage::new(&invite_msg);
    assert!(zero_copy_msg.parse().is_ok());
    
    // Extract call info using zero-copy methods
    let call_id = zero_copy_msg.call_id().unwrap();
    let from_header = zero_copy_msg.from_header().unwrap();
    let to_header = zero_copy_msg.to_header().unwrap();
    
    // Initialize B2BUA and create call
    let mut b2bua = B2buaManager::new(100, 3600, 32);
    let result = b2bua.handle_invite(call_id, from_header, to_header, "abc123", 1, None);
    
    assert!(result.is_ok());
    assert!(b2bua.get_call(call_id).is_some());
    
    println!("✅ Zero-copy B2BUA integration test passed!");
}

/// Test error handling and recovery
#[test]
fn test_error_handling_integration() {
    // Test malformed SIP message
    let malformed_msg = "INVALID SIP MESSAGE\r\n";
    
    let mut sip_msg = SipMessage::new_from_str(malformed_msg);
    let result = sip_msg.parse_headers();
    
    assert!(result.is_err());
    
    // Test B2BUA capacity limits
    let mut b2bua = B2buaManager::new(1, 3600, 32); // Max 1 call
    
    // First call succeeds
    let result1 = b2bua.handle_invite("call1", "sip:a@test.com", "sip:b@test.com", "tag1", 1, None);
    assert!(result1.is_ok());
    
    // Second call fails due to capacity
    let result2 = b2bua.handle_invite("call2", "sip:c@test.com", "sip:d@test.com", "tag2", 1, None);
    assert!(result2.is_err());
    
    if let Err(SsbcError::ResourceError { resource_type, current_usage, limit, .. }) = result2 {
        assert_eq!(resource_type, ResourceType::ConcurrentCalls);
        assert_eq!(current_usage, 1);
        assert_eq!(limit, 1);
    } else {
        panic!("Expected ResourceError");
    }
    
    println!("✅ Error handling integration test passed!");
}

/// Test SDP modification and codec negotiation
#[test]
fn test_sdp_codec_negotiation() {
    let sdp_offer = r#"v=0
o=- 226208 26208 IN IP4 197.255.224.100
s=Test
c=IN IP4 197.255.224.100
t=0 0
m=audio 18076 RTP/AVP 8 0 18 116
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:18 G729/8000
a=rtpmap:116 telephone-event/8000"#;

    let mut session = SessionDescription::parse(sdp_offer).unwrap();
    
    // Original codecs
    let original_codecs = session.extract_codecs();
    assert_eq!(original_codecs.len(), 4);
    
    // Filter to only allow PCMU and PCMA
    session.filter_codecs(&["PCMU", "PCMA"]);
    let filtered_codecs = session.extract_codecs();
    assert_eq!(filtered_codecs.len(), 2);
    assert!(filtered_codecs.iter().any(|c| c.name == "PCMU"));
    assert!(filtered_codecs.iter().any(|c| c.name == "PCMA"));
    assert!(!filtered_codecs.iter().any(|c| c.name == "G729"));
    
    // Change connection address for B2BUA
    session.rewrite_connection_addresses("10.0.0.1");
    assert_eq!(session.connection.as_ref().unwrap().connection_address, "10.0.0.1");
    assert_eq!(session.origin.unicast_address, "10.0.0.1");
    
    // Change media port
    session.change_media_port(0, 20000);
    assert_eq!(session.media_descriptions[0].port, 20000);
    
    // Convert back to string
    let modified_sdp = session.to_string();
    assert!(modified_sdp.contains("c=IN IP4 10.0.0.1"));
    assert!(modified_sdp.contains("m=audio 20000"));
    
    println!("✅ SDP codec negotiation test passed!");
}

/// Performance test with real PCAP data
#[test]
fn test_performance_with_real_data() {
    let invite_msg = r#"INVITE sip:967716910167@197.255.224.99;user=phone SIP/2.0
From: "+2693347248"<sip:+2693347248@197.255.224.100;user=phone>;tag=s26208d1i1z111r290308928
To: "+967716910167"<sip:967716910167@197.255.224.99;user=phone>
Call-ID: perf-test-call
CSeq: 1 INVITE
Via: SIP/2.0/UDP 197.255.224.100:5060;rport;branch=z9hG4bK-5801fe38
Max-Forwards: 70
Content-Length: 0

"#.replace('\n', "\r\n");

    let start = std::time::Instant::now();
    
    // Parse 1000 messages
    for i in 0..1000 {
        let msg = invite_msg.replace("perf-test-call", &format!("call-{}", i));
        let mut sip_msg = SipMessage::new_from_str(&msg);
        assert!(sip_msg.parse_headers().is_ok());
        
        // Extract key information
        let _call_id = sip_msg.call_id().unwrap();
        let _from = sip_msg.from().unwrap();
        let _to = sip_msg.to().unwrap();
    }
    
    let elapsed = start.elapsed();
    let messages_per_second = 1000.0 / elapsed.as_secs_f64();
    
    println!("Parsed 1000 messages in {:?} ({:.0} msg/sec)", elapsed, messages_per_second);
    
    // Should handle at least 10,000 messages per second
    assert!(messages_per_second > 10000.0);
    
    println!("✅ Performance test passed!");
}

// Helper functions from routing tests
fn extract_e164_number(uri_str: &str) -> Option<String> {
    if let Some(start) = uri_str.find("+") {
        let after_plus = &uri_str[start + 1..];
        let number: String = after_plus.chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        if !number.is_empty() {
            return Some(format!("+{}", number));
        }
    }
    None
}

fn analyze_e164_number(number: &str) -> (String, String, String) {
    if !number.starts_with('+') {
        return ("Unknown".to_string(), "Unknown".to_string(), "Unknown".to_string());
    }
    
    let digits = &number[1..];
    
    match digits {
        n if n.starts_with("269") => ("Comoros".to_string(), "269".to_string(), "Premium".to_string()),
        n if n.starts_with("967") => ("Yemen".to_string(), "967".to_string(), "Standard".to_string()),
        n if n.starts_with("216") => ("Tunisia".to_string(), "216".to_string(), "Standard".to_string()),
        n if n.starts_with("1") => ("NANP".to_string(), "1".to_string(), "Premium".to_string()),
        n if n.starts_with("44") => ("UK".to_string(), "44".to_string(), "Premium".to_string()),
        _ => ("Unknown".to_string(), "Unknown".to_string(), "Standard".to_string()),
    }
}