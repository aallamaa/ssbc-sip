use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use ssbc::*;
use std::time::Duration;

/// Real SIP messages from production PCAP analysis for benchmarking
struct SipMessageSamples {
    invite_with_sdp: &'static str,
    redirect_302: &'static str,
    trying_100: &'static str,
    prack_request: &'static str,
    complex_contact: &'static str,
}

impl SipMessageSamples {
    fn new() -> Self {
        Self {
            invite_with_sdp: r#"INVITE sip:967716910167@197.255.224.99;user=phone SIP/2.0
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
Contact: <sip:+2693347248;tgrp=CTHuaweiCore3CLI*4;trunk-context=10.18.49.164@197.255.224.100:5060;transport=UDP;user=phone;Hpt=nw_10_670d1607_199bf16_ex_8e48_16;CxtId=4;TRC=ffffffff-ffffffff>
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
"#,
            redirect_302: r#"SIP/2.0 302 Moved Temporarily
Via: SIP/2.0/UDP 197.255.224.100:5060;rport=5060;received=197.255.224.99;branch=z9hG4bK-5801fe38-17e8fd7-d661e03c-7fc1a2273910
To: "+967716910167"<sip:967716910167@197.255.224.99;user=phone>
From: "+2693347248"<sip:+2693347248@197.255.224.100;user=phone>;tag=s26208d1i1z111r290308928
Call-ID: 7034cb95-68867afa-17e8fd7-7fc19d58b7d0-6be0ffc5-13c4-7225
CSeq: 1 INVITE
Server: CoreX ASR v2.0
Reason: SIP ;cause=302 ;text=""
Contact: <sip:967716910167;tgrp=ETISALATCLI31CLI76@197.255.224.100;transport=UDP;user=phone>;q=1.00, <sip:967716910167;tgrp=BICSCLI10CLI19@197.255.224.100;transport=UDP;user=phone>;q=0.99, <sip:967716910167;tgrp=OrangeHubbingIn21CLI88@197.255.224.100;transport=UDP;user=phone>;q=0.98
Content-Length: 0

"#,
            trying_100: r#"SIP/2.0 100 Trying
From: "+2693347248"<sip:+2693347248@10.18.49.164;user=phone>;tag=6qlgdzz6-CC-1006-OFC-22
To: "+967716910167"<sip:+967716910167@10.18.49.164;user=phone>
Call-ID: isbcyvmfv6zfgxhhh65xfwmgzy6dfqzxd76v@10.18.5.64
CSeq: 1 INVITE
User-Agent: Orchid 3.1.32.6
Supported: 100rel,timer,replaces
Allow: PRACK,BYE,CANCEL,ACK,INVITE,UPDATE,OPTIONS
Via: SIP/2.0/UDP 10.18.5.138:5060;branch=z9hG4bKsi9rufuuoi0e9uwrtrr2arfa2;Role=3;Hpt=8e48_16
Contact: <sip:10.18.49.164:5060>
Content-Length: 0

"#,
            prack_request: r#"PRACK sip:2.48.7.1:5060;transport=udp;Hpt=nw_1c1_670d2417_1df2421_ex_8fa8_16;CxtId=3;TRC=ffffffff-ffffffff SIP/2.0
From: "+2693347248"<sip:+2693347248@197.255.224.100;user=phone>;tag=s26208d1i1z111r290308928
To: "+967716910167"<sip:967716910167@197.255.224.99;user=phone>;tag=response-tag-123
Call-ID: 666e4d6b-6532cfe1-17e8fd7-7fc19d7e63c8-6be0ffc5-13c4-7225
CSeq: 2 PRACK
RAck: 1 1 INVITE
Via: SIP/2.0/UDP 197.255.224.106:5060;branch=z9hG4bK-prack-branch-123
Max-Forwards: 70
Content-Length: 0

"#,
            complex_contact: r#"INVITE sip:test@example.com SIP/2.0
From: <sip:caller@example.com>;tag=abc123
To: <sip:test@example.com>
Call-ID: test-call-id@example.com
CSeq: 1 INVITE
Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK123456
Max-Forwards: 70
Contact: <sip:+2693347248;tgrp=CTHuaweiCore3CLI*4;trunk-context=10.18.49.164@197.255.224.100:5060;transport=UDP;user=phone;Hpt=nw_10_670d1607_199bf16_ex_8e48_16;CxtId=4;TRC=ffffffff-ffffffff>
Content-Length: 0

"#,
        }
    }

    fn to_sip_format(&self, msg: &str) -> String {
        msg.replace('\n', "\r\n")
    }
}

/// Benchmark basic SIP message parsing
fn bench_parsing_performance(c: &mut Criterion) {
    let samples = SipMessageSamples::new();
    
    let messages = vec![
        ("INVITE_WITH_SDP", samples.to_sip_format(samples.invite_with_sdp)),
        ("302_REDIRECT", samples.to_sip_format(samples.redirect_302)),
        ("100_TRYING", samples.to_sip_format(samples.trying_100)),
        ("PRACK_REQUEST", samples.to_sip_format(samples.prack_request)),
        ("COMPLEX_CONTACT", samples.to_sip_format(samples.complex_contact)),
    ];

    let mut group = c.benchmark_group("message_parsing");
    
    for (name, message) in messages {
        group.throughput(Throughput::Bytes(message.len() as u64));
        group.bench_with_input(BenchmarkId::new("parse", name), &message, |b, msg| {
            b.iter(|| {
                let mut sip_msg = SipMessage::new_from_str(black_box(msg));
                black_box(sip_msg.parse()).unwrap();
            })
        });
    }
    group.finish();
}

/// Benchmark header access patterns
fn bench_header_access(c: &mut Criterion) {
    let samples = SipMessageSamples::new();
    let invite_msg = samples.to_sip_format(samples.invite_with_sdp);
    
    // Pre-parse the message for header access benchmarks
    let mut parsed_msg = SipMessage::new_from_str(&invite_msg);
    parsed_msg.parse().unwrap();

    let mut group = c.benchmark_group("header_access");
    
    group.bench_function("via_headers", |b| {
        b.iter(|| {
            black_box(parsed_msg.all_vias()).unwrap();
        })
    });

    group.bench_function("from_header", |b| {
        b.iter(|| {
            black_box(parsed_msg.from()).unwrap();
        })
    });

    group.bench_function("to_header", |b| {
        b.iter(|| {
            black_box(parsed_msg.to()).unwrap();
        })
    });

    group.bench_function("contact_headers", |b| {
        b.iter(|| {
            // Contact parsing may fail due to complex parameters, that's okay
            let _ = black_box(parsed_msg.contacts());
        })
    });

    group.bench_function("call_id", |b| {
        b.iter(|| {
            black_box(parsed_msg.call_id()).unwrap();
        })
    });

    group.bench_function("cseq", |b| {
        b.iter(|| {
            black_box(parsed_msg.cseq_method()).unwrap();
        })
    });

    group.finish();
}

/// Benchmark high-volume parsing scenarios
fn bench_high_volume_parsing(c: &mut Criterion) {
    let samples = SipMessageSamples::new();
    let messages = vec![
        samples.to_sip_format(samples.invite_with_sdp),
        samples.to_sip_format(samples.redirect_302),
        samples.to_sip_format(samples.trying_100),
        samples.to_sip_format(samples.prack_request),
    ];

    let mut group = c.benchmark_group("high_volume");
    group.measurement_time(Duration::from_secs(10));
    
    for size in [100, 1000, 5000, 10000].iter() {
        group.throughput(Throughput::Elements(*size as u64));
        group.bench_with_input(BenchmarkId::new("parse_batch", size), size, |b, &size| {
            b.iter(|| {
                for i in 0..size {
                    let msg = &messages[i % messages.len()];
                    let mut sip_msg = SipMessage::new_from_str(black_box(msg));
                    black_box(sip_msg.parse()).unwrap();
                }
            })
        });
    }
    group.finish();
}

/// Benchmark memory allocations during parsing
fn bench_memory_allocation(c: &mut Criterion) {
    let samples = SipMessageSamples::new();
    let invite_msg = samples.to_sip_format(samples.invite_with_sdp);
    
    let mut group = c.benchmark_group("memory_allocation");
    group.measurement_time(Duration::from_secs(5));
    
    // Benchmark creating and parsing fresh messages
    group.bench_function("fresh_parse", |b| {
        b.iter(|| {
            let mut sip_msg = SipMessage::new_from_str(black_box(&invite_msg));
            black_box(sip_msg.parse()).unwrap();
            // Message is dropped here, measuring allocation/deallocation cost
        })
    });

    // Benchmark reusing SipMessage instances
    group.bench_function("reused_instance", |b| {
        let mut sip_msg = SipMessage::new_from_str(&invite_msg);
        b.iter(|| {
            // Reset and reparse with the same instance
            sip_msg = SipMessage::new_from_str(black_box(&invite_msg));
            black_box(sip_msg.parse()).unwrap();
        })
    });

    group.finish();
}

/// Benchmark SIP routing logic from real PCAP scenarios
fn bench_routing_logic(c: &mut Criterion) {
    let mut group = c.benchmark_group("routing_logic");
    
    // E.164 number extraction benchmark
    let uris = vec![
        "sip:+2693347248@197.255.224.100;user=phone",
        "sip:+967716910167@197.255.224.99;user=phone", 
        "sip:+21641569140@185.28.14.11;user=phone",
        "tel:+14073982735",
        "sip:alice@example.com", // No E.164
    ];

    group.bench_function("e164_extraction", |b| {
        b.iter(|| {
            for uri in &uris {
                black_box(extract_e164_number(black_box(uri)));
            }
        })
    });

    // Country code analysis benchmark
    let numbers = vec!["+2693347248", "+967716910167", "+21641569140", "+14073982735"];
    
    group.bench_function("country_analysis", |b| {
        b.iter(|| {
            for number in &numbers {
                black_box(analyze_e164_number(black_box(number)));
            }
        })
    });

    // Trunk group extraction benchmark
    let contact_headers = vec![
        "<sip:+2693347248;tgrp=CTHuaweiCore3CLI*4;trunk-context=10.18.49.164@197.255.224.100:5060>",
        "<sip:967716910167;tgrp=ETISALATCLI31CLI76@197.255.224.100;transport=UDP;user=phone>;q=1.00",
        "<sip:967716910167;tgrp=BICSCLI10CLI19@197.255.224.100;transport=UDP;user=phone>;q=0.99",
    ];

    group.bench_function("trunk_group_extraction", |b| {
        b.iter(|| {
            for header in &contact_headers {
                black_box(extract_trunk_group(black_box(header)));
            }
        })
    });

    group.finish();
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

fn extract_trunk_group(contact_str: &str) -> Option<String> {
    for part in contact_str.split(';') {
        let part = part.trim();
        if part.to_lowercase().starts_with("tgrp=") {
            if let Some(tgrp_value) = part.split('=').nth(1) {
                let clean_value = tgrp_value.split('@').next()
                    .unwrap_or(tgrp_value)
                    .split('>').next()
                    .unwrap_or(tgrp_value);
                return Some(clean_value.to_string());
            }
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

criterion_group!(
    benches,
    bench_parsing_performance,
    bench_header_access,
    bench_high_volume_parsing,
    bench_memory_allocation,
    bench_routing_logic
);
criterion_main!(benches);