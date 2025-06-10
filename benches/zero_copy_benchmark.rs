use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use ssbc::*;
use std::time::Duration;

/// Benchmark zero-copy parsing vs regular parsing
fn bench_zero_copy_vs_regular(c: &mut Criterion) {
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

    let mut group = c.benchmark_group("parsing_comparison");
    group.throughput(Throughput::Bytes(invite_msg.len() as u64));

    // Benchmark regular SSBC parsing
    group.bench_function("regular_ssbc", |b| {
        b.iter(|| {
            let mut sip_msg = SipMessage::new_from_str(black_box(&invite_msg));
            black_box(sip_msg.parse()).unwrap();
        })
    });

    // Benchmark zero-copy parsing
    group.bench_function("zero_copy", |b| {
        b.iter(|| {
            let mut zero_copy_msg = ZeroCopySipMessage::new(black_box(&invite_msg));
            black_box(zero_copy_msg.parse()).unwrap();
        })
    });

    group.finish();
}

/// Benchmark header access patterns
fn bench_header_access_comparison(c: &mut Criterion) {
    let invite_msg = r#"INVITE sip:967716910167@197.255.224.99;user=phone SIP/2.0
From: "+2693347248"<sip:+2693347248@197.255.224.100;user=phone>;tag=s26208d1i1z111r290308928
To: "+967716910167"<sip:967716910167@197.255.224.99;user=phone>
Call-ID: 7034cb95-68867afa-17e8fd7-7fc19d58b7d0-6be0ffc5-13c4-7225
CSeq: 1 INVITE
Via: SIP/2.0/UDP 197.255.224.100:5060;rport;branch=z9hG4bK-5801fe38-17e8fd7-d661e03c-7fc1a2273910
Max-Forwards: 70
Content-Length: 0

"#.replace('\n', "\r\n");

    // Pre-parse both message types
    let mut regular_msg = SipMessage::new_from_str(&invite_msg);
    regular_msg.parse().unwrap();
    
    let mut zero_copy_msg = ZeroCopySipMessage::new(&invite_msg);
    zero_copy_msg.parse().unwrap();

    let mut group = c.benchmark_group("header_access_comparison");

    // Benchmark Call-ID access
    group.bench_function("regular_call_id", |b| {
        b.iter(|| {
            black_box(regular_msg.call_id()).unwrap();
        })
    });

    group.bench_function("zero_copy_call_id", |b| {
        b.iter(|| {
            black_box(zero_copy_msg.call_id()).unwrap();
        })
    });

    // Benchmark From header access
    group.bench_function("regular_from", |b| {
        b.iter(|| {
            black_box(regular_msg.from()).unwrap();
        })
    });

    group.bench_function("zero_copy_from", |b| {
        b.iter(|| {
            black_box(zero_copy_msg.from_header()).unwrap();
        })
    });

    // Benchmark Via headers access
    group.bench_function("regular_via", |b| {
        b.iter(|| {
            black_box(regular_msg.all_vias()).unwrap();
        })
    });

    group.bench_function("zero_copy_via", |b| {
        b.iter(|| {
            black_box(zero_copy_msg.via_headers());
        })
    });

    group.finish();
}

/// Benchmark E.164 extraction optimizations
fn bench_e164_extraction(c: &mut Criterion) {
    let uris = vec![
        "sip:+2693347248@197.255.224.100;user=phone",
        "sip:+967716910167@197.255.224.99;user=phone", 
        "sip:+21641569140@185.28.14.11;user=phone",
        "tel:+14073982735",
        "sip:+44126439501@host;user=phone",
    ];

    let mut group = c.benchmark_group("e164_extraction");

    // Original implementation
    group.bench_function("original", |b| {
        b.iter(|| {
            for uri in &uris {
                black_box(extract_e164_number(black_box(uri)));
            }
        })
    });

    // Zero-copy optimized implementation
    group.bench_function("zero_copy_fast", |b| {
        b.iter(|| {
            for uri in &uris {
                black_box(extract_e164_fast(black_box(uri)));
            }
        })
    });

    group.finish();
}

/// Benchmark trunk group extraction optimizations
fn bench_trunk_group_extraction(c: &mut Criterion) {
    let contacts = vec![
        "<sip:+2693347248;tgrp=CTHuaweiCore3CLI*4;trunk-context=10.18.49.164@197.255.224.100:5060>",
        "<sip:967716910167;tgrp=ETISALATCLI31CLI76@197.255.224.100;transport=UDP;user=phone>;q=1.00",
        "<sip:967716910167;tgrp=BICSCLI10CLI19@197.255.224.100;transport=UDP;user=phone>;q=0.99",
        "<sip:967716910167;tgrp=OrangeHubbingIn21CLI88@197.255.224.100;transport=UDP;user=phone>;q=0.98",
    ];

    let mut group = c.benchmark_group("trunk_group_extraction");

    // Original implementation
    group.bench_function("original", |b| {
        b.iter(|| {
            for contact in &contacts {
                black_box(extract_trunk_group(black_box(contact)));
            }
        })
    });

    // Zero-copy optimized implementation
    group.bench_function("zero_copy_fast", |b| {
        b.iter(|| {
            for contact in &contacts {
                black_box(extract_trunk_group_fast(black_box(contact)));
            }
        })
    });

    group.finish();
}

/// Benchmark high-volume parsing with zero-copy
fn bench_high_volume_zero_copy(c: &mut Criterion) {
    let messages = vec![
        r#"INVITE sip:test@example.com SIP/2.0
From: <sip:caller@example.com>;tag=123
To: <sip:test@example.com>
Call-ID: test-call-id-1
CSeq: 1 INVITE
Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK123
Content-Length: 0

"#.replace('\n', "\r\n"),
        r#"SIP/2.0 200 OK
From: <sip:caller@example.com>;tag=123
To: <sip:test@example.com>;tag=456
Call-ID: test-call-id-2
CSeq: 1 INVITE
Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK123
Content-Length: 0

"#.replace('\n', "\r\n"),
        r#"BYE sip:test@example.com SIP/2.0
From: <sip:caller@example.com>;tag=123
To: <sip:test@example.com>;tag=456
Call-ID: test-call-id-3
CSeq: 2 BYE
Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK456
Content-Length: 0

"#.replace('\n', "\r\n"),
    ];

    let mut group = c.benchmark_group("high_volume_zero_copy");
    group.measurement_time(Duration::from_secs(5));

    for size in [1000, 5000, 10000].iter() {
        group.throughput(Throughput::Elements(*size as u64));
        
        group.bench_with_input(BenchmarkId::new("regular", size), size, |b, &size| {
            b.iter(|| {
                for i in 0..size {
                    let msg = &messages[i % messages.len()];
                    let mut sip_msg = SipMessage::new_from_str(black_box(msg));
                    black_box(sip_msg.parse()).unwrap();
                }
            })
        });

        group.bench_with_input(BenchmarkId::new("zero_copy", size), size, |b, &size| {
            b.iter(|| {
                for i in 0..size {
                    let msg = &messages[i % messages.len()];
                    let mut zero_copy_msg = ZeroCopySipMessage::new(black_box(msg));
                    black_box(zero_copy_msg.parse()).unwrap();
                }
            })
        });
    }

    group.finish();
}

// Helper functions from original implementation for comparison
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

criterion_group!(
    benches,
    bench_zero_copy_vs_regular,
    bench_header_access_comparison,
    bench_e164_extraction,
    bench_trunk_group_extraction,
    bench_high_volume_zero_copy
);
criterion_main!(benches);