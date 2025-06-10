use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use ssbc::*;

/// Benchmark SIP message pooling performance vs regular allocation
fn bench_pool_vs_allocation(c: &mut Criterion) {
    let sip_invite = r#"INVITE sip:test@example.com SIP/2.0
From: <sip:caller@example.com>;tag=abc123
To: <sip:test@example.com>
Call-ID: benchmark-call-id
CSeq: 1 INVITE
Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK123456
Max-Forwards: 70
Contact: <sip:caller@192.168.1.100:5060>
Content-Length: 0

"#.replace('\n', "\r\n");

    let pool_config = PoolConfig {
        initial_size: 100,
        max_size: 1000,
        pre_allocate: true,
        idle_timeout: 60,
    };
    let pool = SipMessagePool::new(pool_config);

    let mut group = c.benchmark_group("message_allocation");
    group.throughput(Throughput::Elements(1));

    // Benchmark regular allocation
    group.bench_function("regular_allocation", |b| {
        b.iter(|| {
            let mut msg = SipMessage::new_from_str(black_box(&sip_invite));
            black_box(msg.parse()).unwrap();
            black_box(msg.call_id()).unwrap();
        })
    });

    // Benchmark pooled allocation
    group.bench_function("pooled_allocation", |b| {
        b.iter(|| {
            let mut pooled_msg = pool.get();
            black_box(pooled_msg.parse_from_str(black_box(&sip_invite))).unwrap();
            black_box(pooled_msg.message().call_id()).unwrap();
        })
    });

    // Benchmark global pool
    initialize_global_pool(PoolConfig::default());
    group.bench_function("global_pool", |b| {
        b.iter(|| {
            let mut pooled_msg = get_pooled_message();
            black_box(pooled_msg.parse_from_str(black_box(&sip_invite))).unwrap();
            black_box(pooled_msg.message().call_id()).unwrap();
        })
    });

    group.finish();
}

/// Benchmark high-concurrency scenarios
fn bench_concurrent_pool_usage(c: &mut Criterion) {
    let sip_messages = vec![
        r#"INVITE sip:alice@example.com SIP/2.0
From: <sip:bob@example.com>;tag=tag1
To: <sip:alice@example.com>
Call-ID: call-1
CSeq: 1 INVITE
Via: SIP/2.0/UDP 192.168.1.1:5060
Content-Length: 0

"#.replace('\n', "\r\n"),
        r#"200 OK SIP/2.0
From: <sip:bob@example.com>;tag=tag1  
To: <sip:alice@example.com>;tag=tag2
Call-ID: call-1
CSeq: 1 INVITE
Via: SIP/2.0/UDP 192.168.1.1:5060
Content-Length: 0

"#.replace('\n', "\r\n"),
        r#"BYE sip:bob@example.com SIP/2.0
From: <sip:alice@example.com>;tag=tag2
To: <sip:bob@example.com>;tag=tag1
Call-ID: call-1
CSeq: 2 BYE
Via: SIP/2.0/UDP 192.168.1.2:5060
Content-Length: 0

"#.replace('\n', "\r\n"),
    ];

    let pool_config = PoolConfig {
        initial_size: 50,
        max_size: 500,
        pre_allocate: true,
        idle_timeout: 60,
    };
    let pool = SipMessagePool::new(pool_config);

    let mut group = c.benchmark_group("concurrent_usage");
    
    for batch_size in [10, 50, 100, 500].iter() {
        group.throughput(Throughput::Elements(*batch_size));
        
        group.bench_with_input(
            BenchmarkId::new("pooled_batch", batch_size),
            batch_size,
            |b, &size| {
                b.iter(|| {
                    let mut handles = Vec::new();
                    for i in 0..size {
                        let msg_data = black_box(&sip_messages[i % sip_messages.len()]);
                        let mut pooled_msg = pool.get();
                        handles.push(pooled_msg);
                        let result = handles.last_mut().unwrap().parse_from_str(msg_data);
                        black_box(result).unwrap();
                    }
                    black_box(handles.len());
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("regular_batch", batch_size),
            batch_size,
            |b, &size| {
                b.iter(|| {
                    let mut messages = Vec::new();
                    for i in 0..size {
                        let msg_data = black_box(&sip_messages[i % sip_messages.len()]);
                        let mut msg = SipMessage::new_from_str(msg_data);
                        black_box(msg.parse()).unwrap();
                        messages.push(msg);
                    }
                    black_box(messages.len());
                })
            },
        );
    }

    group.finish();
}

/// Benchmark pool statistics overhead
fn bench_pool_stats(c: &mut Criterion) {
    let pool = SipMessagePool::new(PoolConfig::default());
    
    // Prime the pool with some activity
    for _ in 0..100 {
        let _msg = pool.get();
    }

    let mut group = c.benchmark_group("pool_operations");

    group.bench_function("get_stats", |b| {
        b.iter(|| {
            black_box(pool.stats());
        })
    });

    group.bench_function("pool_cleanup", |b| {
        b.iter(|| {
            pool.cleanup();
        })
    });

    group.bench_function("pool_size", |b| {
        b.iter(|| {
            black_box(pool.size());
        })
    });

    group.finish();
}

/// Benchmark string pool performance
fn bench_string_pool(c: &mut Criterion) {
    let string_pool = StringPool::new(1024, 100);
    let test_data = "This is a test string that we'll use for benchmarking string pool performance. It's long enough to require some allocation but not too long to skew results.";

    let mut group = c.benchmark_group("string_allocation");

    group.bench_function("regular_string", |b| {
        b.iter(|| {
            let mut s = String::with_capacity(1024);
            s.push_str(black_box(test_data));
            black_box(s.len());
        })
    });

    group.bench_function("pooled_string", |b| {
        b.iter(|| {
            let mut pooled_str = string_pool.get_buffer();
            pooled_str.as_mut().push_str(black_box(test_data));
            black_box(pooled_str.as_str().len());
        })
    });

    group.finish();
}

/// Benchmark memory allocation patterns
fn bench_allocation_patterns(c: &mut Criterion) {
    let pool_configs = [
        ("small_pool", PoolConfig { initial_size: 10, max_size: 50, pre_allocate: true, idle_timeout: 60 }),
        ("medium_pool", PoolConfig { initial_size: 100, max_size: 500, pre_allocate: true, idle_timeout: 60 }),
        ("large_pool", PoolConfig { initial_size: 1000, max_size: 5000, pre_allocate: true, idle_timeout: 60 }),
    ];

    let sip_invite = r#"INVITE sip:benchmark@test.com SIP/2.0
From: <sip:client@test.com>;tag=bench123
To: <sip:benchmark@test.com>
Call-ID: allocation-benchmark
CSeq: 1 INVITE
Via: SIP/2.0/UDP 10.0.0.1:5060
Content-Length: 0

"#.replace('\n', "\r\n");

    let mut group = c.benchmark_group("allocation_patterns");
    group.throughput(Throughput::Elements(100));

    for (name, config) in pool_configs.iter() {
        let pool = SipMessagePool::new(config.clone());
        
        group.bench_with_input(
            BenchmarkId::new("sustained_load", name),
            name,
            |b, _| {
                b.iter(|| {
                    for _ in 0..100 {
                        let mut pooled_msg = pool.get();
                        black_box(pooled_msg.parse_from_str(&sip_invite)).unwrap();
                        black_box(pooled_msg.message().call_id());
                    }
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_pool_vs_allocation,
    bench_concurrent_pool_usage,
    bench_pool_stats,
    bench_string_pool,
    bench_allocation_patterns
);
criterion_main!(benches);