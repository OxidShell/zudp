use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use zudp::{Decode, Encode, Zudp};

// ── codec ─────────────────────────────────────────────────────────────────────

fn bench_encode_decode(c: &mut Criterion) {
    let payload: Vec<u8> = vec![0xABu8; 512];
    let mut g = c.benchmark_group("codec");
    g.throughput(Throughput::Bytes(512));

    g.bench_function("encode_512B", |b| {
        b.iter(|| criterion::black_box(payload.encode_to_bytes().unwrap()))
    });

    let encoded = payload.encode_to_bytes().unwrap();
    g.bench_function("decode_512B", |b| {
        b.iter(|| Vec::<u8>::decode_from_bytes(criterion::black_box(&encoded)).unwrap())
    });

    g.finish();
}

// ── loopback send / recv ──────────────────────────────────────────────────────

fn bench_loopback(c: &mut Criterion) {
    // Multi-thread runtime so the server task runs concurrently with block_on.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    // Server runs as a background task; receipt confirmed via sync channel.
    let (msg_tx, msg_rx) = std::sync::mpsc::sync_channel::<()>(64);
    let (addr_tx, addr_rx) = std::sync::mpsc::sync_channel::<std::net::SocketAddr>(1);

    rt.spawn(async move {
        let mut server: zudp::ZudpSocket<Vec<u8>> =
            Zudp::default().port(0).listen().await.unwrap();
        addr_tx.send(server.local_addr().unwrap()).unwrap();
        loop {
            match server.recv().await {
                Ok(_) => {
                    if msg_tx.send(()).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let server_addr = addr_rx.recv().unwrap();
    let client = rt
        .block_on(Zudp::default().port(0).connect::<Vec<u8>>(server_addr))
        .unwrap();

    let mut g = c.benchmark_group("loopback");

    let small = vec![0u8; 64];
    g.throughput(Throughput::Bytes(64));
    g.bench_function("small_64B", |b| {
        b.iter(|| {
            rt.block_on(client.send(small.clone())).unwrap();
            msg_rx.recv().unwrap();
        })
    });

    let medium = vec![0u8; 1400];
    g.throughput(Throughput::Bytes(1400));
    g.bench_function("mtu_1400B", |b| {
        b.iter(|| {
            rt.block_on(client.send(medium.clone())).unwrap();
            msg_rx.recv().unwrap();
        })
    });

    let large = vec![0u8; 8192];
    g.throughput(Throughput::Bytes(8192));
    g.bench_function("fragmented_8KiB", |b| {
        b.iter(|| {
            rt.block_on(client.send(large.clone())).unwrap();
            msg_rx.recv().unwrap();
        })
    });

    g.finish();
}

criterion_group!(benches, bench_encode_decode, bench_loopback);
criterion_main!(benches);
