//! Benchmarks for VedDB client

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use std::sync::Arc;
use tokio::runtime::Runtime;
use veddb_client::Client;

const NUM_KEYS: usize = 10_000;

async fn setup_client() -> Client {
    let addr = "127.0.0.1:50051".parse().unwrap();
    Client::with_pool_size(addr, 10)
        .await
        .expect("Failed to create client")
}

async fn cleanup_keys(client: &Client, prefix: &str) {
    for i in 0..NUM_KEYS {
        let _ = client.delete(format!("{}key_{}", prefix, i)).await;
    }
}

fn benchmark_set(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let client = rt.block_on(setup_client());
    rt.block_on(cleanup_keys(&client, "bench_set_"));

    let mut group = c.benchmark_group("client_set");
    group.throughput(Throughput::Elements(1));

    group.bench_function("set", |b| {
        b.iter(|| {
            rt.block_on(async {
                for i in 0..100 {
                    client
                        .set(format!("bench_set_key_{}", i), format!("value_{}", i))
                        .await
                        .unwrap();
                }
            });
        })
    });

    group.finish();
    rt.block_on(cleanup_keys(&client, "bench_set_"));
}

fn benchmark_get(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let client = rt.block_on(setup_client());

    // Setup: insert some test data
    rt.block_on(async {
        for i in 0..100 {
            client
                .set(format!("bench_get_key_{}", i), format!("value_{}", i))
                .await
                .unwrap();
        }
    });

    let mut group = c.benchmark_group("client_get");
    group.throughput(Throughput::Elements(1));

    group.bench_function("get", |b| {
        b.iter(|| {
            rt.block_on(async {
                for i in 0..100 {
                    let _: Vec<u8> = client
                        .get(format!("bench_get_key_{}", i % 100))
                        .await
                        .unwrap();
                }
            });
        })
    });

    group.finish();
    rt.block_on(cleanup_keys(&client, "bench_get_"));
}

fn benchmark_concurrent(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let client = Arc::new(rt.block_on(setup_client()));
    rt.block_on(cleanup_keys(&client, "bench_conc_"));

    let mut group = c.benchmark_group("client_concurrent");
    group.throughput(Throughput::Elements(1));

    for num_tasks in [4, 8, 16].iter() {
        group.bench_with_input(
            format!("{}_tasks", num_tasks),
            num_tasks,
            |b, &num_tasks| {
                b.iter(|| {
                    rt.block_on(async {
                        let mut handles = Vec::new();

                        for task_id in 0..*num_tasks {
                            let client = client.clone();
                            let handle = tokio::spawn(async move {
                                for i in 0..(100 / num_tasks) {
                                    let key = format!("bench_conc_task_{}_{}", task_id, i);
                                    client.set(&key, format!("value_{}", i)).await.unwrap();
                                    let _: Vec<u8> = client.get(&key).await.unwrap();
                                }
                            });
                            handles.push(handle);
                        }

                        for handle in handles {
                            handle.await.unwrap();
                        }
                    });
                })
            },
        );
    }

    group.finish();
    rt.block_on(cleanup_keys(&client, "bench_conc_"));
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(std::time::Duration::from_secs(10));
    targets = benchmark_set, benchmark_get, benchmark_concurrent
);
criterion_main!(benches);
