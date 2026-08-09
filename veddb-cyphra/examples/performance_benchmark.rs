//! High-Performance Benchmark for VedDB Rust Client
//! Direct comparison with JavaScript client performance

use std::time::Instant;
use veddb_client::{Client, Result};

struct BenchmarkResult {
    name: String,
    iterations: usize,
    duration_secs: f64,
    ops_per_sec: u64,
    avg_latency_ms: f64,
}

impl BenchmarkResult {
    fn new(name: String, iterations: usize, duration: std::time::Duration) -> Self {
        let duration_secs = duration.as_secs_f64();
        let ops_per_sec = (iterations as f64 / duration_secs) as u64;
        let avg_latency_ms = (duration_secs * 1000.0) / iterations as f64;
        
        Self {
            name,
            iterations,
            duration_secs,
            ops_per_sec,
            avg_latency_ms,
        }
    }
    
    fn print(&self) {
        println!("⏱️  Duration: {:.3}s", self.duration_secs);
        println!("🏃 Ops/sec: {:,}", self.ops_per_sec);
        println!("⚡ Avg Latency: {:.3}ms", self.avg_latency_ms);
    }
}

async fn benchmark_single_connection(iterations: usize) -> Result<()> {
    let client = Client::connect("127.0.0.1:50051").await?;
    
    for i in 0..iterations {
        let key = format!("single_{}", i);
        let value = format!("value_{}", i);
        client.set(&key, &value).await?;
        let _retrieved: Vec<u8> = client.get(&key).await?;
        client.delete(&key).await?;
    }
    
    Ok(())
}

async fn benchmark_connection_pool(iterations: usize, pool_size: usize) -> Result<()> {
    let client = Client::with_pool_size("127.0.0.1:50051", pool_size).await?;
    
    for i in 0..iterations {
        let key = format!("pool_{}", i);
        let value = format!("value_{}", i);
        client.set(&key, &value).await?;
        let _retrieved: Vec<u8> = client.get(&key).await?;
        client.delete(&key).await?;
    }
    
    Ok(())
}

async fn benchmark_set_only(iterations: usize) -> Result<()> {
    let client = Client::with_pool_size("127.0.0.1:50051", 20).await?;
    
    for i in 0..iterations {
        let key = format!("set_{}", i);
        let value = format!("value_{}", i);
        client.set(&key, &value).await?;
    }
    
    // Cleanup
    for i in 0..iterations {
        let key = format!("set_{}", i);
        let _ = client.delete(&key).await;
    }
    
    Ok(())
}

async fn benchmark_get_only(iterations: usize) -> Result<()> {
    let client = Client::with_pool_size("127.0.0.1:50051", 20).await?;
    
    // Pre-populate data
    for i in 0..iterations {
        let key = format!("get_{}", i);
        let value = format!("value_{}", i);
        client.set(&key, &value).await?;
    }
    
    // Benchmark gets
    for i in 0..iterations {
        let key = format!("get_{}", i);
        let _retrieved: Vec<u8> = client.get(&key).await?;
    }
    
    // Cleanup
    for i in 0..iterations {
        let key = format!("get_{}", i);
        let _ = client.delete(&key).await;
    }
    
    Ok(())
}

async fn benchmark_concurrent_operations(iterations: usize, concurrency: usize) -> Result<()> {
    let client = Client::with_pool_size("127.0.0.1:50051", concurrency).await?;
    let ops_per_worker = iterations / concurrency;
    
    let mut handles = Vec::new();
    
    for worker in 0..concurrency {
        let client = client.clone();
        let handle = tokio::spawn(async move {
            for i in 0..ops_per_worker {
                let key = format!("concurrent_{}_{}", worker, i);
                let value = format!("value_{}_{}", worker, i);
                client.set(&key, &value).await.unwrap();
                let _retrieved: Vec<u8> = client.get(&key).await.unwrap();
                client.delete(&key).await.unwrap();
            }
        });
        handles.push(handle);
    }
    
    for handle in handles {
        handle.await.unwrap();
    }
    
    Ok(())
}

async fn run_benchmark<F, Fut>(name: &str, iterations: usize, benchmark_fn: F) -> BenchmarkResult
where
    F: FnOnce(usize) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    println!("\n🚀 Running: {}", name);
    println!("📊 Iterations: {:,}", iterations);
    println!("🔥 Warming up...");
    
    // Warmup
    let _ = benchmark_fn(std::cmp::min(100, iterations / 10)).await;
    
    // Actual benchmark
    let start = Instant::now();
    benchmark_fn(iterations).await.expect("Benchmark failed");
    let duration = start.elapsed();
    
    let result = BenchmarkResult::new(name.to_string(), iterations, duration);
    result.print();
    result
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("🔥 VedDB Rust Client Performance Benchmark");
    println!("==========================================");
    println!("Rust: {}", env!("RUSTC_VERSION"));
    println!("Platform: {}", std::env::consts::OS);
    
    // Test connection first
    match Client::connect("127.0.0.1:50051").await {
        Ok(client) => {
            client.ping().await?;
            println!("✅ VedDB server connection verified");
        }
        Err(e) => {
            eprintln!("❌ Cannot connect to VedDB server: {}", e);
            eprintln!("Make sure VedDB server is running on 127.0.0.1:50051");
            std::process::exit(1);
        }
    }
    
    let mut results = Vec::new();
    
    // Run benchmarks
    results.push(run_benchmark("Single Connection (3K ops)", 1000, |n| benchmark_single_connection(n)).await);
    results.push(run_benchmark("Connection Pool 10 (5K ops)", 1000, |n| benchmark_connection_pool(n, 10)).await);
    results.push(run_benchmark("Connection Pool 20 (5K ops)", 1000, |n| benchmark_connection_pool(n, 20)).await);
    results.push(run_benchmark("Concurrent 25 workers (10K ops)", 10000, |n| benchmark_concurrent_operations(n, 25)).await);
    results.push(run_benchmark("SET Only (10K ops)", 1000, |n| benchmark_set_only(n)).await);
    results.push(run_benchmark("GET Only (10K ops)", 1000, |n| benchmark_get_only(n)).await);
    
    // Print summary
    println!("\n{}", "=".repeat(80));
    println!("📈 RUST BENCHMARK SUMMARY");
    println!("{}", "=".repeat(80));
    
    for result in &results {
        println!("{:<30} | {:>10} ops/sec | {:>8.3}ms avg", 
                 result.name, 
                 format!("{:,}", result.ops_per_sec),
                 result.avg_latency_ms);
    }
    
    println!("{}", "=".repeat(80));
    
    // Find best performers
    let best_throughput = results.iter().max_by_key(|r| r.ops_per_sec).unwrap();
    let best_latency = results.iter().min_by(|a, b| a.avg_latency_ms.partial_cmp(&b.avg_latency_ms).unwrap()).unwrap();
    
    println!("🏆 Best Throughput: {} ({:,} ops/sec)", best_throughput.name, best_throughput.ops_per_sec);
    println!("⚡ Best Latency: {} ({:.3}ms avg)", best_latency.name, best_latency.avg_latency_ms);
    
    println!("\n🎯 Rust benchmark completed successfully!");
    
    Ok(())
}
