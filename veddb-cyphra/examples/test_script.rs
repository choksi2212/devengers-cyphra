//! Comprehensive test script for VedDB Client
//!
//! This script demonstrates all the features of the VedDB client library
//! and serves as both a test and a usage example.

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task;
use veddb_client::{Client, ClientBuilder, Result};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("🚀 VedDB Client Test Script");
    println!("==========================\n");

    // Test 1: Basic Connection
    println!("1. Testing basic connection...");
    let start = Instant::now();
    let addr = "127.0.0.1:50051".parse()?;
    let client = Client::connect(addr).await?;
    println!("   ✅ Connected in {:?}", start.elapsed());

    // Test 2: Basic Operations
    println!("\n2. Testing basic key-value operations...");
    test_basic_operations(&client).await?;

    // Test 3: Connection Pooling
    println!("\n3. Testing connection pooling...");
    test_connection_pooling().await?;

    // Test 4: Concurrent Operations
    println!("\n4. Testing concurrent operations...");
    test_concurrent_operations().await?;

    // Test 5: Error Handling
    println!("\n5. Testing error handling...");
    test_error_handling(&client).await?;

    // Test 6: Performance Benchmark
    println!("\n6. Running performance benchmark...");
    run_performance_benchmark().await?;

    println!("\n🎉 All tests completed successfully!");
    Ok(())
}

async fn test_basic_operations(client: &Client) -> Result<()> {
    // Set operation
    let key = "test_key";
    let value = "Hello, VedDB!";
    client.set(key, value.as_bytes()).await?;
    println!("   ✅ SET: '{}' = '{}'", key, value);

    // Get operation
    let retrieved = client.get(key).await?;
    let retrieved_str = String::from_utf8_lossy(&retrieved);
    assert_eq!(retrieved_str, value);
    println!("   ✅ GET: '{}' = '{}'", key, retrieved_str);

    // Delete operation
    client.delete(key).await?;
    println!("   ✅ DEL: '{}'", key);

    // Verify deletion
    match client.get(key).await {
        Ok(_) => println!("   ❌ Key should have been deleted"),
        Err(_) => println!("   ✅ Key successfully deleted"),
    }

    Ok(())
}

async fn test_connection_pooling() -> Result<()> {
    let pool_size = 5;
    let addr = "127.0.0.1:50051".parse()?;
    let client = Client::with_pool_size(addr, pool_size).await?;
    println!(
        "   ✅ Created connection pool with {} connections",
        pool_size
    );

    // Test multiple operations using the pool
    for i in 0..10 {
        let key = format!("pool_test_{}", i);
        let value = format!("value_{}", i);

        client.set(&key, value.as_bytes()).await?;
        let retrieved = client.get(&key).await?;
        assert_eq!(retrieved, value.as_bytes());
        client.delete(&key).await?;
    }
    println!("   ✅ Completed 10 operations using connection pool");

    Ok(())
}

async fn test_concurrent_operations() -> Result<()> {
    let addr = "127.0.0.1:50051".parse()?;
    let client = Arc::new(Client::with_pool_size(addr, 8).await?);
    let num_tasks = 20;
    let ops_per_task = 10;

    let mut handles = vec![];

    let start = Instant::now();

    for task_id in 0..num_tasks {
        let client = client.clone();
        let handle = task::spawn(async move {
            for i in 0..ops_per_task {
                let key = format!("concurrent_{}_{}", task_id, i);
                let value = format!("value_{}_{}", task_id, i);

                // Set
                client.set(&key, value.as_bytes()).await.unwrap();

                // Get and verify
                let retrieved = client.get(&key).await.unwrap();
                assert_eq!(retrieved, value.as_bytes());

                // Delete
                client.delete(&key).await.unwrap();
            }
        });
        handles.push(handle);
    }

    // Wait for all tasks to complete
    for handle in handles {
        handle.await.unwrap();
    }

    let duration = start.elapsed();
    let total_ops = num_tasks * ops_per_task * 3; // set + get + delete
    let ops_per_sec = total_ops as f64 / duration.as_secs_f64();

    println!("   ✅ Completed {} concurrent operations", total_ops);
    println!("   📊 Performance: {:.2} ops/sec", ops_per_sec);

    Ok(())
}

async fn test_error_handling(client: &Client) -> Result<()> {
    // Test getting a non-existent key
    match client.get("non_existent_key").await {
        Ok(_) => println!("   ❌ Expected error for non-existent key"),
        Err(e) => println!("   ✅ Correctly handled missing key: {}", e),
    }

    // Test with invalid server (should fail during connection)
    let bad_addr = "127.0.0.1:99999".parse().unwrap();
    match Client::connect(bad_addr).await {
        Ok(_) => println!("   ❌ Expected connection error"),
        Err(e) => println!("   ✅ Correctly handled connection error: {}", e),
    }

    Ok(())
}

async fn run_performance_benchmark() -> Result<()> {
    let addr = "127.0.0.1:50051".parse()?;
    let client = Client::with_pool_size(addr, 10).await?;
    let num_operations = 1000;

    println!("   📊 Running {} operations benchmark...", num_operations);

    // Benchmark SET operations
    let start = Instant::now();
    for i in 0..num_operations {
        let key = format!("bench_key_{}", i);
        let value = format!("bench_value_{}", i);
        client.set(&key, value.as_bytes()).await?;
    }
    let set_duration = start.elapsed();
    let set_ops_per_sec = num_operations as f64 / set_duration.as_secs_f64();
    println!("   📈 SET: {:.2} ops/sec", set_ops_per_sec);

    // Benchmark GET operations
    let start = Instant::now();
    for i in 0..num_operations {
        let key = format!("bench_key_{}", i);
        let _value = client.get(&key).await?;
    }
    let get_duration = start.elapsed();
    let get_ops_per_sec = num_operations as f64 / get_duration.as_secs_f64();
    println!("   📈 GET: {:.2} ops/sec", get_ops_per_sec);

    // Cleanup
    for i in 0..num_operations {
        let key = format!("bench_key_{}", i);
        client.delete(&key).await?;
    }

    println!("   ✅ Benchmark completed and cleaned up");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_client_creation() {
        let addr = "127.0.0.1:50051".parse().unwrap();
        let result = Client::connect(addr).await;
        assert!(result.is_ok(), "Should be able to create client");
    }

    #[tokio::test]
    async fn test_client_builder() {
        let addr = "127.0.0.1:50051".parse().unwrap();
        let result = ClientBuilder::new()
            .addr(addr)
            .pool_size(3)
            .connect_timeout(Duration::from_secs(5))
            .request_timeout(Duration::from_secs(10))
            .connect()
            .await;

        assert!(
            result.is_ok(),
            "Should be able to create client with builder"
        );
    }
}
