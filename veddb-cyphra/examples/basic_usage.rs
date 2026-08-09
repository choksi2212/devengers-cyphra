//! Basic usage example for VedDB Client

use veddb_client::Client;
use veddb_client::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("Connecting to VedDB server...");
    let addr = "127.0.0.1:50051".parse()?;
    let client = Client::connect(addr).await?;

    // Basic key-value operations
    println!("\n=== Basic Key-Value Operations ===");

    // Set a value
    let key = "example_key";
    let value = "Hello, VedDB!";
    println!("Setting key '{}' to '{}'", key, value);
    client.set(key, value.as_bytes()).await?;

    // Get the value back
    let retrieved = client.get(key).await?;
    println!("Retrieved value: {}", String::from_utf8_lossy(&retrieved));

    // Delete the key
    client.delete(key).await?;
    println!("Deleted key '{}'", key);

    // Connection Pooling Example
    println!("\n=== Connection Pooling Example ===");
    let pool_addr = "127.0.0.1:50051".parse()?;
    let pool = Client::with_pool_size(pool_addr, 5).await?;

    // This will use one of the 5 connections from the pool
    pool.set("pool_key", "pool_value".as_bytes()).await?;
    let pool_value = pool.get("pool_key").await?;
    println!(
        "Retrieved from pool: {}",
        String::from_utf8_lossy(&pool_value)
    );

    // Clean up
    pool.delete("pool_key").await?;

    println!("\nExample completed successfully!");
    Ok(())
}
