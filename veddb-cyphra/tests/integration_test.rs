//! Integration tests for VedDB Client

use veddb_client::{Client, Result};

#[tokio::test]
async fn test_basic_operations() -> Result<()> {
    // Create a test client
    let addr = "127.0.0.1:50051".parse().unwrap();
    let client = Client::connect(addr).await?;

    // Test set and get
    client.set("test_key", b"test_value").await?;
    let value = client.get("test_key").await?;
    assert_eq!(value, b"test_value");

    // Test delete
    client.delete("test_key").await?;

    Ok(())
}

#[tokio::test]
async fn test_connection_pooling() -> Result<()> {
    use std::sync::Arc;
    use tokio::task;

    let addr = "127.0.0.1:50051".parse().unwrap();
    let client = Arc::new(Client::with_pool_size(addr, 5).await?);
    let mut handles = vec![];

    // Spawn multiple tasks to test connection pooling
    for i in 0..10 {
        let client = client.clone();
        let handle = task::spawn(async move {
            let key = format!("pool_test_{}", i);
            client.set(key.clone(), key.as_bytes().to_vec()).await.unwrap();
            let value = client.get(key.clone()).await.unwrap();
            assert_eq!(value, key.as_bytes());
        });
        handles.push(handle);
    }

    // Wait for all tasks to complete
    for handle in handles {
        handle.await?;
    }

    Ok(())
}
