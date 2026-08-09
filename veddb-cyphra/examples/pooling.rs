//! Example of using VedDB client with connection pooling

use std::sync::Arc;
use std::time::Instant;
use tokio::task;
use veddb_client::Client;

const NUM_TASKS: usize = 10;
const OPS_PER_TASK: usize = 100;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Create a client with a connection pool
    let addr = "127.0.0.1:50051".parse()?;
    let client = Client::with_pool_size(addr, 4).await?;
    let client = Arc::new(client);

    println!(
        "Starting benchmark with {} tasks and {} operations per task",
        NUM_TASKS, OPS_PER_TASK
    );

    let start = Instant::now();
    let mut handles = vec![];

    // Spawn multiple tasks to simulate concurrent clients
    for task_id in 0..NUM_TASKS {
        let client = client.clone();
        let handle = task::spawn(async move {
            for i in 0..OPS_PER_TASK {
                let key = format!("task_{}_{}", task_id, i);
                let value = format!("value_{}_{}", task_id, i);

                // Set a value
                if let Err(e) = client.set(&key, &value).await {
                    eprintln!("Task {}: Failed to set {}: {}", task_id, key, e);
                    continue;
                }

                // Get the value back
                match client.get::<_, Vec<u8>>(&key).await {
                    Ok(retrieved) => {
                        if retrieved != value.as_bytes() {
                            eprintln!("Value mismatch for {}: {:?} != {}", key, retrieved, value);
                        }
                    }
                    Err(e) => {
                        eprintln!("Task {}: Failed to get {}: {}", task_id, key, e);
                    }
                }

                // Delete the key
                if let Err(e) = client.delete(&key).await {
                    eprintln!("Task {}: Failed to delete {}: {}", task_id, key, e);
                }
            }
        });
        handles.push(handle);
    }

    // Wait for all tasks to complete
    for handle in handles {
        handle.await?;
    }

    let duration = start.elapsed();
    let total_ops = NUM_TASKS * OPS_PER_TASK * 3; // set + get + delete for each operation
    let ops_per_sec = total_ops as f64 / duration.as_secs_f64();

    println!("\nBenchmark results:");
    println!("  Total operations: {}", total_ops);
    println!("  Time taken: {:.2?}", duration);
    println!("  Operations per second: {:.2}", ops_per_sec);

    Ok(())
}
