//! Example of using VedDB client with Pub/Sub

use std::time::Duration;
use tokio::time;
use veddb_client::Client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Connect to the VedDB server
    let addr = "127.0.0.1:50051".parse()?;
    let client = Client::connect(addr).await?;

    // Subscribe to a channel in a separate task
    let subscriber = client.clone();
    let subscribe_task = tokio::spawn(async move {
        let mut subscription = subscriber.subscribe("news").await.unwrap();
        println!("Subscribed to 'news' channel");

        // Listen for messages
        while let Ok(message) = subscription.recv().await {
            println!("Received: {}", String::from_utf8_lossy(&message));
        }
    });

    // Give the subscriber time to subscribe
    time::sleep(Duration::from_secs(1)).await;

    // Publish some messages
    for i in 0..5 {
        let message = format!("Breaking news #{}", i + 1);
        println!("Publishing: {}", message);
        client.publish("news", message.as_bytes()).await?;
        time::sleep(Duration::from_secs(1)).await;
    }

    // Wait a bit for all messages to be received
    time::sleep(Duration::from_secs(1)).await;

    // Unsubscribe and clean up
    client.unsubscribe("news").await?;
    subscribe_task.abort();

    Ok(())
}
