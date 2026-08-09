//! Basic example of using the VedDB client

use veddb_client::Client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Connect to the VedDB server
    let addr = "127.0.0.1:50051".parse()?;
    let client = Client::connect(addr).await?;

    // Ping the server
    client.ping().await?;
    println!("Successfully connected to VedDB server!");

    // Set a key-value pair
    client.set("greeting", "Hello, VedDB!").await?;
    println!("Set 'greeting' to 'Hello, VedDB!'");

    // Get the value back
    let value = client.get("greeting").await?;
    println!("Got 'greeting': {}", String::from_utf8_lossy(&value));

    // Delete the key
    client.delete("greeting").await?;
    println!("Deleted 'greeting'");

    // Try to get the deleted key (will return an error)
    match client.get("greeting").await {
        Ok(value) => println!("Unexpectedly got value: {:?}", value),
        Err(e) => println!("Expected error for missing key: {}", e),
    }

    Ok(())
}
