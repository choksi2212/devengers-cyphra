# Library Usage Guide

This guide explains how to use the `veddb-client` crate in your Rust applications. It covers connection patterns, data operations, error handling, and best practices for production deployments.

## 🚀 Getting Started

Add the crate to your `Cargo.toml`:

```toml
[dependencies]
veddb-client = "0.0.12"
tokio = { version = "1", features = ["full"] }
```

Import and connect:

```rust
use veddb_client::Client;

#[tokio::main]
async fn main() -> veddb_client::Result<()> {
    let client = Client::connect("127.0.0.1:50051").await?;
    client.ping().await?;
    Ok(())
}
```

## 🔌 Connection Options

| Method | Description |
|--------|-------------|
| `Client::connect(addr)` | Creates a single connection client |
| `Client::with_pool_size(addr, size)` | Creates a pooled client with `size` connections |
| `ClientBuilder` | Fine-grained configuration (timeouts, pool sizing, retries) |

### Using `ClientBuilder`

```rust
use std::time::Duration;
use veddb_client::{ClientBuilder, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let client = ClientBuilder::new("127.0.0.1:50051")
        .pool_size(16)
        .connect_timeout(Duration::from_secs(3))
        .request_timeout(Duration::from_secs(10))
        .build()
        .await?;

    client.ping().await?;
    Ok(())
}
```

## 🗃️ Data Operations

### Strings
```rust
client.set("username", "alice").await?;
let value = client.get("username").await?;
println!("{}", String::from_utf8_lossy(&value));
```

### Binary Data
```rust
let bytes = vec![0x01, 0x02, 0x03];
client.set("blob", &bytes).await?;
let retrieved = client.get("blob").await?;
assert_eq!(retrieved, bytes);
```

### Listing Keys
```rust
let keys = client.list_keys().await?;
for key in keys {
    println!("{}", key);
}
```

### Deleting Keys
```rust
client.delete("username").await?;
```

## 🔄 Connection Pooling

Use pooling for concurrent workloads:

```rust
use tokio::task;
use veddb_client::Client;

#[tokio::main]
async fn main() -> veddb_client::Result<()> {
    let client = Client::with_pool_size("127.0.0.1:50051", 8).await?;

    let handles: Vec<_> = (0..32)
        .map(|i| {
            let client = client.clone();
            task::spawn(async move {
                client.set(format!("key{}", i), format!("value{}", i)).await
            })
        })
        .collect();

    for handle in handles {
        handle.await??;
    }

    Ok(())
}
```

> ℹ️ `Client` implements `Clone` when pooling is enabled. Clones share the same connection pool.

## 🧰 Error Handling

The crate exposes a rich `Error` enum:

```rust
use veddb_client::{Client, Error};

#[tokio::main]
async fn main() {
    match Client::connect("127.0.0.1:50051").await {
        Ok(client) => {
            match client.get("missing").await {
                Ok(_) => println!("The key exists"),
                Err(Error::Server(msg)) if msg.contains("NotFound") => println!("Key not found"),
                Err(err) => eprintln!("Unexpected error: {err}"),
            }
        }
        Err(Error::Timeout) => eprintln!("Timed out connecting to server"),
        Err(err) => eprintln!("Failed to connect: {err}"),
    }
}
```

## ♻️ Graceful Shutdown

```rust
let client = Client::connect("127.0.0.1:50051").await?;
client.close().await?; // flushes and closes sockets
```

For pooled clients `close()` drains and shuts down all connections.

## 📈 Metrics & Instrumentation

Enable the `tracing` feature to emit spans:

```toml
[dependencies]
veddb-client = { version = "0.0.12", features = ["tracing"] }
```

In your application:
```rust
tracing_subscriber::fmt::init();
let client = Client::connect("127.0.0.1:50051").await?;
```

## ✅ Best Practices

- Reuse a single `Client` instance per service instead of reconnecting per request.
- Use connection pooling for concurrent workloads.
- Set explicit timeouts via `ClientBuilder` for production.
- Handle `Error::Server` separately to distinguish server-side failures.
- Log protocol-level errors to aid debugging.

## 📚 Next Steps

- CLI usage patterns: [CLI Guide](./cli.md)
- Advanced configuration: [Configuration & Tuning](./configuration.md)
- Troubleshooting tips: [Troubleshooting](./troubleshooting.md)
