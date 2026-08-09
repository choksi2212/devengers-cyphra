# Configuration & Tuning

This guide describes runtime configuration knobs for the VedDB Rust client and CLI, along with recommendations for tuning in production environments.

## ⚙️ ClientBuilder Options

`ClientBuilder` exposes granular controls for connection behavior:

| Method | Description | Default |
|--------|-------------|---------|
| `pool_size(usize)` | Number of pooled connections | `1` (no pooling) |
| `min_idle(usize)` | Minimum idle connections to keep alive | `pool_size` |
| `connect_timeout(Duration)` | Timeout for establishing TCP connections | `5 seconds` |
| `request_timeout(Duration)` | Timeout for individual commands | `30 seconds` |
| `max_retries(u32)` | Number of retries on transient errors | `3` |
| `retry_backoff(Duration)` | Delay between retries | `100 ms` |
| `max_frame_size(usize)` | Maximum payload size accepted | `16 MB` |
| `tcp_nodelay(bool)` | Enable/disable Nagle's algorithm | `true` |

Example:

```rust
use std::time::Duration;
use veddb_client::{ClientBuilder, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let client = ClientBuilder::new("127.0.0.1:50051")
        .pool_size(12)
        .min_idle(6)
        .connect_timeout(Duration::from_secs(2))
        .request_timeout(Duration::from_secs(8))
        .max_retries(5)
        .retry_backoff(Duration::from_millis(250))
        .build()
        .await?;

    client.ping().await?;
    Ok(())
}
```

> ℹ️ Pool resizing is dynamic: idle connections above `min_idle` are closed after 60 seconds of inactivity.

## 🧵 Concurrency Guidelines

- Use pooling (`Client::with_pool_size` or `ClientBuilder::pool_size`) when spawning many concurrent tasks.
- Each pooled connection can pipeline requests, but heavy workloads benefit from ≥ 4 connections.
- Start with pool size = CPU cores and tune based on observed latency.

## 🔐 Security Considerations

- **TLS / Authentication**: Not yet implemented. Follow the [Roadmap](../README.md#🗺️-roadmap) for progress.
- **Network Isolation**: Deploy VedDB behind internal firewalls or VPNs in production.
- **Input Validation**: Verify application data before sending to VedDB to avoid malicious payloads.

## 📊 Observability

### Logging

Enable `tracing` for structured logs:

```rust
tracing_subscriber::fmt::init();
let client = Client::connect("127.0.0.1:50051").await?;
```

Logs include connection lifecycle events, retries, and error context.

### Metrics Collection

Use the `metrics` ecosystem to instrument your application:

```rust
metrics::increment_counter!("veddb.requests", "command" => "set");
```

Pair with client logs to build dashboards in Prometheus, Grafana, or Application Insights.

## ⏱️ Timeout Strategy

- **Connect timeout**: set low (1-3 seconds) to fail fast on network issues.
- **Request timeout**: base on expected workload. For interactive apps: 2-5 seconds; for batch: 10-30 seconds.
- **Retry policy**: enable retries only for idempotent operations (GET, LIST). Avoid retries for `SET` unless your workflow can handle duplicates.

## 🧮 Memory & Payload Limits

- Default maximum frame size is 16 MB. Increase via `ClientBuilder::max_frame_size` if storing large values.
- Watch server-side memory usage when storing big payloads. Use compression at the application layer if needed.

## 🌐 Multi-Environment Setup

Use environment variables to target different servers per environment:

```powershell
# PowerShell example
$env:VEDDB_SERVER = "veddb-dev.internal:50051"
$env:VEDDB_TIMEOUT_MS = "5000"
```

In code:
```rust
let server = std::env::var("VEDDB_SERVER").unwrap_or_else(|_| "127.0.0.1:50051".into());
let client = Client::connect(server).await?;
```

## 🔄 Graceful Shutdown Tips

- Call `Client::close()` during application shutdown to flush in-flight requests.
- For pooled clients, drop clones before calling `close()` to allow draining.
- Use `tokio::signal::ctrl_c()` to listen for termination signals and close clients cleanly.

## 🧪 Staging & Load Testing

- Mirror production configuration in staging.
- Use `veddb-cli` scripting to generate load (see [CLI Guide](./cli.md)).
- Monitor latency percentiles and error rates while ramping up traffic.

---

Continue to [Troubleshooting](./troubleshooting.md) for common issues and resolutions.
