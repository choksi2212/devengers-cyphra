# Installation Guide

This guide walks you through setting up the VedDB Rust client and CLI on your development machine.

## ✅ Prerequisites

- **Rust toolchain** version 1.75 or later
  - Install via `rustup`: https://rustup.rs
- **Cargo** (installed with Rust)
- **VedDB Server** running locally or accessible over the network
  - Server repository: https://github.com/cyphra-team/ved-db-server
  - Download the Windows binary (`veddb-server.exe`) from the releases page

## 📥 Installing from crates.io

Add the client to your project by updating `Cargo.toml`:

```toml
[dependencies]
veddb-client = "0.2.0"
tokio = { version = "1", features = ["full"] }
```

Then run:

```bash
cargo build
```

## 🛠️ Building from Source

Clone the repository and build the library and CLI:

```bash
git clone https://github.com/cyphra-team/ved-db-rust-client.git
cd ved-db-rust-client
cargo build --release
```

The release binaries will be located at:
```
target\release\veddb-cli.exe
```

## 🔗 Connecting to VedDB Server

You can run the VedDB server in Docker or locally:

### 🐳 Option 1: Docker (Recommended)
```bash
# Pull and run the server
docker run -d -p 50051:50051 cyphraii/veddb-server:latest
```

### 💻 Option 2: Local Binary
```bash
# Start server (from ved-db-server repository)
.\target\release\veddb-server.exe
```

### ✅ Test Connection
```bash
# Run CLI against the server (default localhost:50051)
veddb-cli.exe ping
```

See [CLI Usage](./cli.md) for detailed commands and options.

## 📦 Installing CLI Only

If you only want the CLI, download the pre-built binary:

1. Visit the [GitHub Releases](https://github.com/cyphra-team/ved-db-rust-client/releases)
2. Download the latest `veddb-cli-<version>-windows.exe`
3. Place the executable in a directory on your PATH

You can now run `veddb-cli.exe` from any terminal.

## 🔐 Environment Configuration

Optional environment variables supported by the CLI and library:

| Variable | Description | Default |
|----------|-------------|---------|
| `VEDDB_SERVER` | Address of the VedDB server | `127.0.0.1:50051` |
| `VEDDB_TIMEOUT_MS` | Request timeout in milliseconds | `30000` |
| `VEDDB_POOL_SIZE` | Number of pooled connections | `10` |

## ✅ Next Steps

- Learn how to use the client in your application: [Library Guide](./library.md)
- Explore CLI commands: [CLI Usage](./cli.md)
