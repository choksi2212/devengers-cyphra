# CLI Usage Guide

The `veddb-cli` tool provides a friendly command-line interface for interacting with VedDB servers. This guide covers installation, global options, key-value commands, output formats, scripting, and advanced workflows.

## 🚀 Launching the CLI

After building the project or downloading the binary:

```bash
# From repository root
cargo run --release --bin veddb-cli -- <command>

# Using the compiled binary
veddb-cli.exe <command>
```

To check the version:

```bash
veddb-cli.exe --version
```

## ⚙️ Global Options

| Flag | Description | Default |
|------|-------------|---------|
| `-s, --server <ADDR>` | Target VedDB server (host:port) | `127.0.0.1:50051` |
| `-f, --format <FORMAT>` | Output format (`table`, `json`, `raw`) | `table` |
| `-t, --timeout <MS>` | Request timeout in milliseconds | `30000` |
| `-v, --verbose` | Enable verbose logging | Off |
| `-h, --help` | Show global or command help | — |
| `-V, --version` | Show CLI version | — |

Example:

```bash
veddb-cli.exe --server 10.0.0.12:50051 --format json kv list
```

## 🗃️ Key-Value Commands

### `kv set`

Store a value under a key:

```bash
veddb-cli.exe kv set name "Alice"
veddb-cli.exe kv set counter 42
```

### `kv get`

Retrieve a value:

```bash
veddb-cli.exe kv get name
```

Example table output:

```
+------+-------+
| Key  | Value |
+------+-------+
| name | Alice |
+------+-------+
```

### `kv del`

Delete a key:

```bash
veddb-cli.exe kv del name
```

### `kv list`

List all keys in the database:

```bash
veddb-cli.exe kv list
```

### `kv exists`

Check if a key exists (returns exit code `0` if present):

```bash
veddb-cli.exe kv exists name
```

> ℹ️ Use `echo %ERRORLEVEL%` (Windows) to inspect the exit code in scripts.

## 📡 Health Checks

### `ping`

Verify server connectivity and latency:

```bash
veddb-cli.exe ping
```

Sample output:

```
+--------+---------+
| Status | Latency |
+--------+---------+
| pong   | 0 ms    |
+--------+---------+
```

## 🧾 Output Formats

Switch formats via `--format` or `-f`.

### Table (default)
```
veddb-cli.exe kv get user
```

### JSON
```
veddb-cli.exe -f json kv list
```

Output:
```json
{
  "keys": ["name", "email"]
}
```

### Raw
```
veddb-cli.exe -f raw kv get name
```

Outputs plain text value (`Alice`). Useful for shell pipelines.

## 🧪 Scripting Examples

### Batch Insert

```powershell
# PowerShell example
1..5 | ForEach-Object {
    veddb-cli.exe kv set "item$_" "value$_"
}
```

### Export Keys as JSON

```bash
veddb-cli.exe -f json kv list > keys.json
```

### Simple Health Check Script

```powershell
try {
    veddb-cli.exe ping | Out-Null
    Write-Host "VedDB OK"
} catch {
    Write-Error "VedDB unreachable"
}
```

## 🔒 Authentication & TLS (Future)

The CLI is designed to support authentication flags and TLS configuration in upcoming releases. Track progress in the [Roadmap](../README.md#🗺️-roadmap).

## 🛠️ Troubleshooting

- **Timeouts**: Increase `--timeout` or verify server health.
- **Connection refused**: Ensure `veddb-server.exe` is running and reachable.
- **Unicode output issues**: Use the JSON format to guarantee UTF-8 encoding.

For more tips see [Troubleshooting](./troubleshooting.md).
