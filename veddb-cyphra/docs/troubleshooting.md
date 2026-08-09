# Troubleshooting Guide

Having issues with the VedDB Rust client or CLI? This guide provides solutions to common problems and diagnostic steps to get you back on track quickly.

## 🛠 Common Problems

### Client Cannot Connect
- **Symptom**: `Error::Connection` or `Connection refused` messages
- **Checks**:
  - Ensure `veddb-server.exe` is running and reachable.
  - Verify the `--server` address or `VEDDB_SERVER` environment variable.
  - Confirm firewall rules allow TCP traffic on port `50051`.
  - Use `ping` command: `veddb-cli.exe ping`

### Request Timeout
- **Symptom**: `Error::Timeout` or CLI showing `Request timeout`
- **Solutions**:
  - Increase the timeout via `ClientBuilder::request_timeout` or CLI `--timeout` flag.
  - Check server CPU usage; high load can delay responses.
  - Reduce request concurrency or resize the connection pool.

### Server Error Responses
- **Symptom**: `Error::Server("NotFound")` or similar messages
- **Meaning**: The server processed the request and returned an error
- **Next steps**:
  - For missing keys, handle gracefully (`NotFound` is expected).
  - For protocol errors, ensure client and server versions are compatible.
  - Inspect server logs for additional details.

### CLI Prints Garbled Characters
- Happens when using `table` output in non-UTF terminals. Switch to `--format raw` or `--format json`.

### Pool Exhaustion
- **Symptom**: Log messages about pool exhaustion or operations hanging
- **Fixes**:
  - Increase pool size (`ClientBuilder::pool_size`).
  - Ensure connections are released by dropping `Client` clones when finished.

## 🔍 Diagnostic Commands

### Check Server Availability
```bash
veddb-cli.exe ping
```

### Inspect Keys
```bash
veddb-cli.exe kv list
```

### Enable Verbose Logging
```bash
veddb-cli.exe --verbose kv get name
```

### Build in Debug Mode with Logs
```bash
RUST_LOG=veddb_client=debug cargo run --bin veddb-cli -- kv list
```

## 🧪 Testing the Library

Run the test suite to confirm client integrity:
```bash
cargo test
```

Run specific integration tests:
```bash
cargo test --test protocol_tests
```

## 🧰 Collecting Logs

1. Enable tracing in your application (see [Configuration](./configuration.md)).
2. Capture server logs (`veddb-server.exe` prints diagnostic messages).
3. Gather CLI output with `--verbose` flag.

## 🆘 When to Ask for Help

If you've exhausted the troubleshooting steps:
- Collect logs and the command you ran.
- Note the client and server versions.
- Open an issue: https://github.com/cyphra-team/ved-db-rust-client/issues

Provide as much context as possible to speed up resolution.
