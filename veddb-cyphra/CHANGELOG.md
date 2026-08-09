# Changelog

All notable changes to VedDB Rust Client (Library + CLI) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [0.0.12] - 2025-10-02

### Added
- 📚 **Comprehensive documentation** - Beautiful docs.rs page with examples
- 🎨 **Badges** - Crates.io, docs.rs, and license badges
- 📖 **Usage examples** - Connection pooling, binary data, error handling
- 🖥️ **CLI documentation** - Complete CLI usage in docs

### Changed
- Enhanced library documentation with multiple examples
- Improved API documentation structure

---

## [0.0.11] - 2025-10-02

### Added
- ✨ **LIST command** - List all keys stored in the database (both library and CLI)
- 📝 **Enhanced CLI tool** - Better error messages and user feedback
- 🔧 **Connection pooling** - Efficient connection reuse in library
- 📊 **Multiple output formats** - Table, JSON, and raw output in CLI
- ⚡ **Async/await** - Full async support with Tokio in library
- 🖥️ **Complete CLI binary** - `veddb-cli.exe` for Windows

### Changed
- 🚀 **Protocol implementation** - Updated to match server v0.1.21
- 🔄 **Little-endian encoding** - Fixed endianness throughout
- 📡 **Response parsing** - Proper 20-byte header parsing

### Fixed
- 🐛 **Status code handling** - Fixed status code interpretation (0x00=OK, 0x01=NotFound)
- 🔌 **Connection timeouts** - Better timeout handling
- 📝 **Command serialization** - Proper little-endian byte order
- ⚡ **Response deserialization** - Correct header field parsing

### Technical Details
- Command header: 24 bytes with little-endian integers
- Response header: 20 bytes with little-endian integers
- Added `Command::fetch()` for LIST operation
- Fixed `Response::from_bytes()` to use little-endian
- Updated `Command::to_bytes()` to use little-endian

### CLI Improvements
- Better table formatting with prettytable-rs
- JSON output support with `--format json`
- Raw output support with `--format raw`
- Verbose logging with `--verbose` flag
- Server address configuration with `--server`

---

## [0.0.1] - Initial Release

### Added
- Basic KV operations (SET, GET, DELETE)
- PING command
- Simple CLI interface
- Connection management
- Error handling

---

## Future Releases

### Planned for v0.1.x
- Pub/Sub support (SUBSCRIBE, UNSUBSCRIBE, PUBLISH)
- TTL operations
- Batch operations
- Transaction support
- Pattern matching for LIST command
- Better error recovery

### Planned for v1.0.x
- TLS/SSL support
- Authentication
- Compression
- Streaming responses
- Production-ready stability
- Cross-platform support (Linux, macOS)
