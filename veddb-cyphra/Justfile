# Justfile for VedDB Client
# Run with: just <command>
# Install just: cargo install just

# Default recipe
default:
    @just --list

# Build the project
build:
    cargo build --release

# Run all tests
test:
    cargo test

# Run integration tests (requires server)
test-integration:
    cargo test --test integration_test

# Run examples
examples:
    @echo "Running basic usage example..."
    cargo run --example basic_usage
    @echo "Running test script..."
    cargo run --example test_script
    @echo "Running pooling example..."
    cargo run --example pooling

# Run benchmarks
bench:
    cargo bench

# Clean build artifacts
clean:
    cargo clean

# Check code without building
check:
    cargo check

# Format code
fmt:
    cargo fmt

# Run clippy lints
clippy:
    cargo clippy -- -D warnings

# Generate documentation
docs:
    cargo doc --open

# Full test suite (build + test + examples)
full-test: build test examples

# Development workflow
dev: fmt clippy check test
