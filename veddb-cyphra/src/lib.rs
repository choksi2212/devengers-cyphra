//! # VedDB Rust Client v0.2.0
//!
//! [![Crates.io](https://img.shields.io/crates/v/veddb-client.svg)](https://crates.io/crates/veddb-client)
//! [![Documentation](https://docs.rs/veddb-client/badge.svg)](https://docs.rs/veddb-client)
//! [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
//!
//! **Official Rust client library for VedDB v0.2.0** - A hybrid document database with Redis-like caching.
//!
//! VedDB v0.2.0 combines MongoDB-like persistent document storage with Redis-like in-memory caching 
//! in a single unified system. This client library provides full support for both legacy v0.1.x 
//! key-value operations and new v0.2.0 document operations.
//!
//! ## 🚀 Quick Start
//!
//! Add this to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! veddb-client = "0.2.0"
//! tokio = { version = "1", features = ["full"] }
//! ```
//!
//! ### Basic Key-Value Operations (v0.1.x compatibility)
//!
//! ```no_run
//! use veddb_client::{Client, Result};
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     // Connect to VedDB server
//!     let client = Client::connect("127.0.0.1:50051").await?;
//!     
//!     // Ping the server
//!     client.ping().await?;
//!     println!("Server is alive!");
//!     
//!     // Set a key-value pair
//!     client.set("name", "Alice").await?;
//!     
//!     // Get a value
//!     let value = client.get("name").await?;
//!     println!("Value: {}", String::from_utf8_lossy(&value));
//!     
//!     Ok(())
//! }
//! ```
//!
//! ### Document Operations (v0.2.0)
//!
//! ```no_run
//! use veddb_client::{Client, Document, QueryRequest, InsertDocRequest, Value};
//! use std::collections::BTreeMap;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = Client::connect("127.0.0.1:50051").await?;
//!     
//!     // Create a document
//!     let mut doc = Document::new();
//!     doc.insert("name", "Alice");
//!     doc.insert("age", 30i32);
//!     doc.insert("active", true);
//!     
//!     // Insert document
//!     client.insert_document("users", doc).await?;
//!     
//!     // Query documents
//!     let query = QueryRequest {
//!         collection: "users".to_string(),
//!         filter: Some(Value::Object({
//!             let mut filter = BTreeMap::new();
//!             filter.insert("active".to_string(), Value::Bool(true));
//!             filter
//!         })),
//!         projection: None,
//!         sort: None,
//!         skip: None,
//!         limit: Some(10),
//!     };
//!     
//!     let documents = client.query(query).await?;
//!     println!("Found {} documents", documents.len());
//!     
//!     Ok(())
//! }
//! ```
//!
//! ### TLS Connection
//!
//! ```no_run
//! use veddb_client::{Client, TlsConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Configure TLS
//!     let tls_config = TlsConfig::new("localhost")
//!         .accept_invalid_certs(); // For testing only
//!     
//!     // Connect with TLS
//!     let client = Client::connect_with_tls("127.0.0.1:50051", tls_config).await?;
//!     
//!     client.ping().await?;
//!     println!("Secure connection established!");
//!     
//!     Ok(())
//! }
//! ```
//!
//! ### Authentication
//!
//! ```no_run
//! use veddb_client::{Client, TlsConfig, AuthConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let tls_config = TlsConfig::new("localhost");
//!     let auth_config = AuthConfig::username_password("admin", "password");
//!     
//!     let client = Client::connect_with_auth(
//!         "127.0.0.1:50051",
//!         Some(tls_config),
//!         auth_config,
//!     ).await?;
//!     
//!     client.ping().await?;
//!     println!("Authenticated connection established!");
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## ✨ Features
//!
//! ### Core Features
//! - **Async/Await** - Built on Tokio for high-performance async I/O
//! - **Connection Pooling** - Efficient connection management and reuse
//! - **Type-Safe** - Full Rust type safety and error handling
//! - **Protocol Support** - Both v0.1.x (legacy) and v0.2.0 protocols
//!
//! ### Security Features
//! - **TLS 1.3 Support** - Encrypted connections with certificate validation
//! - **Authentication** - Username/password and JWT token authentication
//! - **Mutual TLS** - Client certificate authentication support
//!
//! ### v0.2.0 Features
//! - **Document Storage** - MongoDB-like document operations with JSON support
//! - **Collections & Indexes** - Organize documents and optimize queries
//! - **Advanced Data Structures** - Redis-like lists, sets, sorted sets, hashes
//! - **Pub/Sub Messaging** - Real-time publish-subscribe communication
//! - **Hybrid Architecture** - Automatic routing between cache and persistent layers
//!
//! ## 📖 Advanced Usage
//!
//! ### Advanced Data Structures
//!
//! ```no_run
//! use veddb_client::{Client, ListOpRequest, ListOperation, Value};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = Client::connect("127.0.0.1:50051").await?;
//!     
//!     // List operations
//!     let list_req = ListOpRequest {
//!         key: "mylist".to_string(),
//!         operation: ListOperation::Push {
//!             values: vec![Value::String("item1".to_string())],
//!             left: true,
//!         },
//!     };
//!     client.list_operation(list_req).await?;
//!     
//!     Ok(())
//! }
//! ```
//!
//! ### Pub/Sub Messaging
//!
//! ```no_run
//! use veddb_client::Client;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = Client::connect("127.0.0.1:50051").await?;
//!     
//!     // Subscribe to a channel
//!     client.subscribe("events").await?;
//!     
//!     // Publish a message
//!     client.publish("events", b"Hello, World!").await?;
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## 🔌 Protocol Support
//!
//! VedDB v0.2.0 client supports both protocols:
//!
//! ### v0.1.x Protocol (Legacy)
//! - Simple key-value operations
//! - Pub/sub messaging
//! - Binary protocol over TCP
//!
//! ### v0.2.0 Protocol (New)
//! - Document operations with JSON support
//! - Authentication and authorization
//! - Advanced data structures
//! - TLS encryption
//! - Collection and index management
//!
//! ## 🔗 Related
//!
//! - **Server**: [ved-db-server](https://github.com/cyphra-team/ved-db-server) - VedDB Server v0.2.0
//! - **Repository**: [GitHub](https://github.com/cyphra-team/ved-db-rust-client)
//!
//! ## 📄 License
//!
//! This project is licensed under the MIT License - see the [LICENSE](https://github.com/cyphra-team/ved-db-rust-client/blob/main/LICENSE) file for details.

#![warn(missing_docs)]
#![warn(rustdoc::missing_crate_level_docs)]
#![forbid(unsafe_code)]

mod connection;
mod error;
mod types;

pub use connection::{Client, ClientBuilder, Connection, ConnectionPool, TlsConfig, AuthConfig};
pub use error::Error;
pub use types::{
    Command, Response, StatusCode, OpCode, Value, Document, DocumentId, ObjectId,
    AuthRequest, AuthMethod, AuthCredentials, AuthResponse,
    QueryRequest, InsertDocRequest, UpdateDocRequest, DeleteDocRequest,
    CreateCollectionRequest, CreateIndexRequest, IndexField,
    ListCollectionsRequest, DropCollectionRequest, DropIndexRequest, ListIndexesRequest,
    ListOpRequest, ListOperation, SetOpRequest, SetOperation,
    SortedSetOpRequest, SortedSetOperation, ScoredMember,
    HashOpRequest, HashOperation, OperationResponse,
    CreateUserRequest, DeleteUserRequest, UpdateUserRoleRequest, UserInfo, ServerInfo,
    PROTOCOL_V1, PROTOCOL_V2
};

/// Custom result type for VedDB operations
pub type Result<T> = std::result::Result<T, Error>;

/// Re-export of the `bytes` crate for convenience
pub use bytes;

/// Re-export of the `tracing` crate for convenience
#[cfg(feature = "tracing-subscriber")]
pub use tracing;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_error_conversion() {
        // Test that we can convert from io::Error
        let io_error = std::io::Error::new(std::io::ErrorKind::Other, "test");
        let error: Error = io_error.into();
        assert!(matches!(error, Error::Io(_)));
        
        // Test that we can convert from string
        let error: Error = "test error".into();
        assert!(matches!(error, Error::Other(_)));
    }
}
