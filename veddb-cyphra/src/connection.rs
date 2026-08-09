//! Connection handling for VedDB client with TLS support and v0.2.0 protocol

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use rustls::{ClientConfig, RootCertStore, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio_rustls::{TlsConnector, client::TlsStream};
use tracing::{debug, error, info, warn};

use crate::types::{
    Command, Response, AuthRequest, AuthMethod, AuthCredentials, AuthResponse,
    QueryRequest, InsertDocRequest, UpdateDocRequest, DeleteDocRequest,
    CreateCollectionRequest, CreateIndexRequest, ListOpRequest, SetOpRequest,
    SortedSetOpRequest, HashOpRequest, OperationResponse, Document, Value,
    ListCollectionsRequest, DropCollectionRequest, DropIndexRequest, ListIndexesRequest,
    PROTOCOL_V2
};
use crate::{Error, Result};

/// Default connection timeout
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Default request timeout
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Maximum frame size (16MB)
const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

/// TLS configuration for client connections
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Enable TLS encryption
    pub enabled: bool,
    /// Server name for SNI (Server Name Indication)
    pub server_name: Option<String>,
    /// Path to CA certificate file for server verification
    pub ca_cert_path: Option<String>,
    /// Path to client certificate file (for mutual TLS)
    pub client_cert_path: Option<String>,
    /// Path to client private key file (for mutual TLS)
    pub client_key_path: Option<String>,
    /// Accept invalid certificates (for testing only)
    pub accept_invalid_certs: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server_name: None,
            ca_cert_path: None,
            client_cert_path: None,
            client_key_path: None,
            accept_invalid_certs: false,
        }
    }
}

impl TlsConfig {
    /// Create a new TLS config with server name
    pub fn new(server_name: impl Into<String>) -> Self {
        Self {
            enabled: true,
            server_name: Some(server_name.into()),
            ..Default::default()
        }
    }

    /// Enable TLS with custom CA certificate
    pub fn with_ca_cert(mut self, ca_cert_path: impl Into<String>) -> Self {
        self.ca_cert_path = Some(ca_cert_path.into());
        self
    }

    /// Enable mutual TLS with client certificate
    pub fn with_client_cert(
        mut self,
        cert_path: impl Into<String>,
        key_path: impl Into<String>,
    ) -> Self {
        self.client_cert_path = Some(cert_path.into());
        self.client_key_path = Some(key_path.into());
        self
    }

    /// Accept invalid certificates (for testing only)
    pub fn accept_invalid_certs(mut self) -> Self {
        self.accept_invalid_certs = true;
        self
    }
}

/// Authentication configuration
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Authentication method
    pub method: AuthMethod,
    /// Username for username/password auth
    pub username: Option<String>,
    /// Password for username/password auth
    pub password: Option<String>,
    /// JWT token for token-based auth
    pub token: Option<String>,
}

impl AuthConfig {
    /// Create username/password authentication
    pub fn username_password(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            method: AuthMethod::UsernamePassword,
            username: Some(username.into()),
            password: Some(password.into()),
            token: None,
        }
    }

    /// Create JWT token authentication
    pub fn jwt_token(token: impl Into<String>) -> Self {
        Self {
            method: AuthMethod::JwtToken,
            username: None,
            password: None,
            token: Some(token.into()),
        }
    }
}

/// Connection stream type (plain TCP or TLS)
#[derive(Debug)]
enum ConnectionStream {
    Plain(TcpStream),
    Tls(TlsStream<TcpStream>),
}

impl ConnectionStream {
    async fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        match self {
            ConnectionStream::Plain(stream) => {
                stream.read_exact(buf).await?;
                Ok(())
            },
            ConnectionStream::Tls(stream) => {
                stream.read_exact(buf).await?;
                Ok(())
            },
        }
    }

    async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            ConnectionStream::Plain(stream) => stream.write_all(buf).await,
            ConnectionStream::Tls(stream) => stream.write_all(buf).await,
        }
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        match self {
            ConnectionStream::Plain(stream) => stream.flush().await,
            ConnectionStream::Tls(stream) => stream.flush().await,
        }
    }
}

/// A connection to a VedDB server
#[derive(Debug)]
pub struct Connection {
    /// The underlying stream (TCP or TLS)
    stream: Mutex<ConnectionStream>,
    /// Server address
    addr: SocketAddr,
    /// Next sequence number
    next_seq: AtomicU32,
    /// Connection timeout
    connect_timeout: Duration,
    /// Request timeout
    request_timeout: Duration,
    /// Protocol version (v0.1.x or v0.2.0)
    protocol_version: u8,
    /// Authentication token (for v0.2.0)
    auth_token: Mutex<Option<String>>,
    /// TLS configuration
    tls_config: Option<TlsConfig>,
}

impl Connection {
    /// Create a new connection to the specified address
    pub async fn connect(addr: impl Into<SocketAddr>) -> Result<Self> {
        Self::connect_with_config(addr, None, None).await
    }

    /// Create a new connection with TLS configuration
    pub async fn connect_with_tls(
        addr: impl Into<SocketAddr>,
        tls_config: TlsConfig,
    ) -> Result<Self> {
        Self::connect_with_config(addr, Some(tls_config), None).await
    }

    /// Create a new connection with TLS and authentication
    pub async fn connect_with_auth(
        addr: impl Into<SocketAddr>,
        tls_config: Option<TlsConfig>,
        auth_config: AuthConfig,
    ) -> Result<Self> {
        Self::connect_with_config(addr, tls_config, Some(auth_config)).await
    }

    /// Create a new connection with full configuration
    pub async fn connect_with_config(
        addr: impl Into<SocketAddr>,
        tls_config: Option<TlsConfig>,
        auth_config: Option<AuthConfig>,
    ) -> Result<Self> {
        let addr = addr.into();
        info!("Connecting to VedDB server at {}", addr);

        // Establish TCP connection
        let tcp_stream = timeout(DEFAULT_CONNECT_TIMEOUT, TcpStream::connect(&addr))
            .await
            .map_err(Error::Timeout)??;

        // Upgrade to TLS if configured
        let stream = if let Some(ref tls_cfg) = tls_config {
            if tls_cfg.enabled {
                let tls_connector = Self::create_tls_connector(tls_cfg)?;
                let server_name = tls_cfg.server_name.as_deref()
                    .unwrap_or("localhost");
                let server_name = ServerName::try_from(server_name)
                    .map_err(|e| Error::Connection(format!("Invalid server name: {}", e)))?;
                
                let tls_stream = tls_connector.connect(server_name, tcp_stream).await
                    .map_err(|e| Error::Connection(format!("TLS handshake failed: {}", e)))?;
                
                info!("TLS connection established to {}", addr);
                ConnectionStream::Tls(tls_stream)
            } else {
                ConnectionStream::Plain(tcp_stream)
            }
        } else {
            ConnectionStream::Plain(tcp_stream)
        };

        let mut connection = Self {
            stream: Mutex::new(stream),
            addr,
            next_seq: AtomicU32::new(1),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            protocol_version: PROTOCOL_V2, // Default to v0.2.0
            auth_token: Mutex::new(None),
            tls_config,
        };

        // Authenticate if configured
        if let Some(auth_cfg) = auth_config {
            connection.authenticate(auth_cfg).await?;
        }

        info!("Connected to VedDB server at {}", addr);
        Ok(connection)
    }

    /// Create TLS connector from configuration
    fn create_tls_connector(tls_config: &TlsConfig) -> Result<TlsConnector> {
        // Configure client certificates if provided
        if let (Some(cert_path), Some(key_path)) = (&tls_config.client_cert_path, &tls_config.client_key_path) {
            // Load client certificate and key
            // This would require additional implementation for loading PEM files
            warn!("Client certificate authentication not yet implemented");
        }

        let config = if tls_config.accept_invalid_certs {
            warn!("Accepting invalid certificates - this should only be used for testing!");
            ClientConfig::builder()
                .with_safe_defaults()
                .with_custom_certificate_verifier(Arc::new(AcceptAllVerifier))
                .with_no_client_auth()
        } else {
            // Use system root certificates
            let mut root_store = RootCertStore::empty();
            // In a real implementation, we would load system root certificates here
            ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        Ok(TlsConnector::from(Arc::new(config)))
    }

    /// Authenticate with the server
    pub async fn authenticate(&mut self, auth_config: AuthConfig) -> Result<()> {
        let credentials = match auth_config.method {
            AuthMethod::UsernamePassword => {
                let username = auth_config.username
                    .ok_or_else(|| Error::InvalidArgument("Username required".to_string()))?;
                let password = auth_config.password
                    .ok_or_else(|| Error::InvalidArgument("Password required".to_string()))?;
                AuthCredentials::UsernamePassword { username, password }
            }
            AuthMethod::JwtToken => {
                let token = auth_config.token
                    .ok_or_else(|| Error::InvalidArgument("JWT token required".to_string()))?;
                AuthCredentials::JwtToken { token }
            }
        };

        let auth_request = AuthRequest {
            method: auth_config.method,
            credentials,
        };

        let seq = self.next_seq();
        let payload = serde_json::to_vec(&auth_request)
            .map_err(|e| Error::Serialization(format!("Failed to serialize auth request: {}", e)))?;
        
        let cmd = Command::new(
            crate::types::CommandHeader::new(crate::types::OpCode::Auth, seq),
            Bytes::new(),
            Bytes::from(payload),
        );

        let response = self.execute(cmd).await?;
        
        if !response.is_ok() {
            return Err(Error::AuthenticationFailed);
        }

        // Parse authentication response
        let auth_response: AuthResponse = serde_json::from_slice(&response.payload)
            .map_err(|e| Error::Serialization(format!("Failed to parse auth response: {}", e)))?;

        if !auth_response.success {
            let error_msg = auth_response.error.unwrap_or_else(|| "Authentication failed".to_string());
            return Err(Error::Server(error_msg));
        }

        // Store authentication token
        if let Some(token) = auth_response.token {
            *self.auth_token.lock().await = Some(token);
        }

        info!("Authentication successful");
        Ok(())
    }

    /// Get the next sequence number
    fn next_seq(&self) -> u32 {
        self.next_seq.fetch_add(1, Ordering::SeqCst)
    }

    /// Set protocol version (for compatibility with v0.1.x servers)
    pub fn set_protocol_version(&mut self, version: u8) {
        self.protocol_version = version;
    }

    /// Execute a command and return the response
    pub async fn execute(&self, mut cmd: Command) -> Result<Response> {
        // Set protocol version on command header
        cmd.header.version = self.protocol_version;
        
        let seq = cmd.header.seq;
        debug!("Executing command: {:?} (seq={}, protocol={})", 
               cmd.header.opcode, seq, cmd.header.version);

        let mut stream = self.stream.lock().await;

        // Send the command
        let cmd_bytes = cmd.to_bytes();
        debug!("Sending command: {} bytes", cmd_bytes.len());

        timeout(self.request_timeout, stream.write_all(&cmd_bytes))
            .await
            .map_err(Error::Timeout)??;
        
        timeout(self.request_timeout, stream.flush())
            .await
            .map_err(Error::Timeout)??;

        // Read the response header (16 bytes for v0.2.0, 20 bytes for v0.1.x)
        let header_size = if self.protocol_version == PROTOCOL_V2 { 16 } else { 20 };
        let mut header_buf = vec![0u8; header_size];
        timeout(self.request_timeout, stream.read_exact(&mut header_buf))
            .await
            .map_err(Error::Timeout)??;

        // Parse the header based on protocol version
        let payload_len = if self.protocol_version == PROTOCOL_V2 {
            // v0.2.0 format: 16-byte header
            u32::from_le_bytes([header_buf[8], header_buf[9], header_buf[10], header_buf[11]])
        } else {
            // v0.1.x format: 20-byte header
            u32::from_le_bytes([header_buf[8], header_buf[9], header_buf[10], header_buf[11]])
        };

        if payload_len as usize > MAX_FRAME_SIZE {
            return Err(Error::Protocol(format!(
                "Response too large: {} bytes (max: {})",
                payload_len, MAX_FRAME_SIZE
            )));
        }

        // Read the payload
        let mut payload = vec![0u8; payload_len as usize];
        if payload_len > 0 {
            timeout(self.request_timeout, stream.read_exact(&mut payload))
                .await
                .map_err(Error::Timeout)??;
        }

        // Combine header and payload for parsing
        let mut response_bytes = Vec::with_capacity(header_size + payload_len as usize);
        response_bytes.extend_from_slice(&header_buf);
        response_bytes.extend_from_slice(&payload);

        let response = Response::from_bytes(&response_bytes)
            .map_err(|e| Error::Protocol(format!("Invalid response: {}", e)))?;

        // Verify sequence number
        if response.header.seq != seq {
            return Err(Error::Protocol(format!(
                "Sequence number mismatch: expected {}, got {}",
                seq, response.header.seq
            )));
        }

        // Check for server errors
        if !response.is_ok() {
            let status = response.status();
            let error_msg = String::from_utf8_lossy(&response.payload).into_owned();
            return Err(Error::Server(format!(
                "Server error: {:?}: {}",
                status, error_msg
            )));
        }

        Ok(response)
    }

    /// Ping the server
    pub async fn ping(&self) -> Result<()> {
        let seq = self.next_seq();
        let cmd = Command::ping(seq);
        self.execute(cmd).await?;
        Ok(())
    }

    /// Set a key-value pair
    pub async fn set<K, V>(&self, key: K, value: V) -> Result<()>
    where
        K: Into<Bytes>,
        V: Into<Bytes>,
    {
        let seq = self.next_seq();
        let cmd = Command::set(seq, key, value);
        self.execute(cmd).await?;
        Ok(())
    }

    /// Get a value by key
    pub async fn get<K>(&self, key: K) -> Result<Bytes>
    where
        K: Into<Bytes>,
    {
        let seq = self.next_seq();
        let cmd = Command::get(seq, key);
        let response = self.execute(cmd).await?;
        Ok(response.payload)
    }

    /// Delete a key
    pub async fn delete<K>(&self, key: K) -> Result<()>
    where
        K: Into<Bytes>,
    {
        let seq = self.next_seq();
        let cmd = Command::delete(seq, key);
        self.execute(cmd).await?;
        Ok(())
    }

    /// Compare and swap a value
    pub async fn cas<K, V>(&self, key: K, expected_version: u64, value: V) -> Result<()>
    where
        K: Into<Bytes>,
        V: Into<Bytes>,
    {
        let seq = self.next_seq();
        let cmd = Command::cas(seq, key, expected_version, value);
        self.execute(cmd).await?;
        Ok(())
    }

    // ============================================================================
    // v0.2.0 Document Operations
    // ============================================================================

    /// Query documents in a collection
    pub async fn query(&self, request: QueryRequest) -> Result<Vec<Document>> {
        let seq = self.next_seq();
        let payload = serde_json::to_vec(&request)
            .map_err(|e| Error::Serialization(format!("Failed to serialize query: {}", e)))?;
        
        let cmd = Command::new(
            crate::types::CommandHeader::new(crate::types::OpCode::Query, seq),
            Bytes::new(),
            Bytes::from(payload),
        );

        let response = self.execute(cmd).await?;
        let op_response: OperationResponse = serde_json::from_slice(&response.payload)
            .map_err(|e| Error::Serialization(format!("Failed to parse query response: {}", e)))?;

        if !op_response.success {
            let error_msg = op_response.error.unwrap_or_else(|| "Query failed".to_string());
            return Err(Error::Server(error_msg));
        }

        // Parse documents from response data
        match op_response.data {
            Some(Value::Array(docs)) => {
                let mut documents = Vec::new();
                for doc_value in docs {
                    if let Value::Object(obj) = doc_value {
                        // Convert object to Document
                        let doc_json = serde_json::to_value(obj)
                            .map_err(|e| Error::Serialization(format!("Failed to convert document: {}", e)))?;
                        let document: Document = serde_json::from_value(doc_json)
                            .map_err(|e| Error::Serialization(format!("Failed to parse document: {}", e)))?;
                        documents.push(document);
                    }
                }
                Ok(documents)
            }
            _ => Ok(Vec::new()),
        }
    }

    /// Insert a document into a collection
    pub async fn insert_document(&self, collection: &str, document: Document) -> Result<()> {
        let request = InsertDocRequest {
            collection: collection.to_string(),
            document,
        };

        let seq = self.next_seq();
        let payload = serde_json::to_vec(&request)
            .map_err(|e| Error::Serialization(format!("Failed to serialize insert request: {}", e)))?;
        
        let cmd = Command::new(
            crate::types::CommandHeader::new(crate::types::OpCode::InsertDoc, seq),
            Bytes::new(),
            Bytes::from(payload),
        );

        let response = self.execute(cmd).await?;
        let op_response: OperationResponse = serde_json::from_slice(&response.payload)
            .map_err(|e| Error::Serialization(format!("Failed to parse insert response: {}", e)))?;

        if !op_response.success {
            let error_msg = op_response.error.unwrap_or_else(|| "Insert failed".to_string());
            return Err(Error::Server(error_msg));
        }

        Ok(())
    }

    /// Update documents in a collection
    pub async fn update_document(&self, request: UpdateDocRequest) -> Result<u64> {
        let seq = self.next_seq();
        let payload = serde_json::to_vec(&request)
            .map_err(|e| Error::Serialization(format!("Failed to serialize update request: {}", e)))?;
        
        let cmd = Command::new(
            crate::types::CommandHeader::new(crate::types::OpCode::UpdateDoc, seq),
            Bytes::new(),
            Bytes::from(payload),
        );

        let response = self.execute(cmd).await?;
        let op_response: OperationResponse = serde_json::from_slice(&response.payload)
            .map_err(|e| Error::Serialization(format!("Failed to parse update response: {}", e)))?;

        if !op_response.success {
            let error_msg = op_response.error.unwrap_or_else(|| "Update failed".to_string());
            return Err(Error::Server(error_msg));
        }

        Ok(op_response.affected_count.unwrap_or(0))
    }

    /// Delete documents from a collection
    pub async fn delete_document(&self, request: DeleteDocRequest) -> Result<u64> {
        let seq = self.next_seq();
        let payload = serde_json::to_vec(&request)
            .map_err(|e| Error::Serialization(format!("Failed to serialize delete request: {}", e)))?;
        
        let cmd = Command::new(
            crate::types::CommandHeader::new(crate::types::OpCode::DeleteDoc, seq),
            Bytes::new(),
            Bytes::from(payload),
        );

        let response = self.execute(cmd).await?;
        let op_response: OperationResponse = serde_json::from_slice(&response.payload)
            .map_err(|e| Error::Serialization(format!("Failed to parse delete response: {}", e)))?;

        if !op_response.success {
            let error_msg = op_response.error.unwrap_or_else(|| "Delete failed".to_string());
            return Err(Error::Server(error_msg));
        }

        Ok(op_response.affected_count.unwrap_or(0))
    }

    /// Create a collection
    pub async fn create_collection(&self, request: CreateCollectionRequest) -> Result<()> {
        let seq = self.next_seq();
        let payload = serde_json::to_vec(&request)
            .map_err(|e| Error::Serialization(format!("Failed to serialize create collection request: {}", e)))?;
        
        let cmd = Command::new(
            crate::types::CommandHeader::new(crate::types::OpCode::CreateCollection, seq),
            Bytes::new(),
            Bytes::from(payload),
        );

        let response = self.execute(cmd).await?;
        let op_response: OperationResponse = serde_json::from_slice(&response.payload)
            .map_err(|e| Error::Serialization(format!("Failed to parse create collection response: {}", e)))?;

        if !op_response.success {
            let error_msg = op_response.error.unwrap_or_else(|| "Create collection failed".to_string());
            return Err(Error::Server(error_msg));
        }

        Ok(())
    }

    /// List collections
    pub async fn list_collections(&self, request: ListCollectionsRequest) -> Result<Vec<String>> {
        let seq = self.next_seq();
        let payload = serde_json::to_vec(&request)
            .map_err(|e| Error::Serialization(format!("Failed to serialize list collections request: {}", e)))?;
        
        let cmd = Command::new(
            crate::types::CommandHeader::new(crate::types::OpCode::ListCollections, seq),
            Bytes::new(),
            Bytes::from(payload),
        );

        let response = self.execute(cmd).await?;
        let op_response: OperationResponse = serde_json::from_slice(&response.payload)
            .map_err(|e| Error::Serialization(format!("Failed to parse list collections response: {}", e)))?;

        if !op_response.success {
            let error_msg = op_response.error.unwrap_or_else(|| "List collections failed".to_string());
            return Err(Error::Server(error_msg));
        }

        // Parse collections from response data
        match op_response.data {
            Some(Value::Array(cols)) => {
                let mut collections = Vec::new();
                for col_value in cols {
                    if let Value::String(name) = col_value {
                        collections.push(name);
                    }
                }
                Ok(collections)
            }
            _ => Ok(Vec::new()),
        }
    }

    /// Drop a collection
    pub async fn drop_collection(&self, request: DropCollectionRequest) -> Result<()> {
        let seq = self.next_seq();
        let payload = serde_json::to_vec(&request)
            .map_err(|e| Error::Serialization(format!("Failed to serialize drop collection request: {}", e)))?;
        
        let cmd = Command::new(
            crate::types::CommandHeader::new(crate::types::OpCode::DropCollection, seq),
            Bytes::new(),
            Bytes::from(payload),
        );

        let response = self.execute(cmd).await?;
        let op_response: OperationResponse = serde_json::from_slice(&response.payload)
            .map_err(|e| Error::Serialization(format!("Failed to parse drop collection response: {}", e)))?;

        if !op_response.success {
            let error_msg = op_response.error.unwrap_or_else(|| "Drop collection failed".to_string());
            return Err(Error::Server(error_msg));
        }

        Ok(())
    }

    /// Create an index
    pub async fn create_index(&self, request: CreateIndexRequest) -> Result<()> {
        let seq = self.next_seq();
        let payload = serde_json::to_vec(&request)
            .map_err(|e| Error::Serialization(format!("Failed to serialize create index request: {}", e)))?;
        
        let cmd = Command::new(
            crate::types::CommandHeader::new(crate::types::OpCode::CreateIndex, seq),
            Bytes::new(),
            Bytes::from(payload),
        );

        let response = self.execute(cmd).await?;
        let op_response: OperationResponse = serde_json::from_slice(&response.payload)
            .map_err(|e| Error::Serialization(format!("Failed to parse create index response: {}", e)))?;

        if !op_response.success {
            let error_msg = op_response.error.unwrap_or_else(|| "Create index failed".to_string());
            return Err(Error::Server(error_msg));
        }

        Ok(())
    }

    /// List indexes
    pub async fn list_indexes(&self, request: ListIndexesRequest) -> Result<Vec<Value>> {
        let seq = self.next_seq();
        let payload = serde_json::to_vec(&request)
            .map_err(|e| Error::Serialization(format!("Failed to serialize list indexes request: {}", e)))?;
        
        let cmd = Command::new(
            crate::types::CommandHeader::new(crate::types::OpCode::ListIndexes, seq),
            Bytes::new(),
            Bytes::from(payload),
        );

        let response = self.execute(cmd).await?;
        let op_response: OperationResponse = serde_json::from_slice(&response.payload)
            .map_err(|e| Error::Serialization(format!("Failed to parse list indexes response: {}", e)))?;

        if !op_response.success {
            let error_msg = op_response.error.unwrap_or_else(|| "List indexes failed".to_string());
            return Err(Error::Server(error_msg));
        }

        match op_response.data {
            Some(Value::Array(indexes)) => Ok(indexes),
            _ => Ok(Vec::new()),
        }
    }

    /// Drop an index
    pub async fn drop_index(&self, request: DropIndexRequest) -> Result<()> {
        let seq = self.next_seq();
        let payload = serde_json::to_vec(&request)
            .map_err(|e| Error::Serialization(format!("Failed to serialize drop index request: {}", e)))?;
        
        let cmd = Command::new(
            crate::types::CommandHeader::new(crate::types::OpCode::DropIndex, seq),
            Bytes::new(),
            Bytes::from(payload),
        );

        let response = self.execute(cmd).await?;
        let op_response: OperationResponse = serde_json::from_slice(&response.payload)
            .map_err(|e| Error::Serialization(format!("Failed to parse drop index response: {}", e)))?;

        if !op_response.success {
            let error_msg = op_response.error.unwrap_or_else(|| "Drop index failed".to_string());
            return Err(Error::Server(error_msg));
        }

        Ok(())
    }

    // ============================================================================
    // v0.2.0 Advanced Data Structure Operations
    // ============================================================================

    /// Execute a list operation
    pub async fn list_operation(&self, request: ListOpRequest) -> Result<Value> {
        let seq = self.next_seq();
        let payload = serde_json::to_vec(&request)
            .map_err(|e| Error::Serialization(format!("Failed to serialize list operation: {}", e)))?;
        
        let opcode = match &request.operation {
            crate::types::ListOperation::Push { left: true, .. } => crate::types::OpCode::LPush,
            crate::types::ListOperation::Push { left: false, .. } => crate::types::OpCode::RPush,
            crate::types::ListOperation::Pop { left: true } => crate::types::OpCode::LPop,
            crate::types::ListOperation::Pop { left: false } => crate::types::OpCode::RPop,
            crate::types::ListOperation::Range { .. } => crate::types::OpCode::LRange,
            crate::types::ListOperation::Len => crate::types::OpCode::LLen,
        };

        let cmd = Command::new(
            crate::types::CommandHeader::new(opcode, seq),
            Bytes::new(),
            Bytes::from(payload),
        );

        let response = self.execute(cmd).await?;
        let op_response: OperationResponse = serde_json::from_slice(&response.payload)
            .map_err(|e| Error::Serialization(format!("Failed to parse list operation response: {}", e)))?;

        if !op_response.success {
            let error_msg = op_response.error.unwrap_or_else(|| "List operation failed".to_string());
            return Err(Error::Server(error_msg));
        }

        Ok(op_response.data.unwrap_or(Value::Null))
    }

    /// Execute a set operation
    pub async fn set_operation(&self, request: SetOpRequest) -> Result<Value> {
        let seq = self.next_seq();
        let payload = serde_json::to_vec(&request)
            .map_err(|e| Error::Serialization(format!("Failed to serialize set operation: {}", e)))?;
        
        let opcode = match &request.operation {
            crate::types::SetOperation::Add { .. } => crate::types::OpCode::SAdd,
            crate::types::SetOperation::Remove { .. } => crate::types::OpCode::SRem,
            crate::types::SetOperation::Members => crate::types::OpCode::SMembers,
            crate::types::SetOperation::IsMember { .. } => crate::types::OpCode::SIsMember,
            crate::types::SetOperation::Card => crate::types::OpCode::SCard,
            crate::types::SetOperation::Union { .. } => crate::types::OpCode::SUnion,
            crate::types::SetOperation::Inter { .. } => crate::types::OpCode::SInter,
            crate::types::SetOperation::Diff { .. } => crate::types::OpCode::SDiff,
        };

        let cmd = Command::new(
            crate::types::CommandHeader::new(opcode, seq),
            Bytes::new(),
            Bytes::from(payload),
        );

        let response = self.execute(cmd).await?;
        let op_response: OperationResponse = serde_json::from_slice(&response.payload)
            .map_err(|e| Error::Serialization(format!("Failed to parse set operation response: {}", e)))?;

        if !op_response.success {
            let error_msg = op_response.error.unwrap_or_else(|| "Set operation failed".to_string());
            return Err(Error::Server(error_msg));
        }

        Ok(op_response.data.unwrap_or(Value::Null))
    }

    /// Execute a sorted set operation
    pub async fn sorted_set_operation(&self, request: SortedSetOpRequest) -> Result<Value> {
        let seq = self.next_seq();
        let payload = serde_json::to_vec(&request)
            .map_err(|e| Error::Serialization(format!("Failed to serialize sorted set operation: {}", e)))?;
        
        let opcode = match &request.operation {
            crate::types::SortedSetOperation::Add { .. } => crate::types::OpCode::ZAdd,
            crate::types::SortedSetOperation::Remove { .. } => crate::types::OpCode::ZRem,
            crate::types::SortedSetOperation::Range { .. } => crate::types::OpCode::ZRange,
            crate::types::SortedSetOperation::RangeByScore { .. } => crate::types::OpCode::ZRangeByScore,
            crate::types::SortedSetOperation::Card => crate::types::OpCode::ZCard,
            crate::types::SortedSetOperation::Score { .. } => crate::types::OpCode::ZScore,
        };

        let cmd = Command::new(
            crate::types::CommandHeader::new(opcode, seq),
            Bytes::new(),
            Bytes::from(payload),
        );

        let response = self.execute(cmd).await?;
        let op_response: OperationResponse = serde_json::from_slice(&response.payload)
            .map_err(|e| Error::Serialization(format!("Failed to parse sorted set operation response: {}", e)))?;

        if !op_response.success {
            let error_msg = op_response.error.unwrap_or_else(|| "Sorted set operation failed".to_string());
            return Err(Error::Server(error_msg));
        }

        Ok(op_response.data.unwrap_or(Value::Null))
    }

    /// Execute a hash operation
    pub async fn hash_operation(&self, request: HashOpRequest) -> Result<Value> {
        let seq = self.next_seq();
        let payload = serde_json::to_vec(&request)
            .map_err(|e| Error::Serialization(format!("Failed to serialize hash operation: {}", e)))?;
        
        let opcode = match &request.operation {
            crate::types::HashOperation::Set { .. } => crate::types::OpCode::HSet,
            crate::types::HashOperation::Get { .. } => crate::types::OpCode::HGet,
            crate::types::HashOperation::Del { .. } => crate::types::OpCode::HDel,
            crate::types::HashOperation::GetAll => crate::types::OpCode::HGetAll,
            crate::types::HashOperation::Keys => crate::types::OpCode::HKeys,
            crate::types::HashOperation::Vals => crate::types::OpCode::HVals,
            crate::types::HashOperation::Len => crate::types::OpCode::HLen,
        };

        let cmd = Command::new(
            crate::types::CommandHeader::new(opcode, seq),
            Bytes::new(),
            Bytes::from(payload),
        );

        let response = self.execute(cmd).await?;
        let op_response: OperationResponse = serde_json::from_slice(&response.payload)
            .map_err(|e| Error::Serialization(format!("Failed to parse hash operation response: {}", e)))?;

        if !op_response.success {
            let error_msg = op_response.error.unwrap_or_else(|| "Hash operation failed".to_string());
            return Err(Error::Server(error_msg));
        }

        Ok(op_response.data.unwrap_or(Value::Null))
    }

    // ============================================================================
    // Pub/Sub Operations
    // ============================================================================

    /// Subscribe to a channel
    pub async fn subscribe(&self, channel: &str) -> Result<()> {
        let seq = self.next_seq();
        let cmd = Command::new(
            crate::types::CommandHeader::new(crate::types::OpCode::Subscribe, seq),
            Bytes::from(channel.as_bytes().to_vec()),
            Bytes::new(),
        );

        self.execute(cmd).await?;
        Ok(())
    }

    /// Unsubscribe from a channel
    pub async fn unsubscribe(&self, channel: &str) -> Result<()> {
        let seq = self.next_seq();
        let cmd = Command::new(
            crate::types::CommandHeader::new(crate::types::OpCode::Unsubscribe, seq),
            Bytes::from(channel.as_bytes().to_vec()),
            Bytes::new(),
        );

        self.execute(cmd).await?;
        Ok(())
    }

    /// Publish a message to a channel
    pub async fn publish(&self, channel: &str, message: &[u8]) -> Result<()> {
        let seq = self.next_seq();
        let cmd = Command::new(
            crate::types::CommandHeader::new(crate::types::OpCode::Publish, seq),
            Bytes::from(channel.as_bytes().to_vec()),
            Bytes::from(message.to_vec()),
        );

        self.execute(cmd).await?;
        Ok(())
    }
}

/// A client for interacting with a VedDB server
#[derive(Clone, Debug)]
pub struct Client {
    /// The connection pool
    pool: ConnectionPool,
    /// TLS configuration
    tls_config: Option<TlsConfig>,
    /// Authentication configuration
    auth_config: Option<AuthConfig>,
}

impl Client {
    /// Create a new client connected to the specified address
    pub async fn connect(addr: impl Into<SocketAddr>) -> Result<Self> {
        let pool = ConnectionPool::new(addr, 1, None, None).await?;
        Ok(Self { 
            pool,
            tls_config: None,
            auth_config: None,
        })
    }

    /// Create a new client with a connection pool of the specified size
    pub async fn with_pool_size(addr: impl Into<SocketAddr>, pool_size: usize) -> Result<Self> {
        let pool = ConnectionPool::new(addr, pool_size, None, None).await?;
        Ok(Self { 
            pool,
            tls_config: None,
            auth_config: None,
        })
    }

    /// Create a new client with TLS configuration
    pub async fn connect_with_tls(
        addr: impl Into<SocketAddr>,
        tls_config: TlsConfig,
    ) -> Result<Self> {
        let pool = ConnectionPool::new(addr, 1, Some(tls_config.clone()), None).await?;
        Ok(Self { 
            pool,
            tls_config: Some(tls_config),
            auth_config: None,
        })
    }

    /// Create a new client with TLS and authentication
    pub async fn connect_with_auth(
        addr: impl Into<SocketAddr>,
        tls_config: Option<TlsConfig>,
        auth_config: AuthConfig,
    ) -> Result<Self> {
        let pool = ConnectionPool::new(addr, 1, tls_config.clone(), Some(auth_config.clone())).await?;
        Ok(Self { 
            pool,
            tls_config,
            auth_config: Some(auth_config),
        })
    }

    /// Ping the server
    pub async fn ping(&self) -> Result<()> {
        self.pool.get().await?.ping().await
    }

    /// Set a key-value pair
    pub async fn set<K, V>(&self, key: K, value: V) -> Result<()>
    where
        K: Into<Bytes>,
        V: Into<Bytes>,
    {
        self.pool.get().await?.set(key, value).await
    }

    /// Get a value by key
    pub async fn get<K>(&self, key: K) -> Result<Bytes>
    where
        K: Into<Bytes>,
    {
        self.pool.get().await?.get(key).await
    }

    /// Delete a key
    pub async fn delete<K>(&self, key: K) -> Result<()>
    where
        K: Into<Bytes>,
    {
        self.pool.get().await?.delete(key).await
    }

    /// Compare and swap a value
    pub async fn cas<K, V>(&self, key: K, expected_version: u64, value: V) -> Result<()>
    where
        K: Into<Bytes>,
        V: Into<Bytes>,
    {
        self.pool
            .get()
            .await?
            .cas(key, expected_version, value)
            .await
    }

    /// List all keys (uses Fetch opcode 0x09)
    pub async fn list_keys(&self) -> Result<Vec<String>> {
        let conn = self.pool.get().await?;
        let cmd = Command::fetch(conn.next_seq(), Bytes::new());
        let response = conn.execute(cmd).await?;
        
        if !response.is_ok() {
            return Err(Error::Protocol(format!("List keys failed: {:?}", response.status())));
        }
        
        // Parse newline-separated keys
        let keys_str = String::from_utf8_lossy(&response.payload);
        let keys: Vec<String> = keys_str
            .lines()
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        
        Ok(keys)
    }

    // ============================================================================
    // v0.2.0 Document Operations
    // ============================================================================

    /// Query documents in a collection
    pub async fn query(&self, request: QueryRequest) -> Result<Vec<Document>> {
        self.pool.get().await?.query(request).await
    }

    /// Insert a document into a collection
    pub async fn insert_document(&self, collection: &str, document: Document) -> Result<()> {
        self.pool.get().await?.insert_document(collection, document).await
    }

    /// Update documents in a collection
    pub async fn update_document(&self, request: UpdateDocRequest) -> Result<u64> {
        self.pool.get().await?.update_document(request).await
    }

    /// Delete documents from a collection
    pub async fn delete_document(&self, request: DeleteDocRequest) -> Result<u64> {
        self.pool.get().await?.delete_document(request).await
    }

    /// Create a collection
    pub async fn create_collection(&self, request: CreateCollectionRequest) -> Result<()> {
        self.pool.get().await?.create_collection(request).await
    }

    /// List collections
    pub async fn list_collections(&self) -> Result<Vec<String>> {
        let request = ListCollectionsRequest { filter: None };
        self.pool.get().await?.list_collections(request).await
    }

    /// Drop a collection
    pub async fn drop_collection(&self, name: impl Into<String>) -> Result<()> {
        let request = DropCollectionRequest { name: name.into() };
        self.pool.get().await?.drop_collection(request).await
    }

    /// Create an index
    pub async fn create_index(&self, request: CreateIndexRequest) -> Result<()> {
        self.pool.get().await?.create_index(request).await
    }

    /// List indexes
    pub async fn list_indexes(&self, collection: impl Into<String>) -> Result<Vec<Value>> {
        let request = ListIndexesRequest { collection: collection.into() };
        self.pool.get().await?.list_indexes(request).await
    }

    /// Drop an index
    pub async fn drop_index(&self, collection: impl Into<String>, name: impl Into<String>) -> Result<()> {
        let request = DropIndexRequest { 
            collection: collection.into(),
            name: name.into() 
        };
        self.pool.get().await?.drop_index(request).await
    }

    // ============================================================================
    // v0.2.0 Advanced Data Structure Operations
    // ============================================================================

    /// Execute a list operation
    pub async fn list_operation(&self, request: ListOpRequest) -> Result<Value> {
        self.pool.get().await?.list_operation(request).await
    }

    /// Execute a set operation
    pub async fn set_operation(&self, request: SetOpRequest) -> Result<Value> {
        self.pool.get().await?.set_operation(request).await
    }

    /// Execute a sorted set operation
    pub async fn sorted_set_operation(&self, request: SortedSetOpRequest) -> Result<Value> {
        self.pool.get().await?.sorted_set_operation(request).await
    }

    /// Execute a hash operation
    pub async fn hash_operation(&self, request: HashOpRequest) -> Result<Value> {
        self.pool.get().await?.hash_operation(request).await
    }

    // ============================================================================
    // Pub/Sub Operations
    // ============================================================================

    /// Subscribe to a channel
    pub async fn subscribe(&self, channel: &str) -> Result<()> {
        self.pool.get().await?.subscribe(channel).await
    }

    /// Unsubscribe from a channel
    pub async fn unsubscribe(&self, channel: &str) -> Result<()> {
        self.pool.get().await?.unsubscribe(channel).await
    }

    /// Publish a message to a channel
    pub async fn publish(&self, channel: &str, message: &[u8]) -> Result<()> {
        self.pool.get().await?.publish(channel, message).await
    }

    // ============================================================================
    // Server Info / Metrics
    // ============================================================================

    /// Get server information and metrics
    pub async fn info(&self) -> Result<crate::types::ServerInfo> {
        let conn = self.pool.get().await?;
        let seq = conn.next_seq();
        let cmd = Command::new(
            crate::types::CommandHeader::new(crate::types::OpCode::Info, seq),
            Bytes::new(),
            Bytes::new(),
        );

        let response = conn.execute(cmd).await?;
        let op_response: OperationResponse = serde_json::from_slice(&response.payload)
            .map_err(|e| Error::Serialization(format!("Failed to parse info response: {}", e)))?;

        if !op_response.success {
            let error_msg = op_response.error.unwrap_or_else(|| "Info request failed".to_string());
            return Err(Error::Server(error_msg));
        }

        // Parse ServerInfo from response data - extract from Value::Object manually
        let data = op_response.data.ok_or_else(|| Error::Server("No data in response".to_string()))?;
        let obj = data.as_object().ok_or_else(|| Error::Server("Expected object data".to_string()))?;
        
        let info = crate::types::ServerInfo {
            uptime_seconds: obj.get("uptime_seconds").and_then(|v| v.as_i64()).unwrap_or(0) as u64,
            connection_count: obj.get("connection_count").and_then(|v| v.as_i64()).unwrap_or(0) as u32,
            total_collections: obj.get("total_collections").and_then(|v| v.as_i64()).unwrap_or(0) as u64,
            memory_usage_bytes: obj.get("memory_usage_bytes").and_then(|v| v.as_i64()).unwrap_or(0) as u64,
            ops_per_second: obj.get("ops_per_second").and_then(|v| v.as_f64()).unwrap_or(0.0),
            cache_hit_rate: obj.get("cache_hit_rate").and_then(|v| v.as_f64()).unwrap_or(0.0),
            version: obj.get("version").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
        };
        
        Ok(info)
    }

    // ============================================================================
    // User Management Operations
    // ============================================================================

    /// List all users
    pub async fn list_users(&self) -> Result<Vec<crate::types::UserInfo>> {
        let conn = self.pool.get().await?;
        let seq = conn.next_seq();
        let cmd = Command::new(
            crate::types::CommandHeader::new(crate::types::OpCode::ListUsers, seq),
            Bytes::new(),
            Bytes::new(),
        );

        let response = conn.execute(cmd).await?;
        let op_response: OperationResponse = serde_json::from_slice(&response.payload)
            .map_err(|e| Error::Serialization(format!("Failed to parse list users response: {}", e)))?;

        if !op_response.success {
            let error_msg = op_response.error.unwrap_or_else(|| "List users failed".to_string());
            return Err(Error::Server(error_msg));
        }

        // Parse users from response data - extract from Value::Array of Value::Object manually
        let data = op_response.data.ok_or_else(|| Error::Server("No data in response".to_string()))?;
        let arr = data.as_array().ok_or_else(|| Error::Server("Expected array data".to_string()))?;
        
        let users: Vec<crate::types::UserInfo> = arr.iter().filter_map(|user_val| {
            let obj = user_val.as_object()?;
            Some(crate::types::UserInfo {
                username: obj.get("username").and_then(|v| v.as_str())?.to_string(),
                role: obj.get("role").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                created_at: obj.get("created_at").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                last_login: obj.get("last_login").and_then(|v| v.as_str()).map(|s| s.to_string()),
                enabled: obj.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false),
            })
        }).collect();
        
        Ok(users)
    }

    /// Create a new user
    pub async fn create_user(&self, request: crate::types::CreateUserRequest) -> Result<()> {
        let conn = self.pool.get().await?;
        let seq = conn.next_seq();
        let payload = serde_json::to_vec(&request)
            .map_err(|e| Error::Serialization(format!("Failed to serialize create user request: {}", e)))?;
        
        let cmd = Command::new(
            crate::types::CommandHeader::new(crate::types::OpCode::CreateUser, seq),
            Bytes::new(),
            Bytes::from(payload),
        );

        let response = conn.execute(cmd).await?;
        let op_response: OperationResponse = serde_json::from_slice(&response.payload)
            .map_err(|e| Error::Serialization(format!("Failed to parse create user response: {}", e)))?;

        if !op_response.success {
            let error_msg = op_response.error.unwrap_or_else(|| "Create user failed".to_string());
            return Err(Error::Server(error_msg));
        }

        Ok(())
    }

    /// Delete a user
    pub async fn delete_user(&self, username: impl Into<String>) -> Result<()> {
        let conn = self.pool.get().await?;
        let seq = conn.next_seq();
        let request = crate::types::DeleteUserRequest { username: username.into() };
        let payload = serde_json::to_vec(&request)
            .map_err(|e| Error::Serialization(format!("Failed to serialize delete user request: {}", e)))?;
        
        let cmd = Command::new(
            crate::types::CommandHeader::new(crate::types::OpCode::DeleteUser, seq),
            Bytes::new(),
            Bytes::from(payload),
        );

        let response = conn.execute(cmd).await?;
        let op_response: OperationResponse = serde_json::from_slice(&response.payload)
            .map_err(|e| Error::Serialization(format!("Failed to parse delete user response: {}", e)))?;

        if !op_response.success {
            let error_msg = op_response.error.unwrap_or_else(|| "Delete user failed".to_string());
            return Err(Error::Server(error_msg));
        }

        Ok(())
    }

    /// Update a user's role
    pub async fn update_user_role(&self, username: impl Into<String>, role: impl Into<String>) -> Result<()> {
        let conn = self.pool.get().await?;
        let seq = conn.next_seq();
        let request = crate::types::UpdateUserRoleRequest { 
            username: username.into(), 
            role: role.into() 
        };
        let payload = serde_json::to_vec(&request)
            .map_err(|e| Error::Serialization(format!("Failed to serialize update user role request: {}", e)))?;
        
        let cmd = Command::new(
            crate::types::CommandHeader::new(crate::types::OpCode::UpdateUserRole, seq),
            Bytes::new(),
            Bytes::from(payload),
        );

        let response = conn.execute(cmd).await?;
        let op_response: OperationResponse = serde_json::from_slice(&response.payload)
            .map_err(|e| Error::Serialization(format!("Failed to parse update user role response: {}", e)))?;

        if !op_response.success {
            let error_msg = op_response.error.unwrap_or_else(|| "Update user role failed".to_string());
            return Err(Error::Server(error_msg));
        }

        Ok(())
    }
}

/// A connection pool for managing multiple connections to a VedDB server
#[derive(Debug, Clone)]
pub struct ConnectionPool {
    /// The server address
    addr: SocketAddr,
    /// The connection pool receiver
    pool: async_channel::Receiver<Connection>,
    /// The connection pool sender
    pool_sender: async_channel::Sender<Connection>,
    /// The number of connections in the pool
    size: usize,
}

impl ConnectionPool {
    /// Create a new connection pool
    pub async fn new(
        addr: impl Into<SocketAddr>, 
        size: usize,
        tls_config: Option<TlsConfig>,
        auth_config: Option<AuthConfig>,
    ) -> Result<Self> {
        let addr = addr.into();
        let (tx, rx) = async_channel::bounded(size);

        // Initialize connections
        for _ in 0..size {
            let conn = Connection::connect_with_config(addr, tls_config.clone(), auth_config.clone()).await?;
            tx.send(conn)
                .await
                .map_err(|e| Error::Connection(e.to_string()))?;
        }

        Ok(Self {
            addr,
            pool: rx,
            pool_sender: tx,
            size,
        })
    }

    /// Get a connection from the pool
    pub async fn get(&self) -> Result<ConnectionGuard> {
        let conn = self
            .pool
            .recv()
            .await
            .map_err(|e| Error::Connection(e.to_string()))?;
        Ok(ConnectionGuard {
            conn: Some(conn),
            pool: self.pool_sender.clone(),
        })
    }

    /// Get the number of connections in the pool
    pub fn size(&self) -> usize {
        self.size
    }
}

/// A guard that returns a connection to the pool when dropped
pub struct ConnectionGuard {
    /// The connection
    conn: Option<Connection>,
    /// The connection pool
    pool: async_channel::Sender<Connection>,
}

impl ConnectionGuard {
    /// Get a reference to the underlying connection
    pub fn connection(&self) -> &Connection {
        self.conn.as_ref().unwrap()
    }

    /// Get a mutable reference to the underlying connection
    pub fn connection_mut(&mut self) -> &mut Connection {
        self.conn.as_mut().unwrap()
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            let pool = self.pool.clone();
            tokio::spawn(async move {
                if let Err(e) = pool.send(conn).await {
                    error!("Failed to return connection to pool: {}", e);
                }
            });
        }
    }
}

impl std::ops::Deref for ConnectionGuard {
    type Target = Connection;

    fn deref(&self) -> &Self::Target {
        self.connection()
    }
}

impl std::ops::DerefMut for ConnectionGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.connection_mut()
    }
}

/// TLS certificate verifier that accepts all certificates (for testing only)
struct AcceptAllVerifier;

impl rustls::client::ServerCertVerifier for AcceptAllVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> std::result::Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

/// A builder for configuring and creating a client
#[derive(Debug, Clone)]
pub struct ClientBuilder {
    /// The server address
    addr: SocketAddr,
    /// The connection pool size
    pool_size: usize,
    /// The connection timeout
    connect_timeout: Duration,
    /// The request timeout
    request_timeout: Duration,
    /// TLS configuration
    tls_config: Option<TlsConfig>,
    /// Authentication configuration
    auth_config: Option<AuthConfig>,
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self {
            addr: ([127, 0, 0, 1], 50051).into(),
            pool_size: 10,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            tls_config: None,
            auth_config: None,
        }
    }
}

impl ClientBuilder {
    /// Create a new builder with default settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the server address
    pub fn addr(mut self, addr: impl Into<SocketAddr>) -> Self {
        self.addr = addr.into();
        self
    }

    /// Set the connection pool size
    pub fn pool_size(mut self, size: usize) -> Self {
        self.pool_size = size;
        self
    }

    /// Set the connection timeout
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Set the request timeout
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Set TLS configuration
    pub fn tls_config(mut self, tls_config: TlsConfig) -> Self {
        self.tls_config = Some(tls_config);
        self
    }

    /// Set authentication configuration
    pub fn auth_config(mut self, auth_config: AuthConfig) -> Self {
        self.auth_config = Some(auth_config);
        self
    }

    /// Build and connect the client
    pub async fn connect(self) -> Result<Client> {
        let pool = ConnectionPool::new(self.addr, self.pool_size, self.tls_config.clone(), self.auth_config.clone()).await?;
        Ok(Client { 
            pool,
            tls_config: self.tls_config,
            auth_config: self.auth_config,
        })
    }
}
