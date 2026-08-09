//! Protocol types for VedDB client-server communication.
//! 
//! Supports both v0.1.x (legacy) and v0.2.0 protocols with automatic version detection.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;
use uuid::Uuid;

/// Error type for protocol operations
#[derive(Error, Debug)]
pub enum ProtocolError {
    /// Invalid message format
    #[error("Invalid message format: {0}")]
    InvalidFormat(String),

    /// Invalid opcode
    #[error("Invalid opcode: {0}")]
    InvalidOpCode(u8),

    /// Invalid status code
    #[error("Invalid status code: {0}")]
    InvalidStatusCode(u8),

    /// Message too large
    #[error("Message too large: {0} bytes")]
    MessageTooLarge(usize),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),
}

/// Protocol version constants
pub const PROTOCOL_V1: u8 = 0x01; // Legacy v0.1.x protocol
pub const PROTOCOL_V2: u8 = 0x02; // New v0.2.0 protocol

/// Command opcodes for v0.1.x (legacy) and v0.2.0 protocols
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpCode {
    // Legacy v0.1.x opcodes (0x01-0x0A)
    Ping = 0x01,
    Set = 0x02,
    Get = 0x03,
    Delete = 0x04,
    Cas = 0x05,
    Subscribe = 0x06,
    Unsubscribe = 0x07,
    Publish = 0x08,
    Fetch = 0x09,
    Info = 0x0A,
    
    // New v0.2.0 opcodes (0x10-0x3F)
    // Authentication
    Auth = 0x10,
    AuthResponse = 0x11,
    
    // Document operations
    Query = 0x12,
    InsertDoc = 0x13,
    UpdateDoc = 0x14,
    DeleteDoc = 0x15,
    
    // Collection management
    CreateCollection = 0x16,
    DropCollection = 0x17,
    ListCollections = 0x18,
    
    // Index management
    CreateIndex = 0x19,
    DropIndex = 0x1A,
    ListIndexes = 0x1B,
    
    // Advanced data structures - Lists
    LPush = 0x20,
    RPush = 0x21,
    LPop = 0x22,
    RPop = 0x23,
    LRange = 0x24,
    LLen = 0x25,
    
    // Advanced data structures - Sets
    SAdd = 0x26,
    SRem = 0x27,
    SMembers = 0x28,
    SIsMember = 0x29,
    SCard = 0x2A,
    SUnion = 0x2B,
    SInter = 0x2C,
    SDiff = 0x2D,
    
    // Advanced data structures - Sorted Sets
    ZAdd = 0x2E,
    ZRem = 0x2F,
    ZRange = 0x30,
    ZRangeByScore = 0x31,
    ZCard = 0x32,
    ZScore = 0x33,
    
    // Advanced data structures - Hashes
    HSet = 0x34,
    HGet = 0x35,
    HDel = 0x36,
    HGetAll = 0x37,
    HKeys = 0x38,
    HVals = 0x39,
    HLen = 0x3A,
    
    // User Management
    ListUsers = 0x3B,
    CreateUser = 0x3C,
    DeleteUser = 0x3D,
    UpdateUserRole = 0x3E,
}

impl TryFrom<u8> for OpCode {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            // Legacy v0.1.x opcodes
            0x01 => Ok(OpCode::Ping),
            0x02 => Ok(OpCode::Set),
            0x03 => Ok(OpCode::Get),
            0x04 => Ok(OpCode::Delete),
            0x05 => Ok(OpCode::Cas),
            0x06 => Ok(OpCode::Subscribe),
            0x07 => Ok(OpCode::Unsubscribe),
            0x08 => Ok(OpCode::Publish),
            0x09 => Ok(OpCode::Fetch),
            0x0A => Ok(OpCode::Info),
            
            // New v0.2.0 opcodes
            0x10 => Ok(OpCode::Auth),
            0x11 => Ok(OpCode::AuthResponse),
            0x12 => Ok(OpCode::Query),
            0x13 => Ok(OpCode::InsertDoc),
            0x14 => Ok(OpCode::UpdateDoc),
            0x15 => Ok(OpCode::DeleteDoc),
            0x16 => Ok(OpCode::CreateCollection),
            0x17 => Ok(OpCode::DropCollection),
            0x18 => Ok(OpCode::ListCollections),
            0x19 => Ok(OpCode::CreateIndex),
            0x1A => Ok(OpCode::DropIndex),
            0x1B => Ok(OpCode::ListIndexes),
            0x20 => Ok(OpCode::LPush),
            0x21 => Ok(OpCode::RPush),
            0x22 => Ok(OpCode::LPop),
            0x23 => Ok(OpCode::RPop),
            0x24 => Ok(OpCode::LRange),
            0x25 => Ok(OpCode::LLen),
            0x26 => Ok(OpCode::SAdd),
            0x27 => Ok(OpCode::SRem),
            0x28 => Ok(OpCode::SMembers),
            0x29 => Ok(OpCode::SIsMember),
            0x2A => Ok(OpCode::SCard),
            0x2B => Ok(OpCode::SUnion),
            0x2C => Ok(OpCode::SInter),
            0x2D => Ok(OpCode::SDiff),
            0x2E => Ok(OpCode::ZAdd),
            0x2F => Ok(OpCode::ZRem),
            0x30 => Ok(OpCode::ZRange),
            0x31 => Ok(OpCode::ZRangeByScore),
            0x32 => Ok(OpCode::ZCard),
            0x33 => Ok(OpCode::ZScore),
            0x34 => Ok(OpCode::HSet),
            0x35 => Ok(OpCode::HGet),
            0x36 => Ok(OpCode::HDel),
            0x37 => Ok(OpCode::HGetAll),
            0x38 => Ok(OpCode::HKeys),
            0x39 => Ok(OpCode::HVals),
            0x3A => Ok(OpCode::HLen),
            // User Management
            0x3B => Ok(OpCode::ListUsers),
            0x3C => Ok(OpCode::CreateUser),
            0x3D => Ok(OpCode::DeleteUser),
            0x3E => Ok(OpCode::UpdateUserRole),
            _ => Err(ProtocolError::InvalidOpCode(value)),
        }
    }
}

/// Response status codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusCode {
    /// Operation succeeded
    Ok = 0x00,
    /// General error
    Error = 0x01,
    /// Key not found
    NotFound = 0x02,
    /// Buffer full
    Full = 0x03,
    /// Operation timed out
    Timeout = 0x04,
    /// Version mismatch (for CAS operations)
    VersionMismatch = 0x05,
    /// Authentication required
    AuthRequired = 0x06,
    /// Authentication failed
    AuthFailed = 0x07,
    /// Permission denied
    PermissionDenied = 0x08,
    /// Invalid query
    InvalidQuery = 0x09,
    /// Collection already exists
    CollectionExists = 0x0A,
    /// Collection not found
    CollectionNotFound = 0x0B,
    /// Index already exists
    IndexExists = 0x0C,
    /// Index not found
    IndexNotFound = 0x0D,
}

impl TryFrom<u8> for StatusCode {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, <Self as TryFrom<u8>>::Error> {
        match value {
            0x00 => Ok(StatusCode::Ok),
            0x01 => Ok(StatusCode::Error),
            0x02 => Ok(StatusCode::NotFound),
            0x03 => Ok(StatusCode::Full),
            0x04 => Ok(StatusCode::Timeout),
            0x05 => Ok(StatusCode::VersionMismatch),
            0x06 => Ok(StatusCode::AuthRequired),
            0x07 => Ok(StatusCode::AuthFailed),
            0x08 => Ok(StatusCode::PermissionDenied),
            0x09 => Ok(StatusCode::InvalidQuery),
            0x0A => Ok(StatusCode::CollectionExists),
            0x0B => Ok(StatusCode::CollectionNotFound),
            0x0C => Ok(StatusCode::IndexExists),
            0x0D => Ok(StatusCode::IndexNotFound),
            _ => Err(ProtocolError::InvalidStatusCode(value)),
        }
    }
}

/// Command flags
pub mod flags {
    pub const NO_COPY: u8 = 0x01; // Value is already in arena, use offset
    pub const URGENT: u8 = 0x02; // High priority operation
    pub const TTL: u8 = 0x04; // Extra field contains TTL
    pub const CAS_VERSION: u8 = 0x08; // Extra field contains expected version
}

/// Command header (24 bytes, little-endian)
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct CommandHeader {
    /// Operation code
    pub opcode: u8,
    /// Command flags
    pub flags: u8,
    /// Protocol version (PROTOCOL_V1 or PROTOCOL_V2)
    pub version: u8,
    /// Reserved for future use
    pub reserved: u8,
    /// Client-local sequence ID
    pub seq: u32,
    /// Key length in bytes
    pub key_len: u32,
    /// Value length in bytes
    pub value_len: u32,
    /// Extra data (version for CAS, TTL, etc.)
    pub extra: u64,
}

impl CommandHeader {
    /// Create a new command header with v0.2.0 protocol
    pub fn new(opcode: OpCode, seq: u32) -> Self {
        Self {
            opcode: opcode as u8,
            flags: 0,
            version: PROTOCOL_V2,
            reserved: 0,
            seq,
            key_len: 0,
            value_len: 0,
            extra: 0,
        }
    }

    /// Create a new command header with v0.1.x protocol
    pub fn new_v1(opcode: OpCode, seq: u32) -> Self {
        Self {
            opcode: opcode as u8,
            flags: 0,
            version: PROTOCOL_V1,
            reserved: 0,
            seq,
            key_len: 0,
            value_len: 0,
            extra: 0,
        }
    }

    /// Set the key and value lengths
    pub fn with_lengths(mut self, key_len: u32, value_len: u32) -> Self {
        self.key_len = key_len;
        self.value_len = value_len;
        self
    }

    /// Set extra data
    pub fn with_extra(mut self, extra: u64) -> Self {
        self.extra = extra;
        self
    }

    /// Set a flag
    pub fn with_flag(mut self, flag: u8) -> Self {
        self.flags |= flag;
        self
    }

    /// Check if a flag is set
    pub fn has_flag(&self, flag: u8) -> bool {
        (self.flags & flag) != 0
    }

    /// Get total payload length
    pub fn total_payload_len(&self) -> usize {
        (self.key_len + self.value_len) as usize
    }
}

/// Command structure
#[derive(Debug, Clone)]
pub struct Command {
    /// Command header
    pub header: CommandHeader,
    /// Key (if any)
    pub key: Bytes,
    /// Value (if any)
    pub value: Bytes,
}

impl Command {
    /// Create a new command
    pub fn new(header: CommandHeader, key: impl Into<Bytes>, value: impl Into<Bytes>) -> Self {
        let key = key.into();
        let value = value.into();
        Self {
            header: header.with_lengths(key.len() as u32, value.len() as u32),
            key,
            value,
        }
    }

    /// Create a PING command
    pub fn ping(seq: u32) -> Self {
        Self::new(
            CommandHeader::new(OpCode::Ping, seq),
            Bytes::new(),
            Bytes::new(),
        )
    }

    /// Create a SET command
    pub fn set<K, V>(seq: u32, key: K, value: V) -> Self
    where
        K: Into<Bytes>,
        V: Into<Bytes>,
    {
        Self::new(CommandHeader::new(OpCode::Set, seq), key, value)
    }

    /// Create a GET command
    pub fn get<K>(seq: u32, key: K) -> Self
    where
        K: Into<Bytes>,
    {
        Self::new(CommandHeader::new(OpCode::Get, seq), key, Bytes::new())
    }

    /// Create a DELETE command
    pub fn delete<K>(seq: u32, key: K) -> Self
    where
        K: Into<Bytes>,
    {
        Self::new(CommandHeader::new(OpCode::Delete, seq), key, Bytes::new())
    }

    /// Create a CAS (Compare-And-Swap) command
    pub fn cas<K, V>(seq: u32, key: K, expected_version: u64, value: V) -> Self
    where
        K: Into<Bytes>,
        V: Into<Bytes>,
    {
        Self::new(
            CommandHeader::new(OpCode::Cas, seq).with_extra(expected_version),
            key,
            value,
        )
    }

    /// Create a FETCH command (list keys)
    pub fn fetch(seq: u32, key: impl Into<Bytes>) -> Self {
        Self::new(CommandHeader::new(OpCode::Fetch, seq), key, Bytes::new())
    }

    /// Serialize the command to bytes
    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(24 + self.key.len() + self.value.len());

        // Write header (24 bytes) - ALL LITTLE-ENDIAN
        buf.put_u8(self.header.opcode);
        buf.put_u8(self.header.flags);
        buf.put_u8(self.header.version);
        buf.put_u8(self.header.reserved);
        buf.put_u32_le(self.header.seq);
        buf.put_u32_le(self.header.key_len);
        buf.put_u32_le(self.header.value_len);
        buf.put_u64_le(self.header.extra);

        // Write key and value
        buf.extend_from_slice(&self.key);
        buf.extend_from_slice(&self.value);

        buf.freeze()
    }
}

/// Response header (20 bytes)
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ResponseHeader {
    /// Status code
    pub status: u8,
    /// Response flags
    pub flags: u8,
    /// Reserved
    pub reserved: u16,
    /// Sequence number
    pub seq: u32,
    /// Payload length
    pub payload_len: u32,
    /// Extra data (version, offset, or other metadata)
    pub extra: u64,
}

impl ResponseHeader {
    /// Create a new response header
    pub fn new(status: StatusCode, seq: u32) -> Self {
        Self {
            status: status as u8,
            flags: 0,
            reserved: 0,
            seq,
            payload_len: 0,
            extra: 0,
        }
    }

    /// Set the payload length
    pub fn with_payload_len(mut self, len: u32) -> Self {
        self.payload_len = len;
        self
    }
}

/// Response structure
#[derive(Debug, Clone)]
pub struct Response {
    /// Response header
    pub header: ResponseHeader,
    /// Response payload
    pub payload: Bytes,
}

impl Response {
    /// Create a new response
    pub fn new(header: ResponseHeader, payload: impl Into<Bytes>) -> Self {
        let payload = payload.into();
        Self {
            header: header.with_payload_len(payload.len() as u32),
            payload,
        }
    }

    /// Create a success response
    pub fn ok(seq: u32, payload: impl Into<Bytes>) -> Self {
        Self::new(ResponseHeader::new(StatusCode::Ok, seq), payload)
    }

    /// Create a not found response
    pub fn not_found(seq: u32) -> Self {
        Self::new(ResponseHeader::new(StatusCode::NotFound, seq), Bytes::new())
    }

    /// Create an error response
    pub fn error(seq: u32) -> Self {
        Self::new(
            ResponseHeader::new(StatusCode::Error, seq),
            Bytes::new(),
        )
    }

    /// Deserialize a response from bytes
    pub fn from_bytes(mut bytes: &[u8]) -> Result<Self, ProtocolError> {
        // Support both v0.1.x (20-byte header) and v0.2.0 (16-byte header)
        if bytes.len() < 16 {
            return Err(ProtocolError::InvalidFormat("response too short".into()));
        }

        // Read header - ALL LITTLE-ENDIAN
        let status = StatusCode::try_from(bytes.get_u8())?;
        let flags = bytes.get_u8();
        let reserved = bytes.get_u16_le();
        let seq = bytes.get_u32_le();
        let payload_len = bytes.get_u32_le() as usize;
        
        // v0.2.0 uses 16-byte header (no extra field), v0.1.x uses 20-byte header
        // v0.2.0 uses 16-byte header (no extra field), v0.1.x uses 20-byte header
        // We have already consumed 12 bytes.
        let extra = if bytes.len() >= payload_len + 8 {
            // v0.1.x format with extra field (8 bytes remaining from header)
            bytes.get_u64_le()
        } else {
            // v0.2.0 format without extra field (4 bytes padding remaining from header)
            if bytes.len() >= payload_len + 4 {
                bytes.advance(4);
            }
            0
        };

        // Check payload length
        if bytes.remaining() < payload_len {
            return Err(ProtocolError::InvalidFormat(
                "invalid payload length".into(),
            ));
        }

        // Read payload
        let payload = bytes.copy_to_bytes(payload_len);

        Ok(Self {
            header: ResponseHeader {
                status: status as u8,
                flags,
                reserved,
                seq,
                payload_len: payload_len as u32,
                extra,
            },
            payload,
        })
    }

    /// Check if the response indicates success
    pub fn is_ok(&self) -> bool {
        matches!(StatusCode::try_from(self.header.status), Ok(StatusCode::Ok))
    }

    /// Get the status code
    pub fn status(&self) -> StatusCode {
        StatusCode::try_from(self.header.status).unwrap_or(StatusCode::Error)
    }
}

// ============================================================================
// v0.2.0 Protocol Data Types
// ============================================================================

/// Unique identifier for documents
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DocumentId(Uuid);

impl DocumentId {
    /// Create a new random document ID
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create a document ID from a UUID
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Get the inner UUID
    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }

    /// Convert to bytes
    pub fn to_bytes(&self) -> [u8; 16] {
        *self.0.as_bytes()
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(Uuid::from_bytes(bytes))
    }
}

impl Default for DocumentId {
    fn default() -> Self {
        Self::new()
    }
}

/// ObjectId type for MongoDB compatibility
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ObjectId([u8; 12]);

impl ObjectId {
    /// Create a new ObjectId
    pub fn new() -> Self {
        let mut bytes = [0u8; 12];
        // Timestamp (4 bytes)
        let timestamp = chrono::Utc::now().timestamp() as u32;
        bytes[0..4].copy_from_slice(&timestamp.to_be_bytes());
        
        // Random value (5 bytes)
        let uuid = Uuid::new_v4();
        let random = uuid.as_bytes();
        bytes[4..9].copy_from_slice(&random[0..5]);
        
        // Counter (3 bytes)
        let counter = rand::random::<u32>() & 0x00FFFFFF;
        bytes[9..12].copy_from_slice(&counter.to_be_bytes()[1..4]);
        
        Self(bytes)
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }

    /// Get bytes
    pub fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }

    /// Get timestamp
    pub fn timestamp(&self) -> i64 {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&self.0[0..4]);
        u32::from_be_bytes(bytes) as i64
    }
}

impl Default for ObjectId {
    fn default() -> Self {
        Self::new()
    }
}

/// Value type supporting all JSON types plus ObjectId, DateTime, Binary
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum Value {
    /// Null value
    Null,
    /// Boolean value
    Bool(bool),
    /// 32-bit integer
    Int32(i32),
    /// 64-bit integer
    Int64(i64),
    /// 64-bit floating point
    Float64(f64),
    /// String value
    String(String),
    /// Binary data
    Binary(Vec<u8>),
    /// Array of values
    Array(Vec<Value>),
    /// Object with string keys and value values
    Object(BTreeMap<String, Value>),
    /// ObjectId for MongoDB compatibility
    ObjectId(ObjectId),
    /// DateTime with UTC timezone
    DateTime(DateTime<Utc>),
}

impl Value {
    /// Check if value is null
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    /// Get as boolean
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Get as i64
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Int32(i) => Some(*i as i64),
            Value::Int64(i) => Some(*i),
            _ => None,
        }
    }

    /// Get as f64
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Float64(f) => Some(*f),
            Value::Int32(i) => Some(*i as f64),
            Value::Int64(i) => Some(*i as f64),
            _ => None,
        }
    }

    /// Get as string
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    /// Get as array
    pub fn as_array(&self) -> Option<&Vec<Value>> {
        match self {
            Value::Array(arr) => Some(arr),
            _ => None,
        }
    }

    /// Get as object
    pub fn as_object(&self) -> Option<&BTreeMap<String, Value>> {
        match self {
            Value::Object(obj) => Some(obj),
            _ => None,
        }
    }
}

/// Document type for v0.2.0
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Document {
    #[serde(rename = "_id")]
    pub id: DocumentId,
    #[serde(flatten)]
    pub fields: BTreeMap<String, Value>,
}

impl Document {
    /// Create a new document with random ID
    pub fn new() -> Self {
        Self {
            id: DocumentId::new(),
            fields: BTreeMap::new(),
        }
    }

    /// Create a document with specific ID
    pub fn with_id(id: DocumentId) -> Self {
        Self {
            id,
            fields: BTreeMap::new(),
        }
    }

    /// Insert a field
    pub fn insert<K: Into<String>, V: Into<Value>>(&mut self, key: K, value: V) {
        self.fields.insert(key.into(), value.into());
    }

    /// Get a field
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.fields.get(key)
    }
}

impl Default for Document {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// v0.2.0 Protocol Request/Response Types
// ============================================================================

/// Authentication request payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    pub method: AuthMethod,
    pub credentials: AuthCredentials,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthMethod {
    UsernamePassword,
    JwtToken,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthCredentials {
    UsernamePassword { username: String, password: String },
    JwtToken { token: String },
}

/// Authentication response payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub success: bool,
    pub token: Option<String>,
    pub expires_at: Option<u64>, // Unix timestamp
    pub error: Option<String>,
}

/// Query request payload for document operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryRequest {
    pub collection: String,
    pub filter: Option<Value>,
    pub projection: Option<Value>,
    pub sort: Option<Value>,
    pub skip: Option<u64>,
    pub limit: Option<u64>,
}

/// List collections request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListCollectionsRequest {
    pub filter: Option<Value>,
}

/// Drop collection request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DropCollectionRequest {
    pub name: String,
}

/// List indexes request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListIndexesRequest {
    pub collection: String,
}

/// Drop index request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DropIndexRequest {
    pub collection: String,
    pub name: String,
}

/// Document insertion request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsertDocRequest {
    pub collection: String,
    pub document: Document,
}

/// Document update request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateDocRequest {
    pub collection: String,
    pub filter: Value,
    pub update: Value,
    pub upsert: bool,
}

/// Document deletion request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteDocRequest {
    pub collection: String,
    pub filter: Value,
}

/// Collection creation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCollectionRequest {
    pub name: String,
    pub schema: Option<Value>, // JSON schema
}

/// Index creation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateIndexRequest {
    pub collection: String,
    pub name: String,
    pub fields: Vec<IndexField>,
    pub unique: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexField {
    pub field: String,
    pub direction: i32, // 1 for ascending, -1 for descending
}

/// List operation request (for Redis-like data structures)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListOpRequest {
    pub key: String,
    pub operation: ListOperation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ListOperation {
    Push { values: Vec<Value>, left: bool },
    Pop { left: bool },
    Range { start: i64, stop: i64 },
    Len,
}

/// Set operation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetOpRequest {
    pub key: String,
    pub operation: SetOperation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SetOperation {
    Add { values: Vec<Value> },
    Remove { values: Vec<Value> },
    Members,
    IsMember { value: Value },
    Card,
    Union { other_keys: Vec<String> },
    Inter { other_keys: Vec<String> },
    Diff { other_keys: Vec<String> },
}

/// Sorted set operation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SortedSetOpRequest {
    pub key: String,
    pub operation: SortedSetOperation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SortedSetOperation {
    Add { members: Vec<ScoredMember> },
    Remove { members: Vec<Value> },
    Range { start: i64, stop: i64 },
    RangeByScore { min: f64, max: f64 },
    Card,
    Score { member: Value },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoredMember {
    pub score: f64,
    pub member: Value,
}

/// Hash operation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashOpRequest {
    pub key: String,
    pub operation: HashOperation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HashOperation {
    Set { field: String, value: Value },
    Get { field: String },
    Del { fields: Vec<String> },
    GetAll,
    Keys,
    Vals,
    Len,
}

/// Generic operation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationResponse {
    pub success: bool,
    pub data: Option<Value>,
    pub error: Option<String>,
    pub affected_count: Option<u64>,
}

impl OperationResponse {
    pub fn success(data: Option<Value>) -> Self {
        Self {
            success: true,
            data,
            error: None,
            affected_count: None,
        }
    }

    pub fn error(message: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message),
            affected_count: None,
        }
    }
}

// ============================================================================
// Conversion implementations
// ============================================================================

impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::Bool(b)
    }
}

impl From<i32> for Value {
    fn from(i: i32) -> Self {
        Value::Int32(i)
    }
}

impl From<i64> for Value {
    fn from(i: i64) -> Self {
        Value::Int64(i)
    }
}

impl From<f64> for Value {
    fn from(f: f64) -> Self {
        Value::Float64(f)
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::String(s)
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::String(s.to_string())
    }
}

impl From<Vec<u8>> for Value {
    fn from(b: Vec<u8>) -> Self {
        Value::Binary(b)
    }
}

impl From<Vec<Value>> for Value {
    fn from(arr: Vec<Value>) -> Self {
        Value::Array(arr)
    }
}

impl From<BTreeMap<String, Value>> for Value {
    fn from(obj: BTreeMap<String, Value>) -> Self {
        Value::Object(obj)
    }
}

impl From<ObjectId> for Value {
    fn from(oid: ObjectId) -> Self {
        Value::ObjectId(oid)
    }
}

impl From<DateTime<Utc>> for Value {
    fn from(dt: DateTime<Utc>) -> Self {
        Value::DateTime(dt)
    }
}

// ============================================================================
// User Management Request/Response Types
// ============================================================================

/// Request to create a new user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    pub role: String,
}

/// Request to delete a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteUserRequest {
    pub username: String,
}

/// Request to update a user's role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateUserRoleRequest {
    pub username: String,
    pub role: String,
}

/// User information response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub username: String,
    pub role: String,
    pub created_at: String,
    pub last_login: Option<String>,
    pub enabled: bool,
}

/// Server information/metrics response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub uptime_seconds: u64,
    pub connection_count: u32,
    pub total_collections: u64,
    pub memory_usage_bytes: u64,
    pub ops_per_second: f64,
    pub cache_hit_rate: f64,
    pub version: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn test_command_serialization() {
        let cmd = Command::set(1, "key", "value");
        let bytes = cmd.to_bytes();

        assert_eq!(bytes[0], OpCode::Set as u8); // opcode
        assert_eq!(bytes[1], 0); // flags
        assert_eq!(bytes[2], PROTOCOL_V2); // version
        // Header is 24 bytes, then key, then value
        assert_eq!(&bytes[24..27], b"key");
        assert_eq!(&bytes[27..32], b"value");
    }

    #[test]
    fn test_response_deserialization() {
        let mut buf = BytesMut::new();
        buf.put_u8(StatusCode::Ok as u8); // status
        buf.put_u8(0); // flags
        buf.put_u16_le(0); // reserved
        buf.put_u32_le(42); // seq
        buf.put_u32_le(5); // payload_len
        buf.put_u64_le(0); // extra
        buf.extend_from_slice(b"hello"); // payload

        let resp = Response::from_bytes(&buf).unwrap();
        assert!(resp.is_ok());
        assert_eq!(resp.header.seq, 42);
        assert_eq!(&resp.payload[..], b"hello");
    }

    #[test]
    fn test_document_creation() {
        let mut doc = Document::new();
        doc.insert("name", "Alice");
        doc.insert("age", 30i32);
        doc.insert("active", true);

        assert_eq!(doc.get("name").unwrap().as_str().unwrap(), "Alice");
        assert_eq!(doc.get("age").unwrap().as_i64().unwrap(), 30);
        assert_eq!(doc.get("active").unwrap().as_bool().unwrap(), true);
    }

    #[test]
    fn test_value_conversions() {
        let val_bool: Value = true.into();
        assert!(matches!(val_bool, Value::Bool(true)));

        let val_str: Value = "hello".into();
        assert!(matches!(val_str, Value::String(ref s) if s == "hello"));

        let val_int: Value = 42i64.into();
        assert!(matches!(val_int, Value::Int64(42)));
    }

    #[test]
    fn test_protocol_version() {
        let header = CommandHeader::new(OpCode::Ping, 1);
        assert_eq!(header.version, PROTOCOL_V2);

        let header_v1 = CommandHeader::new_v1(OpCode::Ping, 1);
        assert_eq!(header_v1.version, PROTOCOL_V1);
    }

    #[test]
    fn test_object_id() {
        let oid = ObjectId::new();
        let bytes = oid.as_bytes();
        let oid2 = ObjectId::from_bytes(*bytes);
        assert_eq!(oid, oid2);
    }

    #[test]
    fn test_document_id() {
        let doc_id = DocumentId::new();
        let bytes = doc_id.to_bytes();
        let doc_id2 = DocumentId::from_bytes(bytes);
        assert_eq!(doc_id, doc_id2);
    }
}
