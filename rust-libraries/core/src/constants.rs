// Cryptographic constants
pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;
pub const SIGNATURE_SIZE: usize = 64;

// Protocol constants
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024; // 1MB
pub const MAX_PREKEYS: usize = 100;
pub const PREKEY_ROTATION_DAYS: u64 = 7;

// Network constants
pub const DEFAULT_MIX_PATH_LENGTH: usize = 3;
pub const MAX_MIX_PATH_LENGTH: usize = 5;
pub const BATCH_SIZE: usize = 50;
pub const BATCH_TIMEOUT_MS: u64 = 100;

// Storage constants
pub const DB_PAGE_SIZE: usize = 4096;
pub const MAX_CACHED_SESSIONS: usize = 100;

// Threat detection constants
pub const THREAT_SCORE_HIGH: f32 = 0.7;
pub const THREAT_SCORE_MEDIUM: f32 = 0.4;
pub const THREAT_SCORE_LOW: f32 = 0.2;
