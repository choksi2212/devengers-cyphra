/* tslint:disable */
/* eslint-disable */

/**
 * Decrypt ciphertext with AES-256-GCM.
 *
 * # Arguments
 * * `key_bytes` — 32-byte AES key
 * * `ciphertext_hex` — hex-encoded ciphertext+tag
 * * `nonce_hex` — hex-encoded 12-byte nonce
 *
 * Returns plaintext bytes on success.
 */
export function aes_gcm_decrypt(key_bytes: Uint8Array, ciphertext_hex: string, nonce_hex: string): Uint8Array;

/**
 * Encrypt plaintext with AES-256-GCM.
 *
 * # Arguments
 * * `key_bytes` — 32-byte AES key
 * * `plaintext` — data to encrypt
 *
 * Returns JSON: `{ ciphertext: hex, nonce: hex }`
 */
export function aes_gcm_encrypt(key_bytes: Uint8Array, plaintext: Uint8Array): string;

export function cyphra_wasm_version(): string;

/**
 * Generate a fresh Ed25519 signing key pair.
 * Returns JSON: `{ verifying_key: hex, signing_key: hex }`
 */
export function ed25519_generate_keypair(): string;

/**
 * Sign a message using Ed25519.
 *
 * # Arguments
 * * `signing_key_hex` — 32-byte Ed25519 signing key in hex
 * * `message` — data to sign
 *
 * Returns signature as hex string (64 bytes).
 */
export function ed25519_sign(signing_key_hex: string, message: Uint8Array): string;

/**
 * Verify an Ed25519 signature.
 *
 * # Arguments
 * * `verifying_key_hex` — 32-byte Ed25519 verifying key in hex
 * * `message` — original data that was signed
 * * `signature_hex` — 64-byte signature in hex
 *
 * Returns `true` if valid, `false` otherwise.
 */
export function ed25519_verify(verifying_key_hex: string, message: Uint8Array, signature_hex: string): boolean;

/**
 * Derive key material using HKDF-SHA256.
 *
 * # Arguments
 * * `ikm` — Input Key Material (e.g. DH shared secret)
 * * `salt` — Optional salt (empty = zero bytes)
 * * `info` — Context/application info
 * * `output_len` — Desired output length in bytes (max 255 * 32 = 8160)
 *
 * Returns derived key as hex string.
 */
export function hkdf_sha256(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, output_len: number): string;

export function random_bytes(len: number): Uint8Array;

/**
 * Advance a symmetric chain key by one ratchet step.
 *
 * Produces a new chain key and a message key:
 *   message_key  = HKDF-SHA256(chain_key, salt=[], info="msg_key")
 *   next_chain   = HKDF-SHA256(chain_key, salt=[], info="chain")
 *
 * Returns JSON: `{ message_key: hex, next_chain_key: hex }`
 */
export function ratchet_chain_step(chain_key_hex: string): string;

/**
 * Initialize a new ratchet root key from a shared DH secret.
 *
 * Returns JSON `{ root_key: hex, chain_key: hex }`
 */
export function ratchet_init_from_dh(dh_shared_hex: string, prev_root_key_hex: string): string;

/**
 * Compute SHA-256 hash of data.
 * Returns hash as hex string (64 chars).
 */
export function sha256_hash(data: Uint8Array): string;

/**
 * Perform X25519 Diffie-Hellman to derive a shared secret.
 *
 * # Arguments
 * * `private_key_hex` — 32-byte private key in hex
 * * `peer_public_key_hex` — 32-byte peer public key in hex
 *
 * Returns shared secret as hex string.
 */
export function x25519_diffie_hellman(private_key_hex: string, peer_public_key_hex: string): string;

/**
 * Generate a fresh X25519 key pair.
 * Returns JSON: `{ public_key: hex, private_key: hex }`
 */
export function x25519_generate_keypair(): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly aes_gcm_decrypt: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly aes_gcm_encrypt: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly cyphra_wasm_version: () => [number, number];
    readonly ed25519_generate_keypair: () => [number, number];
    readonly ed25519_sign: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly ed25519_verify: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly hkdf_sha256: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number, number];
    readonly random_bytes: (a: number) => [number, number];
    readonly ratchet_chain_step: (a: number, b: number) => [number, number, number, number];
    readonly ratchet_init_from_dh: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly sha256_hash: (a: number, b: number) => [number, number];
    readonly x25519_diffie_hellman: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly x25519_generate_keypair: () => [number, number];
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
