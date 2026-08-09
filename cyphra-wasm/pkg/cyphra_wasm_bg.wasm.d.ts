/* tslint:disable */
/* eslint-disable */
export const memory: WebAssembly.Memory;
export const aes_gcm_decrypt: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
export const aes_gcm_encrypt: (a: number, b: number, c: number, d: number) => [number, number, number, number];
export const cyphra_wasm_version: () => [number, number];
export const ed25519_generate_keypair: () => [number, number];
export const ed25519_sign: (a: number, b: number, c: number, d: number) => [number, number, number, number];
export const ed25519_verify: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
export const hkdf_sha256: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number, number];
export const random_bytes: (a: number) => [number, number];
export const ratchet_chain_step: (a: number, b: number) => [number, number, number, number];
export const ratchet_init_from_dh: (a: number, b: number, c: number, d: number) => [number, number, number, number];
export const sha256_hash: (a: number, b: number) => [number, number];
export const x25519_diffie_hellman: (a: number, b: number, c: number, d: number) => [number, number, number, number];
export const x25519_generate_keypair: () => [number, number];
export const __wbindgen_exn_store: (a: number) => void;
export const __externref_table_alloc: () => number;
export const __wbindgen_externrefs: WebAssembly.Table;
export const __wbindgen_malloc: (a: number, b: number) => number;
export const __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
export const __externref_table_dealloc: (a: number) => void;
export const __wbindgen_free: (a: number, b: number, c: number) => void;
export const __wbindgen_start: () => void;
