# CYPHRA — Complete Technology Stack Reference

**Every technology, library, algorithm, and framework used in the project — with full forms, explanations, and justifications.**

---

## Table of Contents

1. [Programming Languages](#1-programming-languages)
2. [Frontend Technologies](#2-frontend-technologies)
3. [Backend Technologies](#3-backend-technologies)
4. [Machine Learning Stack](#4-machine-learning-stack)
5. [Cryptographic Technologies](#5-cryptographic-technologies)
6. [Database Technologies](#6-database-technologies)
7. [Networking & Protocols](#7-networking--protocols)
8. [Mobile Technologies](#8-mobile-technologies)
9. [DevOps & Build Tools](#9-devops--build-tools)
10. [Security Standards & Compliance](#10-security-standards--compliance)

---

## 1. Programming Languages

### Rust (v1.96)
- **What:** Systems programming language with memory safety guarantees without garbage collection
- **Where used:** Cryptographic libraries (8 crates), WASM crypto bridge, VedDB database, REST API server
- **Why Rust over C/C++:** Zero-cost abstractions, no null pointer dereferences, no buffer overflows, no data races — critical for cryptographic code where a single memory bug can leak keys
- **Why Rust over Go:** No garbage collector pauses (important for real-time crypto operations), true zero-overhead FFI to C libraries (libsodium), compile-time thread safety guarantees

### Python (v3.11)
- **What:** High-level interpreted language with rich data science ecosystem
- **Where used:** ML inference service (FastAPI), packet capture (Scapy), auto-response engine, training pipeline orchestration
- **Why Python:** Only language with production-quality bindings for ALL three ML frameworks (LightGBM, XGBoost, CatBoost) + Scapy packet manipulation + FastAPI async server. No other language has this ecosystem coverage.

### JavaScript / JSX (ES2022+)
- **What:** Browser scripting language + React JSX syntax
- **Where used:** React frontend (all pages, services, components), Node.js backend, PWA
- **Why JavaScript:** Universal browser language — no alternative for client-side web applications. Node.js enables full-stack JavaScript with WebSocket support.

### Kotlin (v1.9+)
- **What:** Modern JVM language by JetBrains, official Android development language
- **Where used:** Native Android application (Jetpack Compose UI)
- **Why Kotlin over Java:** Null safety, coroutines for async, extension functions, 40% less boilerplate than Java. Google's recommended language for Android since 2019.

### HTML5 / CSS3
- **What:** Web markup and styling languages
- **Where used:** Landing page, PWA, business website
- **Why:** No alternative for web document structure and presentation.

---

## 2. Frontend Technologies

### React (v18.2)
- **Full name:** React JavaScript Library for Building User Interfaces
- **Developer:** Meta (Facebook)
- **Where used:** Entire web application (6 pages, 4 components)
- **Why React over Vue/Angular:** Largest ecosystem, best TypeScript support, hooks-based architecture (simpler than class components), lazy loading via `React.lazy()` + `Suspense` for code splitting
- **Key features used:** Functional components, useState/useEffect hooks, React Router v6, lazy imports, Suspense boundaries

### Vite (v5.0)
- **Full name:** Vite (French for "fast") — Next Generation Frontend Build Tool
- **Developer:** Evan You (Vue.js creator)
- **Where used:** Frontend build tool + dev server (port 5173)
- **Why Vite over Webpack:** 10-100× faster dev server startup (no bundling in dev mode — uses native ES modules), instant Hot Module Replacement (HMR), Rollup-based production build with tree-shaking
- **Configuration:** `vite.config.js` — WASM MIME types, basic-ssl plugin, proxy setup

### TailwindCSS (v3.3)
- **Full name:** Tailwind CSS — Utility-First CSS Framework
- **Where used:** All frontend styling
- **Why Tailwind over Bootstrap/Material UI:** No pre-built components = no design constraints, utility classes = no CSS file bloat, JIT compiler = only ships CSS you actually use (28KB final), custom design tokens (`cyphra-accent`, `cyphra-bg`, `cyphra-surface`)
- **Custom theme:** Dark military aesthetic with cyan/teal accent colors, custom border/text colors

### Zustand (v4.4)
- **Full name:** Zustand (German for "state") — Lightweight State Management
- **Developer:** Pmndrs (Poimandres collective)
- **Where used:** `src/store/useStore.js` — global application state
- **Why Zustand over Redux:** 10× less boilerplate, no providers/reducers/actions pattern, direct mutations via `set()`, built-in shallow equality checks, 1KB bundle size (Redux Toolkit = 30KB+)
- **State shape:** User auth, messages, contacts, threat level, mission presets, notifications

### Framer Motion (v10.16)
- **Full name:** Framer Motion — Production-Ready Motion Library for React
- **Where used:** Page transitions, card animations, threat timeline entries, modal open/close
- **Why:** Declarative animation API (`initial`, `animate`, `exit`), `AnimatePresence` for exit animations, gesture support, layout animations — all with React component syntax

### Three.js (v0.183)
- **Full name:** Three.js — JavaScript 3D Library (WebGL)
- **Where used:** `WebGLBackground.jsx` — particle animation on landing page
- **Why:** Creates an immersive 3D particle field that responds to mouse movement — military/cybersecurity aesthetic. Only mature WebGL abstraction library with React integration.

### GSAP (v3.14)
- **Full name:** GreenSock Animation Platform
- **Where used:** Landing page scroll-triggered animations, text reveals, badge animations
- **Why GSAP over CSS animations:** Timeline sequencing, ScrollTrigger plugin for scroll-based animations, better performance (uses requestAnimationFrame), works consistently across all browsers

### Lucide React (v0.294)
- **Full name:** Lucide — Beautiful & Consistent Icon Library (fork of Feather Icons)
- **Where used:** All icons throughout the application (navigation, status indicators, buttons)
- **Why Lucide over Font Awesome:** Tree-shakeable (only imports used icons), consistent stroke width, React-native components (not font injection), lighter bundle

### React Router DOM (v6.20)
- **Full name:** React Router — Declarative Routing for React
- **Where used:** Client-side routing (`/`, `/auth`, `/dashboard`, `/messenger`, `/security`, `/defense`)
- **Key patterns:** `BrowserRouter`, `Routes`/`Route`, `Navigate` for redirects, `useNavigate` hook, `ProtectedRoute` HOC wrapper

---

## 3. Backend Technologies

### Node.js (v18+)
- **Full name:** Node.js — JavaScript Runtime Built on Chrome's V8 Engine
- **Where used:** Backend API server (Express), WebSocket relay, signal stats engine
- **Why Node.js:** Native WebSocket support, single-threaded event loop perfect for I/O-heavy relay operations, same language as frontend (shared utilities possible), npm ecosystem

### Express.js (v4.x)
- **Full name:** Express — Fast, Unopinionated, Minimalist Web Framework for Node.js
- **Where used:** HTTP REST API server (port 3001)
- **Why Express:** Most mature Node.js HTTP framework, minimal overhead, middleware pattern (CORS, JSON parsing, logging), route registration order control (critical for 404 handler placement)

### ws (WebSocket library)
- **Full name:** ws — Simple to Use, Blazing Fast, and Thoroughly Tested WebSocket Implementation
- **Where used:** Real-time message relay between clients
- **Why `ws` over Socket.io:** No client-side library dependency (browsers have native WebSocket), no polling fallback overhead, raw WebSocket protocol gives full control over frame types and routing logic

### Axum (v0.7)
- **Full name:** Axum — Ergonomic and Modular Web Framework for Rust
- **Developer:** Tokio team
- **Where used:** Rust crypto REST API server (port 5050)
- **Why Axum over Actix-Web/Rocket:** Built on Tower (same middleware as Tonic gRPC), compile-time route type checking, no macros (plain async functions), guaranteed Tokio compatibility, strongest type safety of all Rust web frameworks

### Tokio (v1.35)
- **Full name:** Tokio — Asynchronous Runtime for Rust
- **Where used:** All async Rust code (server, VedDB client, network operations)
- **Why:** The only production-grade async runtime for Rust. Provides: multi-threaded scheduler, async TCP/UDP, timers, channels, synchronization primitives. Used by Cloudflare, Discord, AWS.

### Tower (v0.4) + Tower-HTTP (v0.5)
- **Full name:** Tower — Modular and Reusable Components for Building Network Applications
- **Where used:** Middleware layer on Axum server (CORS, request tracing)
- **Why:** Standardized middleware interface — same `Service` trait used by Axum, Hyper, Tonic. Composable layers for cross-cutting concerns without framework lock-in.

### FastAPI
- **Full name:** FastAPI — Modern, Fast Web Framework for Building APIs with Python
- **Where used:** ML inference service (port 5002)
- **Why FastAPI over Flask/Django:** Async by default (important for concurrent inference requests), automatic OpenAPI docs, Pydantic validation, type hints, 10× faster than Flask for I/O operations, native async/await support for non-blocking Scapy capture

### Uvicorn
- **Full name:** Uvicorn — Lightning-Fast ASGI Server
- **Where used:** Serves the FastAPI application
- **Why:** ASGI (Asynchronous Server Gateway Interface) — handles thousands of concurrent connections without threading. Based on `uvloop` (Cython wrapper around libuv).

---

## 4. Machine Learning Stack

### GhostML Framework (Custom, Rust)
- **What:** In-house machine learning framework implementing core ML algorithms from scratch in Rust
- **Crates:** ghost-core (tensors, metrics), ghost-trees (decision trees, random forest), ghost-ensemble (bagging, boosting, voting, stacking), ghost-neural (dense layers, backpropagation), ghost-optimizer (SGD, Adam), ghost-preprocessing (StandardScaler, encoding), ghost-sampling (SMOTE, stratified split), ghost-python (PyO3 bindings)
- **Role:** Provides the ML pipeline orchestration layer — data preprocessing, feature engineering, model evaluation, and ensemble aggregation. Calls into GPU-optimized training backends for maximum throughput on 19.5M samples.
- **Why custom framework:** Demonstrates deep understanding of ML internals (tree construction, gradient computation, backpropagation), enables custom optimizations, zero dependency on external Python ML ecosystems for preprocessing logic.

### LightGBM (v4.6)
- **Full name:** Light Gradient Boosting Machine
- **Developer:** Microsoft Research
- **Where used:** 3 model variants (LGBM_Deep: 1500 trees, LGBM_Wide: 1000 trees, LGBM_Fast: 600 trees)
- **Why LightGBM:** Histogram-based splitting (bins features into 255 buckets) = 10× faster than exact methods. Leaf-wise growth (grows the leaf with highest loss reduction) = better accuracy with fewer trees. Native multi-threading (uses all 32 CPU threads). Handles 19.5M samples without OOM.
- **Key parameters:** `is_unbalance=True` (handles 80/20 class ratio), `early_stopping_rounds=50`, `binary_logloss` metric

### XGBoost (v3.2)
- **Full name:** eXtreme Gradient Boosting
- **Developer:** DMLC (Distributed Machine Learning Community)
- **Where used:** 2 model variants (XGB_Deep: 1200 trees, XGB_Balanced: 800 trees)
- **Why XGBoost:** L1 + L2 regularization on leaf weights (prevents overfitting), GPU CUDA acceleration (`device="cuda"`), built-in handling of sparse data, column subsampling. Provides complementary error patterns to LightGBM (level-wise vs leaf-wise growth).
- **GPU training:** `tree_method="hist", device="cuda"` — histogram construction + split finding on GPU. RTX 5070 Ti 12GB handles the full 19.5M dataset (previous RTX 4060 8GB failed with OOM).

### CatBoost (v1.2)
- **Full name:** Categorical Boosting
- **Developer:** Yandex
- **Where used:** 1 model (CatBoost_Deep: 1500 iterations)
- **Why CatBoost:** Ordered Target Statistics for handling categorical features (avoids target leakage), symmetric tree structure (all nodes at same depth split on same feature = faster inference), built-in GPU training, lowest overfitting of all three frameworks. Provides the most diverse error pattern in the ensemble.
- **GPU training:** `task_type='GPU', devices='0'` — fits in 6GB GPU memory (uses efficient pool-based allocation)

### Soft-Voting Ensemble
- **What:** Final prediction = arithmetic mean of all 6 model probabilities
- **Formula:** `threat_score = (lgbm_deep + lgbm_wide + lgbm_fast + xgb_deep + xgb_balanced + catboost) / 6`
- **Why soft voting over stacking:** When base models are all >98.8% accuracy with correlated errors, simple averaging cancels individual mistakes better than a meta-learner that can overfit to validation fold patterns. Empirically: soft voting (98.852%) > stacking with LogisticRegression (98.560%).

### Scapy
- **Full name:** Scapy — Packet Manipulation Library
- **Where used:** Live packet capture from network interface (Npcap driver)
- **Why Scapy over tcpdump/tshark:** Python-native (integrates directly with ML pipeline), per-packet callbacks, raw access to all protocol fields (IP, TCP, UDP headers), no intermediate PCAP file needed, real-time processing

### Npcap
- **Full name:** Nmap Packet Capture (successor to WinPcap)
- **Where used:** Windows kernel driver for raw packet access
- **Why needed:** Windows doesn't expose raw sockets to userspace applications. Npcap provides a kernel driver that captures packets before the TCP/IP stack processes them. Required for Scapy to function on Windows.

### scikit-learn (v1.9)
- **Full name:** scikit-learn — Machine Learning in Python
- **Where used:** `StandardScaler` (feature normalization), `StratifiedShuffleSplit` (train/test splitting), metrics (accuracy, precision, recall, F1, confusion matrix)
- **Why:** Industry standard for data preprocessing and evaluation. StandardScaler ensures features are on the same scale (mean=0, std=1) before tree models process them.

### NumPy (v2.4)
- **Full name:** Numerical Python
- **Where used:** Array operations throughout ML pipeline — feature vectors, model predictions, scaling
- **Why:** Foundation of all Python numerical computing. Provides contiguous memory arrays (critical for passing data to LightGBM/XGBoost C++ backends) and vectorized operations (100× faster than Python loops).

### CICFlowMeter (Feature Specification)
- **Full name:** Canadian Institute for Cybersecurity Flow Meter
- **What:** Not a library — it's a feature specification. Defines 80+ bidirectional network flow features.
- **Where used:** Our `packet_capture.py` computes 100 CICFlowMeter-compatible features per flow
- **Why CICFlowMeter features:** All 4 training datasets (CICIDS2017, UNSW-NB15, ISCXVPN2016, CSE-CICIDS2018) use this feature format. Training and inference MUST use the same features for the model to work correctly.

---

## 5. Cryptographic Technologies

### AES-256-GCM
- **Full name:** Advanced Encryption Standard, 256-bit key, Galois/Counter Mode
- **Standard:** NIST FIPS 197 + SP 800-38D
- **Where used:** All message encryption (browser via Rust WASM, Android via Keystore)
- **Why AES-256-GCM over ChaCha20-Poly1305 in browser:** Hardware AES-NI instructions on all modern CPUs make AES faster than ChaCha20 on x86. GCM provides authenticated encryption (integrity + confidentiality) in a single operation.
- **Parameters:** 256-bit key, 96-bit nonce (random per message), 128-bit authentication tag

### XChaCha20-Poly1305
- **Full name:** Extended ChaCha20 stream cipher + Poly1305 MAC
- **Where used:** Double Ratchet AEAD encryption (native Rust, server-side)
- **Why XChaCha20 on server (not AES):** 192-bit nonce (vs 96-bit for AES-GCM) eliminates nonce collision risk for long-lived sessions. libsodium's default AEAD cipher. Critical for Double Ratchet where thousands of messages use the same root key.

### X25519 (Curve25519 ECDH)
- **Full name:** Elliptic Curve Diffie-Hellman on Curve25519
- **Standard:** RFC 7748
- **Where used:** Key exchange in WASM (browser) and native (server)
- **Why X25519 over ECDH-P256:** Constant-time by design (no side-channel leaks), smaller keys (32 bytes vs 65), faster computation, simpler implementation (single-coordinate ladder), no NIST-curve trust concerns

### Ed25519
- **Full name:** Edwards-Curve Digital Signature Algorithm on Edwards25519
- **Standard:** RFC 8032
- **Where used:** Message signing + signature verification
- **Why Ed25519 over ECDSA-P256:** Deterministic signatures (no random nonce needed = no nonce-reuse attacks), faster verification, batch verification support, same key size (32 bytes)

### Kyber-1024 (ML-KEM-1024)
- **Full name:** Module-Lattice Key Encapsulation Mechanism, Security Level 5
- **Standard:** NIST FIPS 203 (standardized August 2024)
- **Where used:** Post-quantum key exchange in native Rust server (X3DH protocol)
- **Why Kyber over NTRU/SABER:** NIST's chosen standard (eliminates standardization risk), fastest of all PQC finalists, smallest ciphertexts in its security category, mature implementation in `pqc_kyber` Rust crate
- **Why Level 5 (1024) over Level 1 (512):** Defence-grade requirement — equivalent to AES-256 classical security. Larger keys (1184 bytes public) but maximum quantum resistance.

### BLAKE3
- **Full name:** BLAKE3 Cryptographic Hash Function
- **Where used:** Key derivation (HKDF-BLAKE3), session key computation, Double Ratchet chain advancement
- **Why BLAKE3 over SHA-256:** 3× faster on single core, parallelizable across cores (Merkle tree structure), derived from SHA-3 finalist (BLAKE2), `derive_key()` function provides built-in domain separation

### HKDF (two variants)
- **Full name:** HMAC-based Key Derivation Function
- **Standard:** RFC 5869
- **Where used:** 
  - HKDF-SHA256: Browser (WASM) for DEK derivation and ratchet advancement
  - HKDF-BLAKE3: Server (native Rust) for X3DH root/chain key derivation
- **Why HKDF over raw hashing:** Two-phase (Extract + Expand) ensures output keys are indistinguishable from random even if input key material has structure. Domain separation via `info` parameter prevents cross-protocol key reuse.

### PBKDF2
- **Full name:** Password-Based Key Derivation Function 2
- **Standard:** NIST SP 800-132
- **Where used:** Password hashing in `auth.service.js` (100,000 iterations, SHA-256)
- **Why PBKDF2 over bcrypt/Argon2:** Web Crypto API only supports PBKDF2 natively. 100,000 iterations provides ~200ms computation time (brute-force resistant). In production, Argon2id would be preferred (memory-hard), but browser API limitation forces PBKDF2.

### SHA-256
- **Full name:** Secure Hash Algorithm, 256-bit (SHA-2 family)
- **Standard:** NIST FIPS 180-4
- **Where used:** User ID derivation (SHA-256 of email), audit log chain, password hashing salt, PBKDF2 PRF
- **Why SHA-256 for user IDs:** Deterministic (same email always = same ID), collision-resistant (no two emails produce same ID), one-way (can't reverse ID to email), fixed length (64 hex chars regardless of email length)

### libsodium (v0.2, via libsodium-sys)
- **Full name:** Sodium Crypto Library (portable, cross-platform NaCl fork)
- **Where used:** Native Rust crates (X25519, Ed25519, XChaCha20-Poly1305, random bytes)
- **Why libsodium:** Audited by multiple security firms, constant-time implementations (timing-attack resistant), misuse-resistant API design, cross-platform (Windows/Linux/macOS), FIPS-ready

### wasm-bindgen (v0.2)
- **Full name:** WebAssembly Binding Generator for Rust
- **Where used:** Bridge between Rust WASM and JavaScript
- **Why:** Only production-grade way to expose Rust functions to JavaScript in the browser. Generates TypeScript definitions, handles memory allocation between JS heap and WASM linear memory, supports complex types (strings, arrays, Result types).

### getrandom (v0.2, `js` feature)
- **Full name:** getrandom — Interface to the Operating System's Random Number Generator
- **Where used:** WASM crate (cryptographic random bytes in the browser)
- **Why `js` feature:** In WASM, there's no OS-level RNG. The `js` feature delegates to `crypto.getRandomValues()` in the browser — the only CSPRNG available in WebAssembly.

---

## 6. Database Technologies

### VedDB (Custom, v0.2.0)
- **Full name:** VedDB — Vector-Enhanced Database (Hybrid Document Database with Redis-like Caching)
- **Where used:** Persistent storage for all user accounts, messages, contacts, Ghost Code mappings
- **Why custom DB over PostgreSQL/MongoDB:**
  1. End-to-end encryption at the storage level (data encrypted before write)
  2. Custom binary protocol (no plaintext SQL queries on the wire)
  3. Built-in pub/sub (could replace WebSocket relay in future)
  4. Zero external dependency (single `.exe` binary, no installation)
  5. TLS 1.3 native (encrypted client-server communication)
  6. Sub-millisecond key-value operations (in-memory with persistence)
- **Protocol:** Custom binary frame format (16-byte header + JSON/binary payload)
- **Client:** Async Rust library with connection pooling (veddb-cyphra/)
- **Fallback:** In-memory `Map` if server is unavailable (graceful degradation)

### TLS 1.3 (rustls)
- **Full name:** Transport Layer Security version 1.3
- **Library:** rustls (pure-Rust TLS implementation)
- **Where used:** VedDB client-server encryption
- **Why rustls over OpenSSL:** Pure Rust (no C memory bugs), modern-only (no legacy cipher suites), constant-time implementations, smaller attack surface

---

## 7. Networking & Protocols

### WebSocket (RFC 6455)
- **Full name:** WebSocket Protocol
- **Where used:** Real-time message delivery, read receipts, delete broadcasts, padding traffic
- **Why WebSocket over HTTP polling/SSE:** Full-duplex (both directions simultaneously), persistent connection (no reconnect overhead per message), native browser API, sub-100ms latency

### X3DH Protocol
- **Full name:** Extended Triple Diffie-Hellman
- **Origin:** Signal Protocol (Open Whisper Systems)
- **Where used:** Session establishment between two parties
- **Why X3DH:** Enables session creation even when recipient is offline (using prekey bundles). Provides: mutual authentication, forward secrecy, deniability. CYPHRA's version adds Kyber-1024 for post-quantum resistance.

### Double Ratchet Protocol
- **Full name:** Double Ratchet Algorithm (formerly Axolotl Ratchet)
- **Origin:** Signal Protocol
- **Where used:** Per-message key derivation (every message uses a unique key)
- **Why:** Forward secrecy (compromise of one key doesn't reveal past messages), post-compromise security (session recovers after a DH ratchet step), out-of-order message handling (skipped keys stored temporarily)

### Mixnet (Onion Routing)
- **What:** Multi-hop relay network where each node peels one encryption layer
- **Where used:** `web-app/mixnet/relay.js` — 5 independent relay processes (ports 6001-6005)
- **Why:** Metadata protection — even if all traffic is captured, an observer cannot link sender to recipient. Only adjacent hops are visible. Used when mission preset requires maximum anonymity.

### TCP RST Injection
- **What:** Sending crafted TCP Reset packets to terminate a malicious connection
- **Where used:** Tier 2 auto-response engine
- **Why:** Faster than firewall rules (sub-second termination), doesn't require admin privileges on some configurations, works for active connections that a firewall rule wouldn't affect retroactively

---

## 8. Mobile Technologies

### Jetpack Compose
- **Full name:** Jetpack Compose — Android's Modern Toolkit for Building Native UI
- **Developer:** Google
- **Where used:** All Android UI (4 screens: Login, ChatList, Chat, Settings)
- **Why Compose over XML Views:** Declarative (describe what UI should look like, not how to build it), reactive (UI auto-updates when state changes), 50% less code than XML + Adapters, built-in animation support, better type safety

### Material3 (Material Design 3)
- **Full name:** Material Design 3 — Google's Design System
- **Where used:** Android app theme, colors, typography, components
- **Why M3:** Dynamic color theming, updated component library, built-in dark mode support, accessibility compliant out of the box

### OkHttp
- **Full name:** OkHttp — HTTP Client for Android and Java
- **Developer:** Square
- **Where used:** REST API calls + WebSocket connection in Android app
- **Why OkHttp:** Connection pooling, transparent GZIP, response caching, WebSocket support (same library for HTTP + WS), certificate pinning support, 30-second configurable timeouts

### Android Keystore
- **Full name:** Android Keystore System
- **Where used:** AES-256-GCM key generation and storage (hardware-backed)
- **Why Keystore over software crypto:** Keys generated and stored inside TEE (Trusted Execution Environment) or StrongBox (separate security chip). Keys NEVER leave the hardware — even root access cannot extract them. Encryption/decryption happens inside the secure enclave.

### Gson
- **Full name:** Google Gson — Java JSON Serialization Library
- **Where used:** JSON parsing in Android (API responses, WebSocket messages)
- **Why Gson over Moshi/kotlinx.serialization:** Zero code generation (faster builds), works with Java and Kotlin, handles generic types, mature and battle-tested

### Progressive Web App (PWA)
- **Full name:** Progressive Web Application
- **Standard:** W3C Web App Manifest + Service Workers
- **Where used:** `cyphra-pwa/` — iOS alternative without App Store
- **Why PWA for iOS:** Apple doesn't allow sideloading APKs. PWAs install from Safari via "Add to Home Screen" — full-screen, custom icon, offline capable. No developer account fee ($99/yr) required.

### Service Worker
- **Full name:** Service Worker API (W3C)
- **Where used:** `cyphra-pwa/sw.js` — offline caching, background sync
- **Why:** Intercepts network requests, serves cached responses when offline, enables "Add to Home Screen" install prompt, background message processing

---

## 9. DevOps & Build Tools

### Cargo (Rust Build System)
- **Full name:** Cargo — Rust's Package Manager and Build System
- **Where used:** All Rust compilation (8 library crates + WASM crate + server)
- **Why:** Only build system for Rust. Handles dependency resolution, compilation, testing, benchmarking, and publishing to crates.io.

### wasm-pack
- **Full name:** wasm-pack — Build, Pack, and Publish Rust-Generated WebAssembly
- **Where used:** Compiling `cyphra-wasm` crate to `.wasm` binary
- **Why:** Only tool that produces browser-compatible WASM from Rust with proper JS bindings, TypeScript definitions, and package.json. Handles `wasm-bindgen` glue code generation.

### npm (Node Package Manager)
- **Full name:** npm — Node Package Manager
- **Where used:** Frontend dependency management, script running
- **Why:** Standard for JavaScript ecosystem. `package.json` defines all dependencies with exact versions.

### Gradle (v8.7)
- **Full name:** Gradle Build Tool
- **Where used:** Android APK compilation
- **Why Gradle:** Only build system for Android (Google's requirement). Handles Kotlin compilation, resource processing, APK signing, ProGuard minification.

### ADB (Android Debug Bridge)
- **Full name:** Android Debug Bridge
- **Where used:** APK installation on physical device via USB
- **Why:** Standard tool for deploying debug builds to connected phones without Android Studio.

### Git
- **Full name:** Git — Distributed Version Control System
- **Where used:** Source code management, team collaboration, branch-based development
- **Branching strategy:** 4 branches (infra, data-ml, backend, frontend) merged to main
- **Remotes:** source (development repo) + destination (production repo)

---

## 10. Security Standards & Compliance

### NIST FIPS 197
- **What:** Advanced Encryption Standard specification
- **Relevance:** AES-256-GCM implementation follows this standard exactly

### NIST SP 800-38D
- **What:** Recommendation for GCM Mode of Operation
- **Relevance:** Defines how GCM authentication tags are computed and verified

### NIST SP 800-132
- **What:** Recommendation for Password-Based Key Derivation
- **Relevance:** PBKDF2 with 100,000 iterations meets this standard's minimum (10,000)

### NIST FIPS 203
- **What:** Module-Lattice Key Encapsulation Mechanism (ML-KEM / Kyber)
- **Relevance:** Kyber-1024 implementation follows the finalized NIST standard

### RFC 7748
- **What:** Elliptic Curves for Security (X25519, X448)
- **Relevance:** X25519 key exchange implementation follows this specification

### RFC 8032
- **What:** Edwards-Curve Digital Signature Algorithm (Ed25519, Ed448)
- **Relevance:** Ed25519 signature scheme follows this specification

### RFC 5869
- **What:** HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
- **Relevance:** Both HKDF-SHA256 (WASM) and HKDF-BLAKE3 (native) follow the Extract-Expand pattern

### RFC 6455
- **What:** The WebSocket Protocol
- **Relevance:** All real-time communication follows WebSocket framing specification

### W3C Web Cryptography API
- **What:** Browser-native cryptographic operations specification
- **Relevance:** Fallback crypto (when WASM unavailable) uses this API exclusively

---

## Summary Statistics

| Category | Count |
|----------|-------|
| Programming Languages | 5 (Rust, Python, JavaScript, Kotlin, HTML/CSS) |
| Frontend Libraries | 9 (React, Vite, Tailwind, Zustand, Framer Motion, Three.js, GSAP, Lucide, React Router) |
| Backend Frameworks | 5 (Express, ws, Axum, Tokio, FastAPI) |
| ML Frameworks | 4 (GhostML, LightGBM, XGBoost, CatBoost) |
| Crypto Algorithms | 11 (AES-GCM, XChaCha20, X25519, Ed25519, Kyber-1024, BLAKE3, HKDF, PBKDF2, SHA-256, X3DH, Double Ratchet) |
| Networking Protocols | 5 (WebSocket, TCP, TLS 1.3, HTTP/REST, Mixnet/Onion) |
| Security Standards | 9 (FIPS 197, SP800-38D, SP800-132, FIPS 203, RFC 7748, 8032, 5869, 6455, W3C WebCrypto) |
| **Total Technologies** | **48+** |

---

*CYPHRA — Every component chosen for a specific technical reason. Zero bloat. Zero redundancy.*


---

## 11. Detailed Algorithm Implementations

### 11.1 AES-256-GCM — Complete Internal Mechanics

**AES (Advanced Encryption Standard)** operates on 128-bit (16-byte) blocks using a 256-bit key through 14 rounds of transformation.

#### Key Expansion

The 256-bit key is expanded into 15 round keys (each 128 bits) through the Rijndael Key Schedule:

```
Original Key (256 bits) → 15 × 128-bit Round Keys

Steps per round:
  1. RotWord: Rotate last 4 bytes of previous round key
  2. SubBytes: Apply S-box substitution to each byte
  3. XOR with round constant (Rcon)
  4. XOR with bytes from 4 positions earlier
```

#### Encryption Rounds (14 rounds for AES-256)

```
Round 0:    AddRoundKey (XOR plaintext with round key 0)

Rounds 1-13:
  Step 1: SubBytes    — Non-linear substitution (16×16 S-box lookup)
  Step 2: ShiftRows   — Cyclic left shift of rows (0,1,2,3 positions)
  Step 3: MixColumns  — Matrix multiplication in GF(2⁸)
  Step 4: AddRoundKey — XOR with round key

Round 14:
  Step 1: SubBytes
  Step 2: ShiftRows
  Step 3: AddRoundKey (no MixColumns in final round)
```

#### GCM (Galois/Counter Mode)

GCM combines CTR mode encryption with GHASH authentication:

```
CTR Mode (Confidentiality):
  Counter₀ = Nonce || 0x00000001
  For each 128-bit block i:
    Encrypted_Counterᵢ = AES(Key, Counter₀ + i)
    Ciphertextᵢ = Plaintextᵢ ⊕ Encrypted_Counterᵢ

GHASH (Authentication):
  H = AES(Key, 0¹²⁸)  — Hash subkey
  
  Tag = GHASH(H, AAD, Ciphertext) ⊕ AES(Key, Counter₀)
  
  Where GHASH is multiplication in GF(2¹²⁸) Galois field:
    Xᵢ = (Xᵢ₋₁ ⊕ Blockᵢ) × H  (in GF(2¹²⁸))
```

#### Why AES-256-GCM specifically for CYPHRA:

| Alternative | Why NOT chosen |
|---|---|
| AES-128-GCM | 128-bit key insufficient for military-grade (NIST recommends 256 for TOP SECRET) |
| AES-256-CBC | No authentication — attacker can modify ciphertext without detection (padding oracle attacks) |
| AES-256-CTR | Provides confidentiality but no integrity — same issue as CBC |
| ChaCha20-Poly1305 | No hardware AES-NI acceleration in browsers — 2× slower on x86 CPUs |
| 3DES | Deprecated, 64-bit block size causes birthday bound issues at 2³² blocks |

#### CYPHRA Implementation (Rust WASM):

```rust
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};

pub fn aes_gcm_encrypt(key_bytes: &[u8], plaintext: &[u8]) -> Result<String, JsValue> {
    // key_bytes MUST be exactly 32 bytes (256 bits)
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    
    // Generate 12-byte (96-bit) random nonce — NEVER reuse with same key
    let mut nonce_bytes = [0u8; 12];
    getrandom(&mut nonce_bytes)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // Encrypt: output = ciphertext || 16-byte auth tag
    let ciphertext = cipher.encrypt(nonce, plaintext)?;
    
    // Return hex-encoded JSON
    Ok(format!(r#"{{"ciphertext":"{}","nonce":"{}"}}"#,
        hex::encode(&ciphertext), hex::encode(&nonce_bytes)))
}
```

**Security properties achieved:**
- **Confidentiality:** Ciphertext reveals nothing about plaintext (IND-CPA secure)
- **Integrity:** Any modification to ciphertext invalidates the tag (INT-CTXT secure)
- **Authenticity:** Tag proves the message was created by someone with the key
- **Nonce misuse:** If nonce repeats, confidentiality is lost but authenticity remains

---

### 11.2 X25519 ECDH — Mathematical Foundation

#### Curve25519 Definition

The curve is defined by the Montgomery equation:
```
y² = x³ + 486662x² + x    (mod p, where p = 2²⁵⁵ - 19)
```

**Field:** F_p where p = 2²⁵⁵ - 19 = 57896044618658097711785492504343953926634992332820282019728792003956564819949

**Base point G:** x-coordinate = 9 (the standard generator point)

**Group order:** n = 2²⁵² + 27742317777372353535851937790883648493

#### Key Generation

```
Private key (scalar): 32 random bytes with clamping:
  - Clear bits 0, 1, 2 (ensures multiple of 8 — avoids small-subgroup attacks)
  - Clear bit 255 (ensures < p)
  - Set bit 254 (ensures constant-time ladder)
  
  Clamped: key[0] &= 248; key[31] &= 127; key[31] |= 64;

Public key: scalar × G (scalar multiplication of base point)
  = result x-coordinate only (32 bytes, Montgomery form)
```

#### Diffie-Hellman Exchange

```
Alice:
  a = random_scalar()  (private)
  A = a × G            (public)

Bob:
  b = random_scalar()  (private)
  B = b × G            (public)

Shared secret (both compute same value):
  Alice: shared = a × B = a × (b × G) = ab × G
  Bob:   shared = b × A = b × (a × G) = ab × G
```

#### Montgomery Ladder (Constant-Time Implementation)

```
The scalar multiplication uses a Montgomery ladder to prevent timing attacks:

For each bit of scalar (from MSB to LSB):
  if bit == 1:
    R₀ = double(R₀)
    R₁ = add(R₀, R₁)
  else:
    R₁ = double(R₁)
    R₀ = add(R₀, R₁)

Key property: SAME number of operations regardless of scalar value
→ No timing side-channel leaks
```

#### Why X25519 over NIST P-256:

| Property | X25519 | P-256 |
|---|---|---|
| Side-channel resistance | Inherent (Montgomery ladder) | Requires careful implementation |
| Key size | 32 bytes | 33 bytes (compressed) or 65 (uncompressed) |
| Speed | ~50,000 ops/sec | ~20,000 ops/sec |
| Trust | Designed by DJB (transparent) | NIST curve (NSA involvement concerns) |
| Implementation complexity | Simple (single formula) | Complex (multiple formulas needed) |
| Twist security | Yes (safe against invalid-curve attacks) | No (requires point validation) |

---

### 11.3 Kyber-1024 — Lattice Cryptography Deep Dive

#### The MLWE Problem (Module Learning With Errors)

Kyber's security is based on the hardness of MLWE:

```
Given:
  A ∈ R_q^(k×k)     — public random matrix (polynomial ring)
  s ∈ R_q^k           — secret vector (small coefficients)
  e ∈ R_q^k           — error/noise vector (small coefficients)
  
  b = A·s + e         — public key (matrix-vector multiply + noise)

Challenge: Given (A, b), find s.

Hardness: No known algorithm (classical or quantum) can solve this 
          efficiently when the noise distribution is appropriately chosen.
```

**Ring structure:** R_q = Z_q[X] / (X^n + 1) where n = 256, q = 3329

This means all operations happen in a polynomial ring modulo X²⁵⁶ + 1, with coefficients modulo 3329.

#### Key Generation

```
KEM.KeyGen():
  1. Sample random matrix A ∈ R_q^(4×4) (4 because Kyber-1024 uses k=4)
  2. Sample secret s ← CBD₂(seed)  (Centered Binomial Distribution, η=2)
  3. Sample error e ← CBD₂(seed')
  4. Compute t = A·s + e   (NTT-domain multiplication for speed)
  5. Public key pk = (t, ρ)  where ρ is seed for regenerating A
  6. Secret key sk = (s, pk, H(pk), z)
  
  Sizes: pk = 1568 bytes, sk = 3168 bytes (Kyber-1024 internal)
  Our API: pk = 1184 bytes, sk = 2400 bytes (pqc_kyber crate format)
```

#### Encapsulation (Sender)

```
KEM.Encaps(pk):
  1. Generate random message m ← {0,1}²⁵⁶
  2. (K̄, r) = G(m || H(pk))   — deterministic randomness from message
  3. Sample r₁, r₂, e₁ ← CBD using r as seed
  4. Compute u = Aᵀ·r₁ + e₁   (ciphertext component 1)
  5. Compute v = tᵀ·r₁ + e₂ + ⌈q/2⌋·m   (ciphertext component 2)
  6. Ciphertext ct = Compress(u, v)
  7. Shared secret K = KDF(K̄ || H(ct))
  
  Ciphertext size: 1568 bytes
  Shared secret: 32 bytes
```

#### Decapsulation (Receiver)

```
KEM.Decaps(ct, sk):
  1. Decompress(ct) → (u, v)
  2. m' = Compress(v - sᵀ·u, 1)   — "decrypt" by removing s component
  3. (K̄', r') = G(m' || H(pk))   — re-derive randomness
  4. Re-encrypt: ct' = Encaps(pk, m'; r')
  5. If ct == ct':  return K = KDF(K̄' || H(ct))   ← SUCCESS
     Else:          return K = KDF(z || H(ct))     ← IMPLICIT REJECT
  
  Shared secret: same 32 bytes as sender computed
```

#### Why Quantum Computers Can't Break Kyber:

```
Classical computers:  Can solve MLWE in time 2^n (exponential) — infeasible for n=256
Quantum computers:   Shor's algorithm breaks RSA/ECDH by factoring/discrete-log
                     BUT Shor's does NOT apply to lattice problems
                     Best quantum attack on MLWE: Grover's reduces to 2^(n/2) — still infeasible
                     Kyber-1024 security: ~2¹⁸⁷ operations (quantum) — NIST Level 5
```

#### Kyber-1024 vs Alternatives:

| Algorithm | Type | PK Size | CT Size | Security | NIST Status |
|---|---|---|---|---|---|
| **Kyber-1024** | Lattice (MLWE) | 1,568 B | 1,568 B | Level 5 | **Standardized (FIPS 203)** |
| NTRU-HPS | Lattice (NTRU) | 1,230 B | 1,230 B | Level 5 | Round 3 finalist (not selected) |
| SABER | Lattice (MLWR) | 1,312 B | 1,472 B | Level 5 | Round 3 finalist (not selected) |
| Classic McEliece | Code-based | 261,120 B | 128 B | Level 5 | Round 4 (impractical key size) |

**Why Kyber won:** Smallest combined (pk + ct) size, fastest encapsulation, strongest security proofs, most implementation diversity (many independent implementations verified against each other).

---

### 11.4 Double Ratchet — Complete Protocol Specification

#### Overview

The Double Ratchet combines three cryptographic ratchets:

```
┌─────────────────────────────────────────────┐
│             ROOT RATCHET                     │
│  Advances when new DH keys are exchanged    │
│  Input: DH shared secret + previous root    │
│  Output: new root key + new chain key       │
└─────────────────────┬───────────────────────┘
                      │
          ┌───────────┴───────────┐
          ▼                       ▼
┌─────────────────┐    ┌─────────────────┐
│  SENDING CHAIN   │    │  RECEIVING CHAIN │
│  Advances per    │    │  Advances per    │
│  sent message    │    │  received message│
│                  │    │                  │
│  chain → msg_key │    │  chain → msg_key │
│  chain → next    │    │  chain → next    │
└─────────────────┘    └─────────────────┘
```

#### State

```rust
struct RatchetState {
    root_key: [u8; 32],           // Current root key
    send_chain_key: [u8; 32],     // Sending chain state
    recv_chain_key: [u8; 32],     // Receiving chain state
    send_counter: u32,            // Messages sent in current chain
    recv_counter: u32,            // Messages received in current chain
    dh_self: (PublicKey, SecretKey),   // Our current DH keypair
    dh_remote: PublicKey,              // Their current DH public key
    skipped_keys: HashMap<(u32, u32), [u8; 32]>,  // For out-of-order messages
}
```

#### Symmetric Chain Ratchet (Per-Message)

```
KDF_CK(chain_key):
  message_key  = BLAKE3::derive_key("CYPHRA-MSG-KEY", chain_key)    → 32 bytes
  next_chain   = BLAKE3::derive_key("CYPHRA-CHAIN-KEY", chain_key)  → 32 bytes
  
  Return (message_key, next_chain)
  
  CRITICAL: After derivation, old chain_key is DELETED from memory.
  This provides FORWARD SECRECY — even if current state is compromised,
  past message_keys cannot be derived (one-way function).
```

**In CYPHRA Rust code:**
```rust
fn derive_message_key(&self, chain_key: &[u8; 32]) -> Result<[u8; 32]> {
    Ok(blake3::derive_key("CYPHRA-MSG-KEY", chain_key))
}

fn advance_chain_key(&self, chain_key: &[u8; 32]) -> Result<[u8; 32]> {
    Ok(blake3::derive_key("CYPHRA-CHAIN-KEY", chain_key))
}
```

**In CYPHRA WASM (browser):**
```rust
pub fn ratchet_chain_step(chain_key_hex: &str) -> Result<String, JsValue> {
    let ck = hex::decode(chain_key_hex)?;
    let msg_key_hex = hkdf_sha256(&ck, &[], b"cyphra:msg_key:v1", 32)?;
    let next_ck_hex = hkdf_sha256(&ck, &[], b"cyphra:chain_key:v1", 32)?;
    Ok(format!(r#"{{"message_key":"{}","next_chain_key":"{}"}}"#, msg_key_hex, next_ck_hex))
}
```

#### DH Ratchet (Key Rotation)

```
When Alice receives a message with a NEW DH public key from Bob:

1. dh_output = X25519(alice_private, bob_new_public)   — Diffie-Hellman
2. (root_key', recv_chain) = HKDF(root_key, dh_output, "ratchet-recv")
3. Generate new Alice DH keypair (fresh randomness)
4. dh_output' = X25519(alice_new_private, bob_new_public)
5. (root_key'', send_chain) = HKDF(root_key', dh_output', "ratchet-send")

Update state:
  root_key = root_key''
  send_chain_key = send_chain
  recv_chain_key = recv_chain
  dh_self = (new_public, new_private)
  dh_remote = bob_new_public
```

**Security property:** If an attacker compromises the current state at time T, after ONE DH ratchet step (when Bob sends a new key), all FUTURE messages become secure again. The attacker cannot derive the new DH output without Bob's new private key.

#### Out-of-Order Message Handling

```
Problem: Message #5 arrives before message #4.

Solution: Skip keys and store them temporarily.

When message_number > expected:
  for i in expected..message_number:
    skipped_key = derive_message_key(chain)
    store(skipped_key, index=i)
    chain = advance_chain(chain)
  
  Now decrypt message #5 with current key.
  When #4 arrives later, try all skipped_keys.

Safety limit: MAX_SKIP = 1000
  If gap > 1000 messages → reject (prevents DoS via memory exhaustion)
```

#### Message Encryption (AEAD)

```
Encrypt(state, plaintext):
  1. msg_key = derive_message_key(send_chain_key)
  2. send_chain_key = advance_chain_key(send_chain_key)
  3. nonce = random(24 bytes)  — XChaCha20 uses 192-bit nonce
  4. ciphertext = XChaCha20-Poly1305.Encrypt(msg_key, nonce, plaintext)
  5. header = (dh_public, send_counter, previous_chain_length)
  6. send_counter++
  7. DELETE msg_key from memory
  
  Output: (header, nonce || ciphertext || auth_tag)
```

#### Why Double Ratchet over Static Key Encryption:

| Property | Static Key | Double Ratchet |
|---|---|---|
| Forward secrecy | ❌ All messages compromised if key leaked | ✅ Only current message exposed |
| Post-compromise security | ❌ Attacker has key forever | ✅ Recovers after 1 DH exchange |
| Key reuse | Same key for all messages | Unique key PER MESSAGE |
| Out-of-order support | ✅ Trivial (same key) | ✅ Via skipped key storage |
| Metadata hiding | ❌ Same key pattern visible | ✅ Keys indistinguishable from random |

---

### 11.5 GhostML — Custom ML Framework Architecture

#### Crate Hierarchy

```
ghostml/
├── ghost-core         ← Foundation: tensors, activation functions, loss functions, metrics
│   ├── matrix.rs      — Dense matrix operations (multiply, transpose, elementwise)
│   ├── activations.rs — ReLU, Sigmoid, Tanh, SELU, Softmax, LeakyReLU
│   ├── losses.rs      — MSE, CrossEntropy, BinaryCrossEntropy, Focal Loss
│   ├── metrics.rs     — Accuracy, Precision, Recall, F1, AUC-ROC, Confusion Matrix
│   ├── types.rs       — Dataset, Sample, Feature, Label type definitions
│   └── optimizers.rs  — SGD, Adam (with momentum, weight decay)
│
├── ghost-preprocessing ← Data preparation
│   ├── StandardScaler — Per-feature normalization: (x - mean) / std
│   ├── MinMaxScaler   — Scale to [0, 1] range
│   ├── LabelEncoder   — Categorical → integer mapping
│   └── OneHotEncoder  — Integer → binary vector
│
├── ghost-sampling      ← Class balancing
│   ├── StratifiedSplit — Maintains class ratio in train/test splits
│   ├── SMOTE          — Synthetic Minority Oversampling (k-NN interpolation)
│   └── ClassWeights   — Inverse frequency weighting for imbalanced data
│
├── ghost-trees         ← Decision tree algorithms
│   ├── DecisionTree   — CART (Classification and Regression Trees)
│   │   ├── Gini impurity splitting criterion
│   │   ├── Information gain (entropy) splitting
│   │   ├── Max depth, min samples per leaf constraints
│   │   └── Feature importance (mean decrease in impurity)
│   └── RandomForest   — Bagging ensemble of decision trees
│       ├── Bootstrap sampling (sampling with replacement)
│       ├── Feature subsampling (√n features per split)
│       └── Majority voting / probability averaging
│
├── ghost-ensemble      ← Ensemble methods
│   ├── Bagging        — Bootstrap Aggregating (parallel trees, voting)
│   ├── Boosting       — Sequential error correction (AdaBoost-style)
│   ├── Voting         — Hard voting (majority) and soft voting (probability mean)
│   └── Stacking       — Meta-learner trained on base model predictions
│
├── ghost-neural        ← Neural network layers
│   ├── Dense          — Fully connected layer (W·x + b)
│   ├── BatchNorm      — Normalize activations (μ=0, σ=1 per batch)
│   ├── Dropout        — Random neuron deactivation (regularization)
│   ├── Forward pass   — Input → layers → output
│   └── Backpropagation — Gradient computation (chain rule)
│
├── ghost-optimizer     ← Training optimization
│   ├── SGD           — Stochastic Gradient Descent (w -= lr × gradient)
│   ├── Adam          — Adaptive Moment Estimation (momentum + RMSprop)
│   │   ├── m = β₁·m + (1-β₁)·gradient      (first moment)
│   │   ├── v = β₂·v + (1-β₂)·gradient²     (second moment)
│   │   └── w -= lr · m̂ / (√v̂ + ε)           (bias-corrected update)
│   └── LR Schedulers — Step decay, cosine annealing, reduce-on-plateau
│
└── ghost-python        ← Python interop
    ├── PyO3 bindings  — `#[pyfunction]` exports to Python
    ├── NumPy bridge   — Direct ndarray ↔ numpy conversion
    └── Module: `import ghostml` in Python scripts
```

#### Role in CYPHRA Pipeline

```
GhostML provides the ML infrastructure layer:

┌──────────────────────────────────────────────────────────┐
│                  GhostML Pipeline                          │
│                                                           │
│  1. Data Loading (ghost-core: Dataset type)               │
│  2. Preprocessing (ghost-preprocessing: StandardScaler)   │
│  3. Sampling (ghost-sampling: StratifiedSplit)            │
│  4. Training Backend Selection:                           │
│     ├── For trees: GPU-optimized C++ backends             │
│     │   (LightGBM histogram, XGBoost GPU, CatBoost GPU)  │
│     └── For neural nets: PyTorch CUDA backend             │
│  5. Ensemble Evaluation (ghost-ensemble: SoftVoting)      │
│  6. Metrics (ghost-core: accuracy, F1, confusion matrix)  │
│                                                           │
└──────────────────────────────────────────────────────────┘
```

The GhostML framework orchestrates the entire pipeline — data flows through Rust preprocessing, gets routed to GPU-optimized training backends for maximum throughput on 19.5M samples, and results are evaluated through GhostML's ensemble and metrics modules.

---

### 11.6 Soft-Voting Ensemble — Mathematical Formulation

#### Problem Setup

Given 6 trained binary classifiers M₁...M₆, each outputting probability P(malicious | features):

```
For a single network flow with feature vector x:

  p₁ = M_LGBM_Deep(x)      ∈ [0, 1]
  p₂ = M_LGBM_Wide(x)      ∈ [0, 1]
  p₃ = M_LGBM_Fast(x)      ∈ [0, 1]
  p₄ = M_XGB_Deep(x)       ∈ [0, 1]
  p₅ = M_XGB_Balanced(x)   ∈ [0, 1]
  p₆ = M_CatBoost_Deep(x)  ∈ [0, 1]
```

#### Soft Voting Formula

```
P_ensemble(malicious | x) = (1/6) × Σᵢ₌₁⁶ pᵢ

Classification:
  if P_ensemble < 0.35 → "Normal" (safe)
  if P_ensemble < 0.55 → "Suspicious" (low)
  if P_ensemble < 0.75 → "Malicious" (medium)
  if P_ensemble ≥ 0.75 → "Critical" (critical)
```

#### Why This Works Better Than Single Models

**Bias-Variance Decomposition:**
```
Error = Bias² + Variance + Irreducible Noise

Single model: High variance (sensitive to training data quirks)
Ensemble:     Lower variance (averaging cancels random errors)

Mathematical proof:
  If each model has error σ² and correlation ρ:
  Ensemble error = ρσ² + (1-ρ)σ²/N
  
  With N=6 models and ρ≈0.7 (correlated but not identical):
  Error reduction ≈ 30% compared to single best model
```

#### Why Soft Voting > Stacking (Empirically)

```
Stacking Meta-Learner (LogisticRegression):
  - Trains on cross-validated predictions of base models
  - Learns optimal weights: w₁p₁ + w₂p₂ + ... + w₆p₆ + bias
  - Result: 98.560% accuracy

Soft Voting (simple mean):
  - No training, no weights, no bias
  - Just: (p₁ + p₂ + p₃ + p₄ + p₅ + p₆) / 6
  - Result: 98.852% accuracy (+0.292% BETTER)

Why stacking lost:
  1. Meta-learner overfit to the validation fold
  2. All base models make same mistakes on same samples (high ρ)
  3. Learned weights: [0.17, 0.16, 0.16, 0.17, 0.17, 0.17] ≈ uniform = soft voting
  4. Bias term shifted decision boundary suboptimally
```

---

### 11.7 Packet Capture — FlowEngine Internals

#### 5-Tuple Flow Identification

```
A "flow" is identified by:
  (src_ip, dst_ip, src_port, dst_port, protocol)

Example:
  (192.168.1.5, 142.250.190.46, 54321, 443, 6)
  = My laptop → Google, ephemeral port → HTTPS, TCP

Bidirectional matching:
  Forward:  (A, B, portA, portB, proto)
  Backward: (B, A, portB, portA, proto)
  Both map to the SAME flow (different direction flags)
```

#### Per-Packet Processing

```python
def _process_packet(self, pkt):
    # 1. Extract IP layer
    ip = pkt[IP]
    proto = ip.proto
    size = len(ip)
    ts = float(pkt.time)
    
    # 2. Extract transport layer
    if proto == 6 (TCP):
        sport, dport = tcp.sport, tcp.dport
        flags = int(tcp.flags)    # FIN=0x01, RST=0x04, PSH=0x08, ACK=0x10, URG=0x20
        win = int(tcp.window)     # TCP window size
    elif proto == 17 (UDP):
        sport, dport = udp.sport, udp.dport
    
    # 3. Lookup or create flow
    key_fwd = (src, dst, sport, dport, proto)
    key_bwd = (dst, src, dport, sport, proto)
    
    if key_fwd in flows → add(forward)
    elif key_bwd in flows → add(backward)
    else → create new flow
    
    # 4. Check eviction conditions
    if FIN or RST flag → evict and emit flow
    
    # 5. Update live counters
    packets_captured++
    bytes_captured += size
```

#### Feature Extraction — All 100 Features

```python
def extract_features(flow):
    # Duration in microseconds
    dur_us = (last_seen - start_time) × 1,000,000
    
    # === PACKET COUNTS (4 features) ===
    total_fwd_packets = len(fwd_packets)
    total_bwd_packets = len(bwd_packets)
    total_fwd_packets_log = log1p(total_fwd_packets)
    total_bwd_packets_log = log1p(total_bwd_packets)
    
    # === BYTE STATISTICS (6 features) ===
    total_length_fwd_packets = sum(fwd_sizes)
    total_length_bwd_packets = sum(bwd_sizes)
    total_bytes = total_length_fwd + total_length_bwd
    # + log transforms of each
    
    # === PACKET LENGTH STATISTICS (8 features) ===
    fwd_pkt_len_mean = mean(fwd_sizes)
    fwd_pkt_len_max = max(fwd_sizes)
    fwd_pkt_len_min = min(fwd_sizes)
    fwd_pkt_len_std = stdev(fwd_sizes)
    # Same 4 for backward direction
    
    # === FLOW RATES (4 features) ===
    flow_bytes_per_sec = total_bytes / duration_seconds
    flow_packets_per_sec = total_packets / duration_seconds
    fwd_packets_per_sec = fwd_count / duration_seconds
    bwd_packets_per_sec = bwd_count / duration_seconds
    
    # === INTER-ARRIVAL TIMES (11 features) ===
    # IAT = time between consecutive packets (in microseconds)
    flow_iat = [t[i+1] - t[i] for all packets merged by timestamp]
    flow_iat_mean, flow_iat_std, flow_iat_max = stats(flow_iat)
    fwd_iat_mean, fwd_iat_std, fwd_iat_min = stats(fwd_iat)
    bwd_iat_total, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min = stats(bwd_iat)
    
    # === TCP FLAGS (7 features) ===
    fin_flag_cnt = count packets with FIN flag
    rst_flag_cnt = count packets with RST flag
    psh_flag_cnt = count packets with PSH flag
    ack_flag_cnt = count packets with ACK flag
    urg_flag_cnt = count packets with URG flag
    fwd_psh_flags = count forward packets with PSH
    fwd_urg_flags = count forward packets with URG
    
    # === WINDOW SIZES (5 features) ===
    init_fwd_win_bytes = first forward packet's TCP window size
    init_bwd_win_bytes = first backward packet's TCP window size
    fwd_seg_size_min = minimum forward packet size
    bwd_header_length = backward_count × 20 (IP header approx)
    init_win_bytes_forward = alias of init_fwd_win_bytes
    
    # === ENGINEERED (13 features) ===
    fwd_packet_fraction = fwd_count / total_count
    fwd_bytes_fraction = fwd_bytes / total_bytes
    payload_ratio = fwd_mean_size / bwd_mean_size
    payload_diff = fwd_mean_size - bwd_mean_size
    iat_cv = flow_iat_std / flow_iat_mean  (coefficient of variation)
    is_well_known_port = 1 if dst_port < 1024
    is_http_port = 1 if dst_port in (80, 443, 8080, 8443)
    is_dns_port = 1 if dst_port == 53
    dst_port_log = log1p(dst_port)
    # + 4 more
    
    # === DATASET ONE-HOT (4 features) ===
    dataset_onehot_0 = 0.0  (live traffic = not from any training dataset)
    dataset_onehot_1 = 0.0
    dataset_onehot_2 = 0.0
    dataset_onehot_3 = 0.0
    
    # Total: 100 features
```

---

### 11.8 StandardScaler — Feature Normalization

#### Why Normalization is Critical

```
Raw feature ranges:
  flow_duration:        0 to 600,000,000 (microseconds)
  total_fwd_packets:    1 to 50,000
  fwd_pkt_len_mean:     0 to 1,500 (bytes)
  dst_port:             0 to 65,535
  
Problem: Tree models split on absolute values.
  A feature with range 0-600M dominates splits over a feature with range 0-1500.
  Even though the small-range feature might be MORE informative.

Solution: StandardScaler transforms each feature to mean=0, std=1:
  x_scaled = (x - μ) / σ
  
After scaling:
  All features have comparable magnitudes
  Tree models evaluate all features fairly
```

#### Fitting (Training Time Only)

```python
scaler = StandardScaler()
scaler.fit(X_train)  # Computes μ and σ for each of 100 features

# Stored values (saved to scaler.pkl):
scaler.mean_    = [μ₁, μ₂, ..., μ₁₀₀]    # 100 means
scaler.scale_   = [σ₁, σ₂, ..., σ₁₀₀]    # 100 standard deviations

# CRITICAL: Only fit on TRAINING data
# Test data and live inference use the SAME μ and σ from training
# This prevents data leakage (test statistics don't influence scaling)
```

#### Inference-Time Scaling (with Clipping)

```python
def _scale(val: float, fname: str) -> float:
    params = scaler[fname]  # {center: μ, scale: σ}
    scaled = (val - params["center"]) / params["scale"]
    return clip(scaled, -10.0, +10.0)  # Prevent extreme outliers
    
# Why clip at ±10?
# An attack flow might have total_fwd_packets = 500,000
# With μ=100, σ=200: scaled = (500000-100)/200 = 2500
# This extreme value would dominate all tree splits
# Clipping to ±10 keeps it "very high" without destabilizing
```

---

### 11.9 Autonomous Response — Complete Decision Logic

#### Flow Processing Pipeline

```
For every completed network flow:

_on_flow_complete(features):
  │
  ├─ Build 100-feature vector
  ├─ Scale with StandardScaler (clip ±10)
  ├─ Run 6-model inference (soft vote)
  ├─ Get threat_score ∈ [0.0, 1.0]
  │
  ├─ IF score ≥ 0.92 (TIER 1):
  │   ├─ Check whitelist (127.0.0.1, ::1)
  │   ├─ Check if already blocked
  │   ├─ Execute: netsh advfirewall firewall add rule
  │   │   name="CYPHRA_BLOCK_{ip}" dir=in action=block remoteip={ip}
  │   ├─ Log: T1_FW_BLOCK
  │   ├─ Schedule: auto-unblock in 300 seconds
  │   └─ Store: blocked_ips[ip] = {tier:1, ts, score, attack_type}
  │
  ├─ ELIF score ≥ 0.80 (TIER 2):
  │   ├─ Verify protocol == TCP (6)
  │   ├─ Craft 10 RST packets (5 seq guesses × 2 directions)
  │   ├─ Send via Scapy raw socket
  │   ├─ Log: T2_RST
  │   ├─ Check T3 escalation: if 3+ hits in 60s → apply T1
  │   └─ Store: blocked_ips[ip] = {tier:2, ts, score}
  │
  ├─ ELIF score ≥ 0.65 (TIER 3):
  │   ├─ Append (timestamp, score) to per-IP history
  │   ├─ Count detections in last 60 seconds
  │   ├─ IF count ≥ 3 → ESCALATE to Tier 1
  │   ├─ Log: T3_TRACK (hit N/3 in window)
  │   └─ No immediate action (tracking only)
  │
  └─ ELSE (score < 0.65):
      └─ Normal traffic — no action
```

#### Auto-Unblock Background Thread

```python
# Runs continuously in a daemon thread
def _unblock_loop(self):
    while True:
        time.sleep(30)  # Check every 30 seconds
        now = time.time()
        
        expired = [ip for ip, info in self.blocked.items()
                   if info["auto_unblock_at"] and now >= info["auto_unblock_at"]]
        
        for ip in expired:
            # Remove Windows Firewall rule
            subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                           f"name=CYPHRA_BLOCK_{ip.replace('.','_')}"])
            
            # Remove from tracking
            del self.blocked[ip]
            
            # Log
            self._log_action("AUTO_UNBLOCKED", ip, ...)
```

---

### 11.10 Signal Stats Engine — Hardware Telemetry Collection

#### Data Collection Flow (Every 6 Seconds)

```
┌─────────────────────────────────────────────────────────────┐
│  _collectSignalStats() — runs every 6 seconds               │
│                                                              │
│  Source 1: netsh wlan show interfaces                        │
│  ├─ Regex: /Signal\s*:\s*(\d+)%/       → signal_pct (0-100) │
│  ├─ Regex: /\bSSID\s*:\s*(.+)/         → ssid               │
│  ├─ Regex: /BSSID\s*:\s*([\da-f:]+)/   → bssid              │
│  ├─ Regex: /Channel\s*:\s*(\d+)/       → channel            │
│  └─ Regex: /Radio type\s*:\s*(.+)/     → radio_type         │
│                                                              │
│  Derived: signal_dbm = -100 + (signal_pct/100) × 50         │
│           noise_floor = -95 dBm (2.4GHz) or -90 (5GHz)      │
│           snr_db = max(0, signal_dbm - noise_floor)          │
│                                                              │
│  Source 2: route print 0.0.0.0                               │
│  └─ Regex: /0\.0\.0\.0\s+0\.0\.0\.0\s+([\d.]+)/  → gateway │
│                                                              │
│  Source 3: ping -n 4 {gateway}                               │
│  ├─ Regex: /[Tt]ime[=<](\d+)\s*ms/g  → rtt_samples[]        │
│  ├─ latency_ms = mean(rtt_samples)                           │
│  ├─ jitter_ms = sqrt(variance(rtt_samples))                  │
│  └─ packet_loss_pct = (4 - len(rtt_samples)) / 4 × 100      │
│                                                              │
│  Source 4: w32tm /query /status                              │
│  └─ Regex: /Phase Offset\s*:\s*(-?[\d.]+)s/                 │
│     → timing_drift_ms = offset × 1000                        │
│                                                              │
│  Source 5: GET http://127.0.0.1:5002/realtime/feed?limit=30  │
│  ├─ Extract flow completion timestamps                        │
│  ├─ Compute IAT coefficient of variation (beaconing metric)  │
│  ├─ Compute mean bytes_per_packet                            │
│  └─ Detect RST spike (>30% high-threat in recent flows)      │
│                                                              │
│  Output: Cached in _signalCache, served via GET /api/signal/stats│
└─────────────────────────────────────────────────────────────┘
```

---

## 12. Training Data — Detailed Dataset Analysis

### 12.1 CICIDS2017 — Intrusion Detection Dataset

| Property | Value |
|----------|-------|
| Publisher | Canadian Institute for Cybersecurity, University of New Brunswick |
| Year | 2017 |
| Duration | 5 days (Monday–Friday) |
| Total Flows | ~2,830,743 |
| Benign | ~2,273,097 (80.3%) |
| Malicious | ~557,646 (19.7%) |
| Features | 78 original CICFlowMeter features |
| File Format | CSV (one file per day) |

**Attack breakdown:**
| Day | Attack | Flows |
|-----|--------|-------|
| Tuesday | FTP-Patator, SSH-Patator | ~13,800 |
| Wednesday | DoS Slowloris, DoS SlowHTTPTest, DoS Hulk, DoS GoldenEye, Heartbleed | ~252,600 |
| Thursday | Web Attack (Brute Force, XSS, SQL Injection), Infiltration | ~9,500 |
| Friday | Botnet (ARES), Port Scan, DDoS (LOIT) | ~281,700 |

**Why chosen:** Most cited IDS dataset in academic literature (5000+ citations). Realistic benign background (25 real users doing browsing, email, SSH, FTP). Attack diversity (brute force, DoS, web, botnet, scan).

### 12.2 UNSW-NB15 — Network-Based Intrusion Detection

| Property | Value |
|----------|-------|
| Publisher | UNSW Canberra (Australian Defence Force Academy) |
| Year | 2015 |
| Tool | IXIA PerfectStorm traffic generator |
| Total Flows | ~257,673 |
| Benign | ~93,000 (36.1%) |
| Malicious | ~164,673 (63.9%) |
| Features | 49 features (including service, state, ct_* counters) |
| Unique Features | Connection-tracking features (ct_src_dport_ltm, ct_dst_sport_ltm) |

**Attack categories:**
| Category | Description |
|----------|-------------|
| Fuzzers | Random data injection to crash systems |
| Analysis | Port scan, spam, HTML file penetration |
| Backdoors | Unauthorized access via hidden channels |
| DoS | Resource exhaustion attacks |
| Exploits | Known vulnerability exploitation |
| Generic | All-purpose attack traffic |
| Reconnaissance | Information gathering (probing) |
| Shellcode | Code that spawns a remote shell |
| Worms | Self-propagating malware traffic |

**Why chosen:** Highest diversity of attack types (9 categories). Provides connection-tracking features (unique to UNSW) that help detect lateral movement and persistent threats.

### 12.3 ISCXVPN2016 — VPN Traffic Classification

| Property | Value |
|----------|-------|
| Publisher | Canadian Institute for Cybersecurity |
| Year | 2016 |
| Total Flows | ~271,028 |
| Categories | 14 (7 application types × 2 VPN/non-VPN) |

**Traffic types (each captured over VPN and without VPN):**
- Web Browsing (HTTP/HTTPS)
- Email (SMTP/IMAP)
- Chat (Skype/Hangouts/Facebook)
- Streaming (YouTube/Netflix/Vimeo)
- File Transfer (FTP/SFTP)
- VoIP (Skype voice/video)
- P2P (BitTorrent)

**Why chosen:** Enables detection of encrypted tunnel traffic. VPN-encapsulated attacks are invisible to payload-based IDS — flow features (IAT, packet sizes) are the ONLY way to classify them. Adds diversity of "normal but unusual" traffic patterns.

### 12.4 CSE-CICIDS2018 — Largest Dataset

| Property | Value |
|----------|-------|
| Publisher | Communications Security Establishment Canada + CIC |
| Year | 2018 |
| Infrastructure | 50 machines on AWS (realistic enterprise scale) |
| Total Flows | ~16,233,002 |
| Duration | 10 days |
| Benign | ~13,484,708 (83.1%) |
| Malicious | ~2,748,294 (16.9%) |

**Attack timeline:**
| Day | Attack |
|-----|--------|
| Day 1-2 | Brute Force (SSH + FTP) |
| Day 3-4 | DoS (Hulk, Slowloris, SlowHTTPTest, GoldenEye) |
| Day 5-6 | DDoS (LOIC UDP/TCP/HTTP, HOIC) |
| Day 7-8 | Web Attacks (SQL Injection, XSS, CSRF) |
| Day 9 | Botnet (Ares) |
| Day 10 | Infiltration (Metasploit, Nmap) |

**Why chosen:** Scale (16M flows = tests model on volume that matches real enterprise networks). Most recent of the 4 datasets. Includes modern attacks (HOIC DDoS, Metasploit infiltration). Enterprise topology (50 machines = realistic multi-host environment).



---

## 13. Frontend Architecture — Detailed Component Breakdown

### 13.1 Application Routing Architecture

```
URL Path          →  Component              →  Auth Required?  →  Layout?
─────────────────────────────────────────────────────────────────────────
/                 →  LandingPage            →  No              →  No
/auth             →  AuthPage              →  No (redirects if logged in) → No
/dashboard        →  DashboardPage         →  Yes             →  Yes (sidebar)
/messenger        →  MessengerPage         →  Yes             →  Yes (sidebar)
/security         →  SecurityDashboard     →  Yes             →  Yes (sidebar)
/defense          →  DefenseOpsPage        →  Yes             →  Yes (sidebar)
*                 →  Redirect to /         →  No              →  No
```

**Code-splitting strategy:**
```javascript
// Each page is lazy-loaded — only downloaded when user navigates to it
const LandingPage = lazy(() => import('./pages/LandingPage'))
const AuthPage = lazy(() => import('./pages/AuthPage'))
const DashboardPage = lazy(() => import('./pages/DashboardPage'))
const MessengerPage = lazy(() => import('./pages/MessengerPage'))
const SecurityDashboard = lazy(() => import('./pages/SecurityDashboard'))
const DefenseOpsPage = lazy(() => import('./pages/DefenseOpsPage'))

// Result: Initial bundle = ~30KB (Layout + router)
// Each page loads on-demand: 7-45KB per page
// Total if ALL loaded: ~160KB (vs 660KB if bundled together)
```

### 13.2 Service Layer Architecture

Each service is a singleton class that encapsulates one domain:

```
┌─────────────────────────────────────────────────────────────────┐
│                      SERVICE LAYER                                │
│                                                                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │ CryptoService│  │  AuthService │  │  VedDBService        │  │
│  │ (singleton)  │  │  (singleton) │  │  (singleton)         │  │
│  │              │  │              │  │                       │  │
│  │ .init()      │  │ .login()     │  │ .init()              │  │
│  │ .encrypt()   │  │ .register()  │  │ .set(key, val)       │  │
│  │ .decrypt()   │  │ .hashPwd()   │  │ .get(key)            │  │
│  │ .sign()      │  │ .deriveKey() │  │ .delete(key)         │  │
│  │ .verify()    │  │              │  │ .subscribe(key, cb)  │  │
│  │ .hash()      │  │              │  │ .ws (WebSocket)      │  │
│  │ .ratchet()   │  │              │  │                       │  │
│  └──────┬───────┘  └──────┬───────┘  └───────────┬──────────┘  │
│         │                  │                       │              │
│         ▼                  ▼                       ▼              │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                 WASM Bridge Service                        │   │
│  │  Loads cyphra_wasm.js → calls Rust functions              │   │
│  │  Fallback: Web Crypto API if WASM unavailable             │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │ThreatService │  │DefenseService│  │ ML Intelligence Svc  │  │
│  │ (singleton)  │  │ (singleton)  │  │ (singleton)          │  │
│  │              │  │              │  │                       │  │
│  │ .startMonitor│  │ .analyzeSignal│ │ .getModelInfo()      │  │
│  │ .analyzeMsg()│  │ .detectThreat│  │ .analyzeMessage()    │  │
│  │ .getStats()  │  │ .getAuditLog│  │ .getNetworkStats()   │  │
│  │              │  │ .setRole()   │  │ .triggerAttack()     │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
│                                                                   │
│  ┌──────────────┐  ┌──────────────┐                             │
│  │MixnetService │  │PaddingService│                             │
│  │ (singleton)  │  │ (singleton)  │                             │
│  │              │  │              │                             │
│  │ .setHops()   │  │ .start(rate) │                             │
│  │ .sendThruMix│  │ .stop()      │                             │
│  │ .getStatus() │  │ .getStatus() │                             │
│  └──────────────┘  └──────────────┘                             │
└─────────────────────────────────────────────────────────────────┘
```

### 13.3 State Management — Zustand Store Design

**Why Zustand over Redux Toolkit:**

| Aspect | Redux Toolkit | Zustand |
|--------|--------------|---------|
| Boilerplate | createSlice + configureStore + Provider | Single `create()` call |
| Bundle size | 30KB+ | 1.2KB |
| DevTools | Requires middleware setup | Built-in (opt-in) |
| Async actions | createAsyncThunk | Just use async/await in actions |
| Selectors | createSelector (memoized) | Direct property access (auto-optimized) |
| Learning curve | High (actions, reducers, selectors, middleware) | Minimal (just a hook) |

**Store design principles:**
1. **Flat state** — no deeply nested objects (prevents re-render cascading)
2. **Actions modify state directly** — no reducer pattern needed
3. **Selectors via destructuring** — `const { messages, addMessage } = useStore()`
4. **External service calls inside actions** — store orchestrates side effects

### 13.4 WebGL Background — Three.js Particle System

```javascript
// WebGLBackground.jsx — Creates cybersecurity-themed 3D particle field

// Scene setup
const scene = new THREE.Scene()
const camera = new THREE.PerspectiveCamera(75, aspect, 0.1, 1000)
const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true })

// Particle system: 5000 points in 3D space
const geometry = new THREE.BufferGeometry()
const positions = new Float32Array(5000 * 3)  // x, y, z per particle

for (let i = 0; i < 5000; i++) {
    positions[i * 3] = (Math.random() - 0.5) * 100      // x: -50 to +50
    positions[i * 3 + 1] = (Math.random() - 0.5) * 100  // y: -50 to +50
    positions[i * 3 + 2] = (Math.random() - 0.5) * 100  // z: -50 to +50
}

geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3))

// Particle material: cyan glow, size attenuation with distance
const material = new THREE.PointsMaterial({
    size: 0.5,
    color: 0x00d4ff,        // Cyphra cyan
    transparent: true,
    opacity: 0.6,
    sizeAttenuation: true,  // Smaller when further away
})

// Mouse interaction: particles drift toward cursor
document.addEventListener('mousemove', (e) => {
    mouseX = (e.clientX / window.innerWidth) * 2 - 1
    mouseY = -(e.clientY / window.innerHeight) * 2 + 1
    // Rotate camera slightly based on mouse position
    camera.rotation.x += mouseY * 0.001
    camera.rotation.y += mouseX * 0.001
})

// Animation loop (60fps): slowly rotate the particle field
function animate() {
    requestAnimationFrame(animate)
    particles.rotation.y += 0.0005  // Slow Y-axis rotation
    particles.rotation.x += 0.0002  // Very slow X-axis rotation
    renderer.render(scene, camera)
}
```

---

## 14. VedDB Protocol — Complete Wire Format Specification

### 14.1 Frame Structure (v0.2.0)

```
Byte offset  Size    Field           Description
──────────── ─────── ─────────────── ──────────────────────────────────────
0            2       magic           Always 0x56 0x44 ("VD" in ASCII)
2            1       version         0x02 for v0.2.0
3            1       opcode          Operation code (see Section 6)
4            4       seq_num         Sequence number (u32, little-endian)
8            4       payload_len     Payload size in bytes (u32, little-endian)
12           2       flags           Bit flags (reserved)
14           2       reserved        Alignment padding
──────────── ─────── ─────────────── ──────────────────────────────────────
16           N       payload         JSON or binary data (N = payload_len)
```

### 14.2 Request-Response Matching

```
Client sends:
  [Header: magic=VD, ver=2, op=SET, seq=42, len=25, flags=0, res=0]
  [Payload: {"key":"user:abc","value":"..."}]

Server responds:
  [Header: magic=VD, ver=2, op=OK, seq=42, len=0, flags=0, res=0]
  [Payload: empty]

Matching rule: response.seq MUST equal request.seq
  If mismatch → client rejects response (protocol error)
  Enables pipelining (send multiple requests, match responses by seq)
```

### 14.3 Error Response Format

```
If operation fails:
  [Header: magic=VD, ver=2, op=ERROR, seq=42, len=N, flags=0, res=0]
  [Payload: "Key not found" or "Authentication required"]

Status codes in response header byte:
  0x00 = OK (success)
  0x01 = ERROR (generic failure)
  0x02 = NOT_FOUND (key doesn't exist)
  0x03 = FULL (server buffer exhausted)
  0x04 = TIMEOUT (operation took too long server-side)
  0x05 = VERSION_MISMATCH (CAS conflict)
  0x06 = AUTH_REQUIRED (must authenticate first)
  0x07 = FORBIDDEN (authenticated but no permission)
```

### 14.4 Authentication Handshake

```
Step 1: Client connects (TCP or TLS)

Step 2: Client sends AUTH request:
  Header: op=0x10 (Auth), seq=1
  Payload: {
    "method": "UsernamePassword",
    "credentials": {
      "username": "cyphra_admin",
      "password": "s3cureP@ssw0rd"
    }
  }

Step 3: Server validates and responds:
  Header: op=0x11 (AuthResponse), seq=1
  Payload: {
    "success": true,
    "token": "eyJhbGciOiJIUzI1NiIs...",  ← JWT for subsequent requests
    "role": "admin",
    "expires_at": "2026-06-14T12:00:00Z"
  }

Step 4: All subsequent requests include the token implicitly
  (stored in connection state — no per-request auth header needed)
```

### 14.5 Connection Pooling Implementation

```rust
pub struct ConnectionPool {
    connections: Vec<Arc<Mutex<Connection>>>,
    next_index: AtomicUsize,
}

impl ConnectionPool {
    // Round-robin connection selection
    pub async fn get(&self) -> ConnectionGuard {
        let idx = self.next_index.fetch_add(1, Ordering::Relaxed) % self.connections.len();
        let conn = self.connections[idx].clone();
        let guard = conn.lock().await;  // Wait if connection is busy
        ConnectionGuard(guard)
    }
}

// Usage:
let pool = ConnectionPool::new("127.0.0.1:50051", 5).await?;
// Creates 5 persistent TCP connections

// Thread 1:
pool.get().await?.set("key1", "val1").await?;  // Uses connection 0

// Thread 2 (concurrent):
pool.get().await?.get("key2").await?;  // Uses connection 1

// Thread 3 (concurrent):
pool.get().await?.set("key3", "val3").await?;  // Uses connection 2
```

---

## 15. Performance Benchmarks

### 15.1 ML Inference Performance

| Metric | Value | Conditions |
|--------|-------|-----------|
| Single flow inference | 4.8 ms | 6 models, soft vote, CPU |
| Feature extraction | 0.2 ms | 100 features from raw packet records |
| StandardScaler | 0.01 ms | 100 multiply + clip operations |
| LightGBM predict | 0.8 ms | 1500 trees, 255 leaves each |
| XGBoost predict | 1.2 ms | 1200 trees (requires DMatrix construction) |
| CatBoost predict | 0.9 ms | 1500 iterations, symmetric trees |
| Ensemble overhead | 0.1 ms | Mean of 6 floats + classification |
| Total pipeline | ~5 ms | Packet → classification complete |

### 15.2 Cryptographic Operation Performance

| Operation | WASM (Browser) | Native Rust | Web Crypto Fallback |
|-----------|---------------|-------------|---------------------|
| AES-256-GCM encrypt (1KB) | 0.05 ms | 0.01 ms | 0.08 ms |
| AES-256-GCM decrypt (1KB) | 0.05 ms | 0.01 ms | 0.08 ms |
| X25519 keypair generation | 0.3 ms | 0.1 ms | 0.5 ms (ECDH-P256) |
| X25519 DH shared secret | 0.3 ms | 0.1 ms | N/A |
| Ed25519 sign | 0.2 ms | 0.08 ms | 0.4 ms (ECDSA-P256) |
| Ed25519 verify | 0.4 ms | 0.15 ms | 0.5 ms (ECDSA-P256) |
| HKDF-SHA256 (32 bytes) | 0.02 ms | 0.005 ms | 0.03 ms |
| SHA-256 hash (1KB) | 0.01 ms | 0.003 ms | 0.02 ms |
| BLAKE3 hash (1KB) | N/A | 0.001 ms | N/A |
| Kyber-1024 keygen | N/A | 0.5 ms | N/A |
| Kyber-1024 encapsulate | N/A | 0.6 ms | N/A |
| Kyber-1024 decapsulate | N/A | 0.5 ms | N/A |
| X3DH session initiate | N/A | 2.3 ms | N/A |
| Double Ratchet step | 0.05 ms | 0.01 ms | 0.07 ms |

### 15.3 Network Performance

| Metric | Value |
|--------|-------|
| WebSocket message latency (LAN) | 1-3 ms |
| VedDB SET (via Rust TLS client) | < 5 ms |
| VedDB GET (via Rust TLS client) | < 3 ms |
| VedDB SET (via CLI subprocess) | 50-100 ms |
| Signal stats collection cycle | ~4 seconds (4 system commands) |
| ML realtime feed poll interval | 3 seconds |
| Mixnet 5-hop relay latency | ~50-100 ms |
| Auto-response (T1 firewall rule) | ~200 ms |
| Auto-response (T2 RST injection) | ~50 ms |

### 15.4 Build Performance

| Build Target | Time | Output Size |
|---|---|---|
| Frontend (Vite production) | 2.5 s | 160 KB (JS) + 29 KB (CSS) |
| WASM crate (wasm-pack release) | 1.6 s | 153 KB (.wasm) |
| Rust server (cargo release) | 12 s | 4.05 MB (.exe) |
| Android APK (Gradle debug) | 25 s | ~15 MB (.apk) |
| ML model training (all 7) | 65 min | ~110 MB (all model files) |

---

## 16. Comparison With Industry Solutions

### 16.1 CYPHRA vs Darktrace (Enterprise AI SOC)

| Feature | Darktrace | CYPHRA |
|---------|-----------|--------|
| Detection method | Unsupervised AI (anomaly) | Supervised ensemble (classification) |
| Training data | Customer's own network | 19.5M academic flows + live capture |
| Accuracy | Not publicly disclosed | 98.85% (published, reproducible) |
| Autonomous response | Antigena (proprietary) | Open response engine (T1/T2/T3) |
| Encrypted comms | ❌ Not included | ✅ AES-256-GCM + Kyber-1024 |
| Post-quantum | ❌ | ✅ Kyber-1024 |
| Pricing | $100K+ / year | Self-hosted (free) |
| Open source | ❌ Proprietary | Partially (custom libraries visible) |

### 16.2 CYPHRA vs Signal (E2E Encrypted Messenger)

| Feature | Signal | CYPHRA Ghost Messenger |
|---------|--------|------------------------|
| E2E Encryption | AES-256-CBC + Curve25519 | AES-256-GCM + X25519 (+ Kyber-1024 PQC) |
| Key exchange | X3DH (classical) | PQC-Hybrid X3DH (quantum-resistant) |
| Ratchet | Double Ratchet (HMAC-SHA256) | Double Ratchet (BLAKE3, 3× faster) |
| Self-destruct | Timer starts on send | Timer starts on recipient READ (more secure) |
| Threat scanning | ❌ | ✅ ML threat analysis on every message |
| SOC integration | ❌ | ✅ Same dashboard sees network + messaging threats |
| Hardware crypto | Signal PIN (software) | Android Keystore (TEE hardware) |
| Identity system | Phone number | Ghost Code (anonymous) |

### 16.3 CYPHRA vs Snort/Suricata (Open-Source IDS)

| Feature | Snort/Suricata | CYPHRA |
|---------|---------------|--------|
| Detection | Rule-based (signatures) | ML-based (learned patterns) |
| New attack detection | ❌ Requires rule update | ✅ ML generalizes to unseen attacks |
| Accuracy | Depends on rules | 98.85% (measured) |
| Autonomous response | ❌ Alert only | ✅ T1 firewall + T2 RST + T3 escalation |
| Encrypted traffic | ❌ Cannot inspect | ✅ Flow-level features (doesn't need payload) |
| E2E messaging | ❌ | ✅ Integrated |
| Signal monitoring | ❌ | ✅ DOC (Wi-Fi health, EW threats) |

---

## 17. Known Limitations — Honest Engineering Assessment

### 17.1 Detection Latency

```
Attack begins:           T + 0.0 seconds
Packets captured:        T + 0.0 to T + 5.0 seconds (flow accumulates)
Flow evicted (FIN/RST):  T + varies (instant for port scan, 30s for idle)
Feature extraction:      T + 0.1 seconds after eviction
ML inference:            T + 0.005 seconds (5ms)
Response triggered:      T + 0.2 seconds (firewall rule creation)

RESULT: First 2-5 seconds of any attack ALWAYS land before detection.
This is FUNDAMENTAL to all flow-based IDS — not fixable without packet-level (stateless) detection.
```

### 17.2 Model Domain Shift

```
Training data: 2015-2018 academic lab traffic
Live traffic:  2026 real-world (Teams, Discord, OneDrive, Windows telemetry)

Problem: The model learned what "benign" looks like from 2017 university users.
         Modern traffic patterns (cloud sync, video conferencing, app telemetry)
         didn't exist in the training data.

Mitigation: dataset_onehot flags set to 0.0 for live traffic.
            Demo attacks use onehot_0=1.0 to classify against CICIDS2017 domain.
            
Long-term fix: Periodic retraining on captured live traffic (supervised labeling needed).
```

### 17.3 Windows-Only Dependency

```
Feature              │ Windows Command          │ Linux Equivalent
─────────────────────┼──────────────────────────┼──────────────────────
Wi-Fi signal         │ netsh wlan show interfaces│ iwconfig / nmcli
Gateway discovery    │ route print              │ ip route show default
Firewall block       │ netsh advfirewall        │ iptables / nftables
NTP timing           │ w32tm /query /status     │ ntpq -p / chronyc
Packet capture       │ Npcap (WinPcap)          │ libpcap (built-in)

Porting effort: Replace 5 system commands + Npcap with Linux equivalents.
Estimated: 2-3 days of development.
```

---

*Document generated: June 14, 2026*  
*Total technologies documented: 48+*  
*Total algorithms explained: 15+*  
*Total comparisons provided: 12*


---

## 18. Development Environment & Toolchain

### 18.1 IDE & Editor Configuration

| Tool | Purpose | Configuration |
|------|---------|--------------|
| VS Code / Kiro | Primary development IDE | Extensions: rust-analyzer, Python, ESLint, Tailwind Intellisense |
| Android Studio | Android app development | Hedgehog+ with Kotlin Compose plugin |
| Chrome DevTools | Frontend debugging | Network tab (WebSocket frames), Console (WASM logs) |

### 18.2 Testing Strategy Per Layer

| Layer | Testing Approach | Tool |
|-------|-----------------|------|
| Rust crates | Unit tests + integration tests | `cargo test` (built-in) |
| Rust server | Endpoint test suite (11 tests) | `test_all.py` (Python requests) |
| ML inference | 34-test automated suite | `test_all.py` (urllib) |
| Frontend | Build verification (Vite) | `npx vite build` (zero-error check) |
| Android | Manual testing on device | ADB install + USB debugging |
| E2E Messaging | Cross-device manual test | Web → Phone simultaneous chat |
| Demo attacks | 8 attack profiles | `demo_attacks.py` (real ML scores) |

### 18.3 Dependency Management

| Ecosystem | Lock File | Package Manager |
|-----------|-----------|-----------------|
| Rust | `Cargo.lock` | Cargo (exact versions pinned) |
| Python | `requirements.txt` | pip (version ranges) |
| Node.js | `package-lock.json` | npm (exact dependency tree) |
| Android | `gradle/libs.versions.toml` | Gradle Version Catalog |

### 18.4 Git Workflow

```
Repository strategy:
  source repo  → https://github.com/choksi2212/cyphra-hackprix (development)
  dest repo    → https://github.com/choksi2212/theoriginals-cyphra (production)

Branch strategy:
  main     ← merged from all 4 feature branches
  infra    ← Person 4: Rust libraries, WASM, Android, docs
  data-ml  ← Person 2: ML models, training, VedDB binaries
  backend  ← Person 3: Node.js server, Rust REST API
  frontend ← Person 1: React app, PWA, business site

Commit convention:
  feat(scope): description    — New feature
  fix(scope): description     — Bug fix
  chore: description          — Maintenance/cleanup
  init: description           — Project setup
```

---

## 19. Port Allocation & Service Map

```
┌──────────────────────────────────────────────────────────────┐
│                    CYPHRA SERVICE MAP                          │
├──────────┬────────────────────────────┬───────────────────────┤
│  Port    │  Service                   │  Protocol             │
├──────────┼────────────────────────────┼───────────────────────┤
│  5173    │  Vite Dev Server (React)   │  HTTP                 │
│  3001    │  Node.js Backend           │  HTTP + WebSocket     │
│  3002    │  PWA Server (iOS)          │  HTTP                 │
│  5002    │  ML FastAPI Service        │  HTTP                 │
│  5050    │  Rust Crypto API Server    │  HTTP                 │
│  50051   │  VedDB Database Server     │  Custom Binary + TLS  │
│  6001    │  Mixnet Relay Node 0       │  HTTP                 │
│  6002    │  Mixnet Relay Node 1       │  HTTP                 │
│  6003    │  Mixnet Relay Node 2       │  HTTP                 │
│  6004    │  Mixnet Relay Node 3       │  HTTP                 │
│  6005    │  Mixnet Relay Node 4       │  HTTP                 │
└──────────┴────────────────────────────┴───────────────────────┘
```

### Start Order (Dependencies)

```
Level 0 (no dependencies):
  ├── veddb-server.exe           ← Standalone database
  └── start_mixnet.bat           ← 5 independent relay nodes

Level 1 (depends on VedDB):
  ├── cyphra-server.exe          ← Connects to VedDB via TLS
  └── ml-service (main.py)       ← Captures packets independently

Level 2 (depends on Level 1):
  └── node server.js             ← Proxies to ML + Rust + VedDB

Level 3 (depends on Level 2):
  ├── npm run dev                ← Connects to Node.js backend
  ├── cyphra-android             ← Connects to Node.js backend
  └── cyphra-pwa server          ← Connects to Node.js backend
```

---

## 20. Security Threat Model

### 20.1 Assets Protected

| Asset | Protection Mechanism |
|-------|---------------------|
| Message content | AES-256-GCM encryption (client-side, server never sees plaintext) |
| Private keys | Encrypted with user's password before VedDB storage |
| User identity | Ghost Codes (anonymous sharing without email exposure) |
| Communication patterns | Traffic padding (configurable 10-95% dummy messages) |
| Sender-recipient link | Mixnet onion routing (N relay hops hide connection) |
| Session keys | Double Ratchet (deleted after use — forward secrecy) |
| Audit integrity | SHA-256 hash chaining (any tampering breaks the chain) |
| Network perimeter | Autonomous firewall blocking (Tier 1 at ≥0.92 threat score) |

### 20.2 Threat Actors Considered

| Actor | Capability | Mitigation |
|-------|-----------|------------|
| Passive eavesdropper | Captures all network traffic | AES-256-GCM encryption + TLS 1.3 |
| Active MitM | Modifies traffic in transit | GCM authentication tag (any modification detected) |
| Compromised server | Has full database access | Private keys encrypted with user password; DEK derived per-message (not stored) |
| Quantum computer (future) | Breaks X25519/ECDH | Kyber-1024 PQC hybrid (quantum-safe layer) |
| Traffic analyst | Observes timing/volume | Padding service + mixnet routing |
| Brute-force attacker | Tries many passwords | PBKDF2 100K iterations (200ms per attempt = 5 attempts/sec max) |
| Key compromise | Steals current session key | Double Ratchet (post-compromise recovery after 1 DH exchange) |
| Insider threat | Has partial system access | RBAC (Operator cannot view audit logs), audit chain tamper-evident |

### 20.3 What CYPHRA Does NOT Protect Against

| Threat | Why not protected | Mitigation path |
|--------|-------------------|-----------------|
| Endpoint compromise (malware on device) | If attacker controls the OS, they can read memory | Hardware-backed Keystore (Android) partially mitigates |
| Social engineering | User voluntarily shares credentials | MFA (not implemented yet) |
| Zero-day kernel exploit | Npcap runs in kernel space | Keep Npcap updated; defense-in-depth |
| Physical access to device | Can read localStorage/memory | Device encryption + biometric lock |
| DDoS flooding (volumetric) | 5s detection delay = 50K packets land first | Upstream ISP filtering needed |

---

## 21. Acronym & Glossary Reference

| Acronym | Full Form | Category |
|---------|-----------|----------|
| AEAD | Authenticated Encryption with Associated Data | Crypto |
| AES | Advanced Encryption Standard | Crypto |
| API | Application Programming Interface | Web |
| ARPU | Average Revenue Per User | Business |
| ASGI | Asynchronous Server Gateway Interface | Web |
| AUC | Area Under the ROC Curve | ML |
| BLAKE3 | (hash function, not acronym) | Crypto |
| CAC | Customer Acquisition Cost | Business |
| CAGR | Compound Annual Growth Rate | Business |
| CAS | Compare-And-Swap | Database |
| CBC | Cipher Block Chaining | Crypto |
| CORS | Cross-Origin Resource Sharing | Web |
| CSPRNG | Cryptographically Secure Pseudo-Random Number Generator | Crypto |
| CTR | Counter Mode | Crypto |
| CUDA | Compute Unified Device Architecture | GPU |
| DDoS | Distributed Denial of Service | Security |
| DEK | Data Encryption Key | Crypto |
| DH | Diffie-Hellman | Crypto |
| DOC | Defence Operations Center | CYPHRA |
| ECDH | Elliptic Curve Diffie-Hellman | Crypto |
| ECDSA | Elliptic Curve Digital Signature Algorithm | Crypto |
| EW | Electronic Warfare | Defence |
| F1 | F1-Score (harmonic mean of precision & recall) | ML |
| FFI | Foreign Function Interface | Programming |
| FIPS | Federal Information Processing Standards | Standards |
| FN | False Negative | ML |
| FP | False Positive | ML |
| GCM | Galois/Counter Mode | Crypto |
| GBDT | Gradient Boosted Decision Trees | ML |
| GPU | Graphics Processing Unit | Hardware |
| HKDF | HMAC-based Key Derivation Function | Crypto |
| HMAC | Hash-based Message Authentication Code | Crypto |
| HTTP | HyperText Transfer Protocol | Web |
| IAT | Inter-Arrival Time | Network |
| IDS | Intrusion Detection System | Security |
| IKM | Input Key Material | Crypto |
| JIT | Just-In-Time (compilation) | Programming |
| JWT | JSON Web Token | Auth |
| KDF | Key Derivation Function | Crypto |
| KEM | Key Encapsulation Mechanism | Crypto |
| LAN | Local Area Network | Network |
| LGBM | Light Gradient Boosting Machine | ML |
| LTV | Lifetime Value | Business |
| MAC | Message Authentication Code | Crypto |
| MITM | Man-in-the-Middle | Security |
| ML | Machine Learning | ML |
| ML-KEM | Module-Lattice Key Encapsulation Mechanism | Crypto |
| MLWE | Module Learning With Errors | Crypto |
| MLP | Multi-Layer Perceptron | ML |
| mTLS | Mutual TLS | Security |
| NAT | Network Address Translation | Network |
| NIC | Network Interface Card | Hardware |
| NIST | National Institute of Standards and Technology | Standards |
| NTP | Network Time Protocol | Network |
| OKM | Output Key Material | Crypto |
| PBKDF2 | Password-Based Key Derivation Function 2 | Crypto |
| PQC | Post-Quantum Cryptography | Crypto |
| PRK | Pseudo-Random Key | Crypto |
| PWA | Progressive Web App | Mobile |
| RBAC | Role-Based Access Control | Security |
| REST | Representational State Transfer | Web |
| RST | TCP Reset (flag) | Network |
| RTT | Round-Trip Time | Network |
| SaaS | Software as a Service | Business |
| SHA | Secure Hash Algorithm | Crypto |
| SMOTE | Synthetic Minority Oversampling Technique | ML |
| SNI | Server Name Indication | TLS |
| SNR | Signal-to-Noise Ratio | Signal |
| SOC | Security Operations Center | CYPHRA |
| TLS | Transport Layer Security | Security |
| TN | True Negative | ML |
| TP | True Positive | ML |
| VRAM | Video Random Access Memory | Hardware |
| WASM | WebAssembly | Web |
| WS | WebSocket | Web |
| XGB | eXtreme Gradient Boosting | ML |
| X3DH | Extended Triple Diffie-Hellman | Crypto |

---

*End of Technology Stack Reference*

*CYPHRA — Every byte has a purpose. Every algorithm has a reason.*
