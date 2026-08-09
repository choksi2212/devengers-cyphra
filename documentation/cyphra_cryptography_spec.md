# Cyphra Messenger: Cryptographic Architecture & Algorithmic Blueprint

Cyphra is designed as a military-grade, zero-knowledge messaging platform. This document explicitly details every cryptographic algorithm utilized, its exact implementation context, its mathematical mechanics, and the rigorous justification for its selection over alternatives.

---

## 1. Transport Layer Security & Symmetric Encryption

### AES-256-GCM (Advanced Encryption Standard - 256-bit Key - Galois/Counter Mode)

**Where it is used:**
- End-to-end encryption of all message payloads (text, metadata).
- Local storage encryption in the VedDB frontend client service.
- Symmetric key wrapping within the Web Crypto API on both Web and Android clients.

**What it means:**
AES-256 is a symmetric block cipher standardized by NIST. It uses a 256-bit key (the maximum strength available for AES) to perform 14 rounds of substitution, permutation, and mixing operations on 128-bit blocks of data. 
GCM (Galois/Counter Mode) is an *authenticated encryption with associated data* (AEAD) mode. It combines the Counter (CTR) mode for encryption (turning the block cipher into a stream cipher) with a Galois field multiplier for authentication.

**Exact Usage Mechanics:**
1. **Key Generation:** A completely random 256-bit symmetric key is generated for every chat/session (or derived via ECDH, detailed later).
2. **Initialization Vector (IV):** A unique, cryptographically secure 12-byte (96-bit) nonce (IV) is generated for *every single message*.
3. **Encryption (CTR Mode):** The IV is combined with a counter, encrypted with the AES key, and XORed against the plaintext to produce ciphertext.
4. **Authentication (Galois MAC):** As the ciphertext is produced, it is fed into a Galois Hash function. This produces a 16-byte authentication tag appended to the ciphertext.
5. **Payload:** The transmitted payload contains: `IV + Ciphertext + Auth Tag`.

**Why it is used (Justification):**
- **Quantum Resistance (Symmetric):** Grover's algorithm theoretically halves symmetric key strength on a quantum computer. A 128-bit key would reduce to 64 bits (vulnerable). A 256-bit key reduces to 128 bits, which remains entirely secure against known theoretical quantum attacks.
- **AEAD Guarantees:** GCM provides both confidentiality (encryption) and integrity (authentication). If an attacker flips a single bit of the ciphertext or the IV in transit (a malleability attack), the authentication tag verification fails during decryption, and the message is instantly dropped.
- **Performance:** AES is hardware-accelerated on nearly all modern CPUs (via AES-NI) and ARM architectures (TrustZone/Crypto extensions), allowing real-time encryption with near-zero latency and negligible battery drain on mobile devices.

---

## 2. Key Agreement & Asymmetric Encryption

### ECDH (Elliptic Curve Diffie-Hellman) over P-256 (secp256r1)

**Where it is used:**
- Generating the shared secret between two users who have never communicated before.
- Deriving the AES-256-GCM symmetric key used for the actual message payload encryption.

**What it means:**
ECDH is a key agreement protocol that allows two parties, each having an elliptic-curve public-private key pair, to establish a shared secret over an insecure channel. P-256 (also known as NIST P-256 or prime256v1) is a specific, standardized elliptic curve equation defined over a 256-bit prime field.

**Exact Usage Mechanics:**
1. Alice generates a Private Key ($d_A$) and calculates a Public Key ($Q_A = d_A \times G$, where $G$ is the base point on P-256).
2. Bob generates his Private Key ($d_B$) and Public Key ($Q_B = d_B \times G$).
3. They exchange public keys via the VedDB backend.
4. Alice computes the shared secret: $S = d_A \times Q_B = d_A \times (d_B \times G)$.
5. Bob computes the same shared secret: $S = d_B \times Q_A = d_B \times (d_A \times G)$.
6. Both parties now possess the identical point $S$. The x-coordinate of $S$ is passed through a Key Derivation Function (HKDF) to produce the AES-256 symmetric key.

**Why it is used (Justification):**
- **Perfect Forward Secrecy (PFS) capability:** By generating ephemeral (temporary) ECDH keys for sessions, even if a user's long-term identity key is compromised, past communications remain encrypted because the session keys are destroyed.
- **Key Size Efficiency:** A 256-bit Elliptic Curve key provides exactly the same level of security (128-bit security level) as a massive 3072-bit RSA key. This dramatically reduces bandwidth payload size and memory footprint, which is critical for mobile connectivity and rapid message dispatch.
- **Web Crypto API Native:** P-256 is universally supported across all modern browser Web Crypto implementations and Android's native Keystore, ensuring deterministic cross-platform compatibility without needing massive third-party cryptographic libraries (like BouncyCastle or Libsodium).

---

## 3. Account Generation, Hashing & Key Derivation

### SHA-256 (Secure Hash Algorithm 256-bit)

**Where it is used:**
- Deterministic User ID generation: `userId = SHA-256(email)`.
- Non-deterministic Password representation: `passwordHash = SHA-256(password + salt)`.

**What it means:**
SHA-256 is a cryptographic hash function that takes an input of any size and produces a fixed-size 256-bit (32-byte) hash. It is a one-way function; it is mathematically infeasible to determine the original input from the hash value alone.

**Exact Usage Mechanics:**
- **User IDs:** Instead of sending exposing plain-text emails to the server or database (which violates zero-knowledge principles), Cyphra hashes the email locally on the client. `sha256("user@example.com")` results in `b4c9...`. This hash becomes the public identifier for routing messages.
- **Passwords:** A cryptographically secure random `salt` is generated. The hash is computed as `sha256(password + salt)`. (Note: In production deployments, PBKDF2 or Argon2 is strictly recommended over raw SHA-256 for passwords to defend against GPU-accelerated brute-force attacks, but SHA-256 serves as the baseline).

**Why it is used (Justification):**
- **Collision Resistance:** The probability of two different emails producing the same SHA-256 hash is infinitesimally small (roughly 1 in $2^{256}$), guaranteeing mathematically unique User IDs across the network.
- **Zero-Knowledge Backend:** The VedDB database only ever sees a 64-character hex string representing the user. If the database is compromised, the attacker has no clear-text emails to spear-phish or sell.
- **Deterministic lookup:** To add a contact, Alice only needs to know Bob's email. Alice's client computes the SHA-256 hash of Bob's email locally and asks the server for that specific hash. The server never learns who Alice is searching for.

---

## 4. Digital Signatures & Non-Repudiation

### ECDSA (Elliptic Curve Digital Signature Algorithm) over P-256

**Where it is used:**
- Signing the AES public keys before uploading them to the server.
- Verifying the identity of the sender when a message is received.

**What it means:**
ECDSA is the elliptic curve analogue of the Digital Signature Algorithm (DSA). It allows a user to generate a mathematical proof (the signature) that a specific piece of data was created by the owner of a specific private key, and that the data has not been altered.

**Exact Usage Mechanics:**
1. Alice hashes her exported public key payload using SHA-256.
2. Alice uses her identity Private Key to sign this hash.
3. The signature and the public key are uploaded to the Cyphra network.
4. Bob downloads Alice's public key bundle. He uses Alice's previously known identity Public Key to verify the signature.
5. If verification passes, Bob is mathematically certain the key belongs to Alice and was not injected by a Man-in-the-Middle (MitM) attacker.

**Why it is used (Justification):**
- **Authentication without shared secrets:** ECDSA allows Bob to verify Alice's actions without Alice ever needing to send Bob a secret code.
- **MitM Protection:** If an attacker intercepts the initial key exchange and swaps Alice's public key for their own (so they can intercept the AES key), the signature verification will fail because the attacker does not possess Alice's private key to sign the fraudulent payload.

---

## 5. Post-Quantum Key Encapsulation (Kyber)

### ML-KEM-1024 (Module-Lattice-Based Key-Encapsulation Mechanism, formerly Kyber-1024)

**Where it is used:**
- Establishing the shared symmetric key in a post-quantum secure manner.
- Combined iteratively with ECDH in a hybrid key-exchange system to ensure security against both classical and quantum adversaries.

**What it means:**
Kyber (standardized by NIST as ML-KEM) is a Key Encapsulation Mechanism (KEM) uniquely designed to be resistant to attacks by large-scale quantum computers. The "1024" designation represents its maximum security parameter set, roughly equivalent to AES-256 in classical symmetric security strength and fully equating to NIST Security Category 5. 

Unlike RSA or Elliptic Curve mathematics (which rely on integer factorization and discrete logarithms respectively), Kyber operates on **Module Learning With Errors (MLWE)**. The core mathematical premise relies on the extreme difficulty of solving linear equations over module lattices when a small amount of deliberate cryptographic "noise" (errors) is introduced.

**Exact Usage Mechanics:**
1. **Key Generation:** Bob generates a post-quantum Keypair (a Secret Key array and a Public Key matrix of polynomials) based on Kyber-1024 parameters. 
2. **Key Encapsulation:** Alice uses Bob's Public Key matrix to encapsulate a randomly generated 256-bit symmetric shared secret. This generates a Ciphertext that conceptually contains the secret hidden within lattice noise.
3. **Transmission:** Alice transmits this Ciphertext across the insecure backend array to Bob. 
4. **Key Decapsulation:** Bob uses his Kyber Secret Key to filter out the structural lattice noise from the Ciphertext, perfectly recovering the exact 256-bit symmetric shared secret Alice generated.
5. **Hybrid Mixing:** The resulting Kyber shared secret is concatenated with the ECDH P-256 standard shared secret, and both are passed through an HKDF (HMAC-based Key Derivation Function) to create the finalized, quantum-impervious AES-256-GCM key used for payload encryption.

**Why it is used (Justification):**
- **Harvest Now, Decrypt Later (HNDL) Mitigation:** Nation-state adversaries routinely harvest and store heavily encrypted data traffic today, anticipating that a Cryptographically Relevant Quantum Computer (CRQC) will be built in the next decade that can effortlessly break P-256 and RSA via Shor's Algorithm. Utilizing Kyber-1024 ensures captured Cyphra intercepts cannot be retrospectively decrypted.
- **Hybrid Redundancy:** By running Kyber-1024 parallel to ECDH P-256, Cyphra guarantees that even if a catastrophic mathematical flaw is eventually found in the complex new Kyber algorithm, the encryption simply degrades to standard Elliptic Curve security. The system retains classical perfect forward secrecy regardless.
- **Performance:** Despite being quantum-resistant, Kyber operations (polynomial multiplication over lattices) are remarkably fast. Key generation and encapsulation execute in fractions of a millisecond natively, avoiding the massive computational overhead characteristic of earlier post-quantum algorithms.

---

## 6. Defense-in-Depth Mechanisms

### Cryptographically Secure Pseudo-Random Number Generators (CSPRNG)
- **Usage:** Used to generate Initialization Vectors (IVs) for AES-256-GCM, password salts, and ephemeral private keys.
- **Mechanism:** On Web, `window.crypto.getRandomValues()`. On Android, `java.security.SecureRandom`.
- **Justification:** Standard random functions (`Math.random()`) are deterministic and predictable. If an attacker can predict the IV used in AES-GCM, the entire encryption scheme collapses entirely. CSPRNGs utilize hardware entropy (CPU thermal noise, interrupt timing) to ensure absolute mathematical unpredictability.

### Self-Destruct Timers (Cryptographic Deletion)
- **Usage:** Messages with `selfDestruct = true`.
- **Mechanism:** When the destruct timer expires, the local client sends a cryptographically signed HTTP DELETE request to the backend. Simultaneously, the client permanently drops the AES-256-GCM symmetric key used for that specific session/message from local memory.
- **Justification:** Even if the database deletion fails, or the device is later forensically imaged by an adversary, the ciphertext on the disk is utterly useless because the symmetric key required to decrypt it has been permanently erased from RAM (Cryptographic Erasure).
