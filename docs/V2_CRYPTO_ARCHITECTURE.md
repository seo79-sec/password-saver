# PasswordSaver v2 cryptographic foundation

## Scope and separation from v1

The implementation in `crypto/v2` is a standalone envelope-encryption engine. It does not import the v1 `CryptoManager`, `Vault`, `App`, `SaveVault`, or `LoadVault`; neither does v1 import this package. No application setting selects v2, and this code performs no filesystem writes or migrations.

The v1 package can provide implementation precedents and libraries: it already uses Go's `crypto/aes`, `cipher.AEAD`, `crypto/rand`, and `golang.org/x/crypto/argon2`. The v2 package independently uses those primitives but does not reuse v1 serialization, session state, or signing. Its key hierarchy, AAD, and envelope are incompatible with v1 by design.

The v1 vault is JSON containing its existing encrypted-data tuple and a trailing HMAC made with the static v1 application key. `SaveVault` creates an encrypted `.bak` and commits through the existing platform-specific atomic-replacement helpers (`MoveFileEx` with write-through on Windows; rename and directory sync on Unix-like systems). `App` owns the v1 authorization, in-memory vault, reset, and recovery flows. These behaviors and tests remain unchanged. The static v1 HMAC key is not referenced by v2.

## v2 container

The wire format is canonical JSON with this logical shape:

```json
{
  "format": "passwordsaver-v2",
  "version": 2,
  "aead": "aes-256-gcm",
  "kdf": {
    "id": "argon2id",
    "version": 19,
    "time": 3,
    "memoryKiB": 65536,
    "threads": 4,
    "salt": "base64"
  },
  "wrapNonce": "base64",
  "wrappedDEK": "base64",
  "nonce": "base64",
  "ciphertext": "base64"
}
```

`wrappedDEK` is the output of AEAD encryption of the 32-byte DEK. `ciphertext` is the output of AEAD encryption of the application payload. In both fields Go's `cipher.AEAD.Seal` appends the authentication tag to ciphertext; tags are not separate unauthenticated fields. AES-256-GCM uses a 32-byte key, 12-byte nonce, and 16-byte tag.

The container has two authentication domains. The payload domain covers only immutable content metadata (format ID, version, content AEAD ID, and payload nonce). The wrapper domain covers the format ID, version, AEAD ID, KDF ID/version/parameters, salt, and wrapper nonce. KDF and wrapper metadata are deliberately absent from payload AAD, so changing the master password does not invalidate the data ciphertext.

The parser first caps the serialized container at 44 MiB, rejects unknown JSON members and noncanonical JSON (including duplicate fields, alternate ordering, whitespace, or trailing values), then validates format/version, algorithm IDs, base64 lengths, nonce lengths, ciphertext/tag lengths, and KDF bounds. Payloads are capped at 32 MiB. These checks happen before Argon2id.

### AAD encoding

AAD is deterministic binary encoding, independent of JSON's textual representation. Integers use fixed-width big-endian encoding. Byte strings use a four-byte big-endian length followed by exactly that many bytes.

The DEK-wrap AAD is the domain separator `PasswordSaver/v2/DEK-WRAP\0`, then length-prefixed format ID, 16-bit version, length-prefixed AEAD ID, length-prefixed KDF ID, 32-bit Argon2 version, 32-bit time cost, 32-bit memory in KiB, one-byte thread count, length-prefixed decoded salt, and length-prefixed wrap nonce. This independently authenticates the changeable key-wrapper metadata.

Payload AAD is the domain separator `PasswordSaver/v2/PAYLOAD\0`, then length-prefixed format ID, 16-bit version, length-prefixed AEAD ID, and length-prefixed payload nonce. The payload nonce is also the nonce argument to AEAD; including it in AAD is intentional redundancy. It does not include the salt, KDF parameters, wrapper nonce, or wrapped DEK. Those fields are authenticated by the independent wrapper AEAD operation.

The strict JSON encoding plus these length-delimited AAD encodings avoid ambiguous metadata representations. Unknown versions, KDFs, or AEAD IDs are rejected; there is no fallback to v1 or another algorithm.

## Key flow and lifetime

1. For each encryption, `crypto/rand.Reader` supplies a fresh 32-byte DEK, a 32-byte Argon2id salt, and separate algorithm-generated nonces for wrapping and payload encryption. `AEADAlgorithm` owns both nonce generation and nonce validation. AES-256-GCM reads 12 random bytes. The reusable RFC 9058 MGM nonce policy generates one block of random bytes and sets the most-significant bit, and rejects a wrong block length or a nonce with that bit clear. This policy is only a nonce helper; Kuznyechik-MGM itself is not implemented.
2. Argon2id derives a 32-byte KEK from the master password and fresh salt. The default is time cost 3, 64 MiB, and four lanes. Accepted container bounds are time 2–6, memory 19–256 MiB, and 1–8 threads. The parser enforces these bounds before key derivation.
3. The KEK wraps the DEK with the selected AEAD and DEK-wrap AAD.
4. The DEK encrypts one payload with the same AEAD implementation and payload AAD.
5. The DEK, KEK, and temporary password byte copy are overwritten on return paths. The returned plaintext belongs to the caller and is not erased by the engine.

### Master-password change

`ChangeMasterPassword` first parses and authenticates the existing wrapper and payload with the current password. It returns an error without producing a replacement if either AEAD authentication fails. After successful verification, it generates a fresh salt and algorithm-validated wrapper nonce, derives a new KEK from the new password, and encrypts the same DEK into a new wrapper. The payload ciphertext and payload nonce are copied unchanged. Payload authentication is independent of wrapper metadata, while the new wrapper authenticates its own salt, KDF parameters, and nonce. This operation is an in-memory container transform only; the caller must later use a separately reviewed atomic persistence flow.

Each derived KEK is used for one wrap operation, and each fresh DEK is used for one payload operation. The wrap and payload nonces are generated by separate reads from the secure random source. There is no same-key nonce reuse within a container. As with any random-nonce design, global uniqueness is probabilistic; fresh per-container keys limit the consequence of a nonce collision across containers.

Go cannot promise that every compiler/runtime copy of a string or byte slice has been physically erased. Wiping is best effort and does not protect against a process already able to inspect this process's memory.

## Algorithm extension point

`AEADAlgorithm` exposes an ID, key/nonce/tag sizes, algorithm-specific nonce generation and validation, and a constructor returning Go's `cipher.AEAD`. The engine validates nonce policy both when generating a nonce and when parsing a container, checks the AEAD's reported nonce/tag sizes, and passes AAD through `Seal` and `Open`. The registry rejects duplicate or unknown identifiers. AES-256-GCM is the only production algorithm provider in this stage. The RFC 9058 nonce policy and test-only provider exercise the extension point; they are not MGM encryption. A future Kuznyechik-MGM implementation must provide a reviewed `cipher.AEAD`-compatible implementation, enforce the full RFC 9058 requirements, and pass known-answer and interoperability tests before registration. Do not implement a cipher or mode locally, and do not silently reinterpret existing IDs.

## Threat model and limits

AEAD authenticates the encrypted DEK, payload, and covered metadata. A wrong master password, altered salt/KDF parameter, altered nonce, ciphertext, tag, or bound metadata fails closed. Resource caps limit hostile-container parsing and Argon2id work. The container does not authenticate a filename or external filesystem metadata; callers must bind any required context through their own AAD design in a future format revision.

This package does not implement password-strength policy beyond the current 12-byte minimum, online throttling, OS key storage, anti-malware protection, memory isolation, or file replacement/backup. Argon2id only raises the cost of offline password guessing; weak master passwords remain vulnerable to offline attacks. Random-source failure aborts encryption.

## Future migration procedure

Migration is deliberately out of scope. A later integration must be explicit and separately reviewed: preserve the original v1 primary and `.bak`; authenticate and decrypt v1 only with the existing v1 loader; write a v2 container to a separate temporary or side-by-side path; reopen and authenticate the v2 output; then request explicit user confirmation before switching the active format. Retain recoverable v1 bytes until successful verification and a documented rollback window. Never infer v2 from a failed v1 password, overwrite the only v1 copy, or silently migrate on `LoadVault`.

## Atomic storage integration

The current `SaveVault`/`LoadVault` path consumes v1's `EncryptedData` and static HMAC envelope. A v2 container cannot be passed to those functions, and doing so would break existing files and recovery expectations. If v2 storage is integrated later, keep format dispatch explicit, preserve v1 reading, and reuse/adapt the existing atomic replacement and encrypted-backup mechanisms only after defining how v1 and v2 backups are distinguished and restored. This PR keeps all persistence code untouched.
