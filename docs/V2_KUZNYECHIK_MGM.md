# Kuznyechik-MGM provider assessment

**Status: blocked; no provider is registered.** AES-256-GCM remains the only
implemented/default v2 algorithm. This assessment deliberately does not copy
or reimplement a block cipher or MGM.

## Standards reviewed

- [RFC 7801](https://www.rfc-editor.org/rfc/rfc7801) specifies the 256-bit
  Kuznyechik key and 128-bit block. Its Appendix A vectors are also presented
  in section 5 of the RFC.
- [RFC 9058](https://www.rfc-editor.org/rfc/rfc9058) specifies MGM, including
  the 128-bit ICN with a zero most significant bit, 128-bit maximum tag,
  non-repeating nonce requirement for each key, and the prohibition on
  simultaneously empty associated data and plaintext. Appendix A.1.1 and
  A.1.2 are the Kuznyechik test vectors.

The existing v2 nonce policy already generates a block-sized nonce and clears
its top bit. It is only a shape check: it does not by itself guarantee nonce
uniqueness. The v2 session tracks payload nonces for a retained DEK, while new
containers use fresh DEKs. Any future MGM provider must retain those lifecycle
properties and must reject empty AAD plus empty plaintext before calling an
AEAD implementation whose `Seal` reports invalid inputs by panicking.

## Implementations evaluated

### `github.com/krotos139/go-gostcrypto` v1.0.0

- MIT license; pure Go, no cgo or external Go dependencies; requires Go 1.24.
- Provides `gost3412/kuznyechik.NewCipher` as a `cipher.Block` and
  `mgm.NewMGM` as a `cipher.AEAD`. It supports the required 16-byte tag, checks
  the nonce length and top bit, rejects an empty AAD/plaintext pair, and
  enforces RFC 9058's encoded-length limit.
- The Kuznyechik and MGM package tests pass, including the published RFC 7801
  block-cipher vectors and both Kuznyechik RFC 9058 Appendix A vectors. The
  packages also cross-compile to Windows/amd64 as pure Go.
- **Blocker:** the library explicitly documents that its table-based
  Kuznyechik is not protected against cache-timing attacks. Source inspection
  confirms data-dependent lookups in the S-box and multiplication tables.
  These operations process secret-dependent cipher state. The project also
  describes itself as educational/research software, says it is not a
  certified product, and gives no independent security audit. Passing test
  vectors establishes functional agreement for those inputs; it does not
  establish resistance to side channels or a broader security review.

This implementation has the best API and license fit among the candidates
reviewed, but its documented side-channel limitation makes it unsuitable to
enable for a password vault without an explicit, accepted threat-model
decision and an adequate implementation review.

### `github.com/pedroalbanese/gogost`

- GPL-3.0; pure Go, with Kuznyechik and MGM packages and RFC 9058 vectors.
- Its MGM and Kuznyechik code is table-based. The MGM implementation also
  retains mutable scratch buffers on the AEAD object, so callers must not
  assume concurrent operations on one instance are safe.
- The reviewed upstream snapshot is older than the MIT candidate. The GPL
  license and implementation properties make it a poor fit here.

### Other candidates

- `github.com/maxyotka/gost-crypto` is AGPL-3.0 and has a newer but similarly
  table-based Kuznyechik implementation. Its MGM `Seal` path does not reject
  the RFC-prohibited case where both plaintext and AAD are empty.
- The RU-WireGuard fork includes custom MGM and Kuznyechik code, but the
  reviewed code is GPL-3.0, table-based, and specialized for its project. It
  is not an appropriate drop-in provider for this application.

No candidate reviewed combines a suitable license, the required API and
vectors, and a sufficiently supported side-channel/security posture for
unqualified use in this vault.

## Recommendation and alternatives

1. Keep AES-256-GCM as the only selectable and default v2 algorithm. Existing
   containers and the v2 serialization remain unchanged.
2. Reconsider MGM when a provider with a suitable license, public review, and
   a defensible constant-time implementation is available, or after a focused
   review explicitly accepts the cache-timing exposure for the desktop threat
   model. Such acceptance should be a documented security decision, not an
   implicit consequence of passing known-answer tests.
3. A separately maintained native provider could be evaluated as an
   alternative, but it would need a clear Windows distribution story, a
   stable API, licensing review, reproducible builds, and platform-specific
   side-channel analysis. Adding cgo or a system crypto dependency without
   those checks would trade one uncertainty for another.

If a provider is reconsidered, its integration must use a distinct algorithm
ID, retain AES read compatibility, reject unknown IDs, and add project-level
tests for RFC 7801/RFC 9058 vectors, container round trips and tampering,
password changes without payload re-encryption, session nonce uniqueness,
parallel use, and session closure. No current container should be rewritten
or switched automatically.

## Verification performed for this assessment

Using `go-gostcrypto` v1.0.0 source, `go test ./gost3412/kuznyechik ./mgm`
passed. Windows/amd64 test binaries for both packages compiled successfully;
they were not executed on Windows. These checks establish conformance to the
included test vectors and build compatibility only. They do not clear the
side-channel blocker or substitute for an independent cryptographic audit.
