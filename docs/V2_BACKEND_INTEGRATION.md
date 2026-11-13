# PasswordSaver v2 backend session and activation

## Scope and current UI behavior

This stage adds backend infrastructure only. It does not bind a v2 login, save, or activation method to Wails, and it does not enable v2 by default. Existing v1 files remain `vault_data.enc` and `vault_data.enc.bak`. The candidate/active v2 file is `vault_data.v2.enc`; `vault_format.state` records a durable selection. Normal v1 methods keep using v1 only. If the selector says v2, the existing Wails `Login` refuses to open v1, preventing an automatic downgrade until a future UI flow is added.

## Opaque v2 session lifecycle

`crypto/v2.Engine.Unlock` verifies the container structure and both AEAD authentication tags, derives the KEK from the supplied master password, unwraps the DEK, and returns an opaque `crypto/v2.Session` plus the decrypted payload. The session stores only the DEK and authenticated container metadata; it does not retain the master password and exposes no key getter. The caller decodes the Vault and best-effort clears the temporary plaintext bytes.

On close, logout, idle lock, or a detected external file change, the backend closes the opaque session and overwrites its DEK buffer. Go cannot guarantee erasure of all compiler/runtime copies or cryptographic internals. `App` serializes storage mutations and logout with its mutex; the crypto session also serializes operations and close with its own mutex.

Each save encrypts the updated Vault using the retained DEK, a new algorithm-generated nonce, and a new ciphertext. It preserves the original salt, KDF metadata, wrapper nonce, and wrapped DEK exactly. The session remembers every payload nonce used during its lifetime and the nonce in the container it opened; collisions are rejected and retried. On a later process/session restart only the latest on-disk nonce is available to seed this in-memory set. Random 96-bit AES-GCM nonces therefore retain a negligible probabilistic collision risk across old versions that are no longer present; there is no claim of a global rollback-resistant nonce ledger.

## Active format selector

The selector is canonical, versioned JSON stored at `vault_format.state` and committed using the existing same-directory temporary-file, file-sync, atomic-replace, and directory-sync path. It has three states:

- **No selector, no v2 file:** legacy v1 is active (including the initial empty-vault case). After a successful legacy login the backend writes an explicit `v1-only` selector.
- **`v1-only`:** v1 is explicitly active. A v2 candidate may exist, but it does not alter selection; it must be explicitly prepared before activation.
- **`v1-prepared`:** v1 is active and v2 is a candidate. SHA-256 snapshots identify both files and whether preparation is still fresh.
- **`v2-active`:** v2 is active. The retained v1 files are not consulted for reads or fallback.

Malformed/unknown selector state is ambiguous and blocks sensitive operations. A v2 file with no selector is also ambiguous; its presence does not select v2 or authorize a fallback to v1. A prepared record whose hashes no longer match still explicitly selects v1, but activation is rejected. An active-v2 record with a missing v2 file is ambiguous. Reset and v1 recovery are blocked while v2 is active or activation is prepared.

Selector data is local filesystem metadata, not cryptographically protected against an attacker with full filesystem control. An attacker able to rewrite or roll back all local files may roll back the selector too. The selector prevents accidental/implicit fallback and detects ordinary corruption; it is not an anti-rollback security boundary.

## Prepare and confirm activation

The unexported `v2ActivationService` is not a Wails binding. `Prepare` authenticates v1 through its existing HMAC + `CryptoManager` path and opens v2 through the v2 engine. It compares the complete `Vault` structure, including account fields and TOTP enabled/secret values. If 2FA is enabled, it requires a valid current TOTP code. It then records the exact source/candidate hashes as `v1-prepared` and returns a short-lived one-time challenge.

`Confirm` is the separate explicit confirmation step. It consumes the challenge, re-reads and re-authenticates both files using the master password, rechecks TOTP, compares their complete structures and prepared hashes, creates an encrypted v2 backup, reads it back, authenticates it, and compares it with the candidate. Only then does it atomically write `v2-active`. It never edits or deletes either v1 file and never refreshes an outdated candidate. If v1 changes after preparation, confirmation fails and v1 remains active.

The app wrapper closes any existing v1 session when the selector commit succeeds. If directory synchronization reports an uncertain result after replacement, it rereads the selector: when it says v2-active, the previous app session is closed and no v1 fallback occurs. An interruption before selector replacement leaves `v1-prepared` active; after replacement the selector chooses v2 even if the caller did not receive success.

## Canceling a prepared activation

Preparation does not change the active vault, but its `v1-prepared` selector intentionally blocks v1 reset and backup recovery until the user resolves the choice. `BeginCancelV2Preparation` and `ConfirmCancelV2Preparation` provide a separate internal, two-step cancellation. The first call requires a well-formed selector whose mode is exactly `v1-prepared` and returns a short-lived, one-time confirmation token. The second consumes that token, rereads the selector under the activation lock, verifies that the same prepared record is still current, and atomically writes `v1-only`.

Cancellation does not inspect, delete, rewrite, or replace `vault_data.enc`, `vault_data.enc.bak`, or `vault_data.v2.enc`. The v2 candidate remains available for another explicit preparation or a separately controlled future deletion flow. Cancellation refuses `v2-active`, missing, malformed, unknown, or changed selector state. It can still be started from a valid `v1-prepared` record after the candidate is missing or damaged; that lets the owner explicitly restore v1 recovery controls without silently treating an ambiguous directory as v1. After confirmed cancellation, ordinary v1 backup recovery is available again.

If the activation token expires, the application restarts, or token generation fails, the persistent selector remains safely non-active for v2. A fresh cancellation challenge can be issued from `v1-prepared` without relying on the old in-memory token. If preparation cannot generate its confirmation token before writing `v1-prepared`, it leaves the existing selector unchanged; when no selector existed, after both files have been explicitly authenticated and compared it persists `v1-only` so v1 recovery remains available. If cancellation confirmation itself expires, the user can begin a new cancellation. An atomic-selector directory-sync error is reported as an uncertain commit; reread the selector before retrying.

## Active v2 saves and failure behavior

The internal v2 session binds itself to the exact file bytes it authenticated at unlock. Before every save it checks that the selector still says v2-active and that the on-disk v2 bytes still match the session revision. It serializes and encrypts the candidate, writes the old encrypted bytes to `.bak`, verifies the backup bytes, checks the primary again, then atomically replaces the primary. It updates the in-memory session's file digest only after successful commit.

- Encryption or pre-commit write failure leaves the current primary unchanged; `App` restores the previous in-memory Vault state.
- A detected external change invalidates and closes the session; the app clears its in-memory Vault rather than treating stale data as current.
- A directory-sync failure after replacement is uncertain. The session is closed and the app locks; the selector remains v2-active, so no stale v1 fallback is attempted. Reopen and authenticate v2 to determine the committed contents.
- Backups are not automatically restored. A failed AEAD open never falls back to `.bak` or v1.
- A v1 reset/recovery attempt cannot remove or overwrite active v2 data. Recovery and reset require an unambiguous v1-active state with no pending v2 preparation.
- The selector and file are not one atomic multi-file transaction. The activation order makes the selector the final commit point; v1 remains intact until and after that point.

## Compatibility, threats, and limitations

The v1 storage format, AES-GCM/Argon2id parameters, v2 container format, existing Wails bindings, and user-facing UI are not changed. The stage reuses the authenticated v2 wrapper created during migration and does not re-enter the master password on each save. V1 remains recoverable and is preserved after activation.

AEAD cannot distinguish a wrong master password from damage to the authenticated key wrapper. Selector files are not protected against full local filesystem rollback. External programs do not honor the process mutex; hash checks detect persistent changes before/after operations but cannot eliminate every cross-process time-of-check/time-of-use race. Random nonce uniqueness across independent app restarts remains probabilistic because older nonce history is not persisted. Temporary plaintext and key wiping in Go is best effort.

## Next Wails/Svelte stage

Before exposing v2 to users, add an explicit format-aware login flow that calls the internal v2 unlock path only after reading the selector; present and require an explicit confirmation for the activation challenge; render TOTP flow without returning key material; and route all CRUD operations through the selected active session. Add user-visible handling for ambiguous selector state and uncertain commits. Keep format selection and backup recovery in backend code, and add end-to-end Windows tests before enabling any v2 UI path. Do not auto-activate v2 merely because a candidate file exists.
