# PasswordSaver v2 storage and v1 migration

## Scope and active files

This layer is separate from the Wails interface and from the existing `SaveVault` and `LoadVault` functions. The current application continues to use `vault_data.enc` and `vault_data.enc.bak` as its active v1 files. `vault_data.v2.enc` is an explicitly addressed v2 candidate produced by the standalone API; finding it does not switch the application to v2. Both files may exist, and v1 remains active until a later, separately reviewed activation change.

The layer uses the existing `Vault` structure, including every current account field, `TwoFAEnabled`, and `TwoFASecret`. It serializes that structure to JSON and delegates encryption, parsing limits, and AEAD authentication to `crypto/v2`. The v2 file has no v1 static HMAC. The existing v1 serializer, encryption format, primary file, backup, and restore behavior are not changed by migration.

## Format detection and errors

`DetectVaultFormat` classifies the serialization shape only. A top-level `format` marker identifies a v2 candidate even when the value is unsupported. A v1 candidate has the legacy encrypted-data JSON shape followed by its signature bytes. The detector does not verify the v1 HMAC or authenticate a v2 tag. Unknown shapes are rejected.

V2 reading is always explicitly requested for a path. A failed v2 authentication never retries as v1 or consults a v1 backup. Structural v2 damage, unsupported format/algorithm, and AEAD authentication failure have separate error classes. AEAD cannot distinguish a wrong master password from damage to an authenticated wrapper: both fail the same tag check. The API reports that honestly as “password may be incorrect or authenticated data may be damaged”; it does not claim certainty it cannot provide. V1 HMAC validation does distinguish damaged serialized bytes from a decryption failure under the supplied password.

The file reader checks the file's size before reading and uses a bounded read. The crypto engine then performs bounded, cheap structural and KDF-parameter checks before Argon2id. Errors include no password, account, or plaintext values.

## V1 to v2 preparation

`MigrateV1VaultToV2` reads the existing primary v1 file, verifies its existing HMAC and decrypts it with the v1 `CryptoManager`, serializes the complete `Vault`, and encrypts it with `crypto/v2` to a separate path. It refuses to start when the source is absent, invalid, or has the wrong master password, and refuses any existing target. It does not read, restore, or replace the v1 `.bak`.

Before writing, migration re-reads and compares the source snapshot. It repeats this comparison after reopening and authenticating the new v2 file and comparing its structured `Vault` to the source structure. The process-wide vault lock prevents concurrent changes through this application's v1 save path during the migration. External processes do not participate in that mutex; persistent external changes detected by the before/after comparisons cause migration to return an error. An external writer that races between checks cannot be globally locked out on every supported filesystem, so the source remains the authoritative copy and the candidate is never activated automatically.

Successful output is a preparation artifact only. No application setting, UI state, or file-selection logic is changed. The original `vault_data.enc` and `vault_data.enc.bak` stay byte-for-byte unchanged.

## File writes, backups, and interruption behavior

New v2 files are written to a mode-0600 temporary file in the destination directory. The file data is synchronized before a no-replace atomic commit. Unix-like systems create the destination with a same-directory hard link, which fails if it already exists; Windows uses `MoveFileEx` without the replace flag and with write-through. The directory is synchronized where supported. Existing v2 updates first authenticate the current file, recheck that it has not changed, atomically save its encrypted bytes as `.bak`, recheck the primary, and then atomically replace it using the repository's existing replacement helper. A failed backup or detected concurrent change prevents replacing the primary.

- Before commit, a process crash or write/flush failure can leave a hidden temporary file. The source remains unchanged; a future cleanup routine may remove stale `.vault-v2-stage-*` files after validating that they are not active.
- A no-replace collision leaves the existing target untouched.
- If the filesystem reports a directory-sync error after commit, the result is uncertain. The v1 source remains intact and authoritative; inspect and authenticate the staged v2 candidate before retrying.
- A damaged v2 file is rejected. The layer does not automatically restore `.bak`, because it has no generation counter or trusted freshness metadata to prove that the backup is newer. Recovery must be an explicit future operation that authenticates the selected copy and verifies its contents before replacement.
- Disk-full, permission, and filesystem errors are returned without logging plaintext. Migration does not delete or rewrite v1 data.

## Rollback and future activation

Until v2 activation is implemented, rollback is simply to keep using the unchanged v1 active path. The v2 candidate may be retained for analysis or explicitly removed after the user verifies that the v1 primary and backup remain available. There is no automatic cleanup, restore, or active-file switch in this stage.

A future activation step must be separate and explicit: authenticate both formats; preserve the v1 primary and backup; create and verify a v2 backup; require user confirmation; atomically change a durable format-selection record; and define recovery for power loss between each step. It must also establish freshness/version metadata before considering any automatic backup selection. Never choose an older backup solely because the current file fails authentication.

## Current limitations

- The UI and normal `SaveVault`/`LoadVault` paths do not call this v2 layer.
- AEAD authentication failure cannot uniquely identify wrong-password versus authenticated-byte damage.
- Process-level locking does not prevent an unrelated process from editing files. Migration detects persistent source changes around the operation but cannot provide a universal cross-platform external lock.
- No migration cancellation/resume journal, stale temporary-file cleanup, v2 backup recovery flow, or active-format switch exists yet.
- Memory clearing is best effort in Go; strings, compiler/runtime copies, and cryptographic internals cannot be guaranteed erased.
