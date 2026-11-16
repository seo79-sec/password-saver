# PasswordSaver v2 storage and v1 migration

## Scope and active files

The v2 storage layer is separate from v1's `SaveVault` and `LoadVault` serialization. The application supports both formats through a strict selector. `vault_data.enc` and `vault_data.enc.bak` retain their v1 format; `vault_data.v2.enc` is a separately encrypted v2 container and `vault_format.state` records whether v1 or v2 is active. Merely finding a v2 candidate does not switch formats; migration and activation require explicit, separate user actions.

The layer uses the existing `Vault` structure, including every current account field, `TwoFAEnabled`, and `TwoFASecret`. It serializes that structure to JSON and delegates encryption, parsing limits, and AEAD authentication to `crypto/v2`. PasswordSaver Standard registers AES-256-GCM only. The v2 file has no v1 static HMAC. The existing v1 serializer, encryption format, primary file, backup, and restore behavior are not changed by migration.

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
- A damaged or missing active v2 primary is never automatically replaced. The Wails flow offers explicit two-stage recovery only after the backup authenticates with the supplied master password. It binds confirmation to the exact backup and primary snapshots, preserves a damaged primary in a `.corrupt-*` archive, and restores the checked backup bytes. There is no freshness counter; recovery can lose saves made after the backup snapshot, which the confirmation dialog discloses.
- Disk-full, permission, and filesystem errors are returned without logging plaintext. Migration does not delete or rewrite v1 data.

## Rollback and future activation

Before activation, rollback is simply to keep using the unchanged v1 active path; v2 preparation can be explicitly cancelled. After activation, v2 remains selected through missing/corrupt-primary recovery; neither login nor recovery falls back to v1. The v2 candidate is not automatically deleted.

A future activation step must be separate and explicit: authenticate both formats; preserve the v1 primary and backup; create and verify a v2 backup; require user confirmation; atomically change a durable format-selection record; and define recovery for power loss between each step. It must also establish freshness/version metadata before considering any automatic backup selection. Never choose an older backup solely because the current file fails authentication.

## Current limitations

- The UI and normal `SaveVault`/`LoadVault` paths do not call this v2 layer.
- AEAD authentication failure cannot uniquely identify wrong-password versus authenticated-byte damage.
- Process-level locking does not prevent an unrelated process from editing files. Migration detects persistent source changes around the operation but cannot provide a universal cross-platform external lock.
- No migration cancellation/resume journal, stale temporary-file cleanup, or anti-rollback freshness record exists yet. The active-format switch and explicit v2 backup recovery flow are implemented; recovery never falls back to v1.
- Memory clearing is best effort in Go; strings, compiler/runtime copies, and cryptographic internals cannot be guaranteed erased.
