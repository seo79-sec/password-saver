# PasswordSaver 2.0 — Wails and Svelte v2 integration

## Format status and login

At startup the frontend asks Go for `GetVaultStatus()`. The response contains only a public state (`v1-active`, `v1-prepared`, `v2-active`, or `ambiguous`) and whether a v2 file is present/fresh. It contains no passwords, TOTP secret, container hashes, DEK, KEK, or session internals. Go remains responsible for validating the selector and choosing the login API. An ambiguous selector blocks both login paths; an active v2 selector always routes to `LoginV2`, even when its container is missing or damaged.

The v1 login and its TOTP step remain available for v1-active and v1-prepared. The v2 login opens an opaque `crypto/v2.Session` in Go. The password is passed only to the login call; the session retains the DEK and the backend holds the decrypted Vault for the existing CRUD APIs. If TOTP is enabled, the session remains locked until Go accepts `Verify2FA`. Wrong TOTP codes use the existing attempt limit. Logout, inactivity timeout, or a detected file change closes the session. Existing account listing, add, edit, delete, search, categories, password generation, clipboard, password visibility, and 2FA operations use the same App methods; v2 saves route through the v2 session and never call the v1 writer.

## Explicit migration and cancellation

From an authenticated v1 session, open **Security of vault** and choose **Update vault to v2**. Re-enter the v1 master password and, when enabled, a current TOTP code. The backend checks that the v1 file decrypts to the current session contents, stages a separate v2 container, reopens it, and compares the full Vault including TOTP settings. The selector remains v1-prepared, so the v1 session and files remain authoritative.

After verification, the dialog explains that activation is a separate action. The user re-enters the master password and TOTP and presses **Explicitly activate v2**. Go validates the challenge, current snapshots, credentials, TOTP and backup before switching the selector. The v1 session then closes and the user returns to the login screen for v2. An expired or consumed challenge can be reissued by rerunning preparation; a changed candidate must be cancelled and prepared again.

The **Cancel preparation** action uses a separate begin/confirm challenge. It can be started after an app restart, token expiry, or missing v2 candidate when the selector is still a structurally valid v1-prepared record. Confirmed cancellation atomically writes v1-only and preserves the v1 primary, v1 backup, and v2 candidate. It is refused for v2-active and malformed/unknown selectors. A damaged selector requires manual recovery guidance; the UI does not infer v1 or v2 and does not automatically downgrade.

## Error behavior

- Wrong password, authenticated-container damage, wrong TOTP, and expired activation are shown as separate, nonsecret messages.
- Stale files require a new authenticated preparation. External changes close the v2 session and prevent stale saves.
- A missing or corrupt active-v2 container does not fall back to v1 or a backup. The status stays v2-active and the login reports that the v2 container is unavailable.
- Disk-full and uncertain-sync errors do not report a successful save. After an uncertain commit, the backend closes the session and asks the user to verify the active format/content before retrying.
- Ambiguous or damaged selectors block login and reset/recovery actions. Cancellation is offered only when strict selector validation confirms v1-prepared.

## Manual Windows test sequence

Use a disposable Windows account/profile and synthetic data such as `test@example.invalid` and `Synthetic-Password-42!`. Do not use a personal vault.

1. Start with a v1 test vault containing several categorized records and TOTP enabled. Verify v1 login, TOTP, search, edit, delete, password show/hide, copy/clipboard clearing, and manual lock.
2. In the security section, prepare v2 with the correct master password and TOTP. Verify the confirmation dialog says the container was reopened and checked, then close it without activating. Confirm `vault_data.enc` and `vault_data.enc.bak` remain unchanged.
3. Reopen the app while the selector remains v1-prepared. Verify v1 login is still selected. Prepare again, then explicitly cancel. Verify both v1 files and the v2 candidate still exist and v1 backup recovery controls are available.
4. Prepare again, confirm v2 activation, and log in using the v2 password and TOTP. Verify account contents and categories match the original. Exercise add/edit/delete, password generation, visibility, copy, TOTP setup/verification, manual lock, and the configured inactivity timeout.
5. Restart and verify status remains v2-active and login opens v2. Verify the v1 login path does not open v1 while v2 is active. In a disposable copy only, remove or damage the v2 file and confirm the UI reports unavailable without fallback.
6. In a separate disposable copy, corrupt or replace the selector with unknown JSON and confirm login is blocked. Check that cancellation is not offered for this state and v1/v2 files are untouched.
7. Test a read-only destination and a full-disk or simulated write failure if the Windows test harness supports it. Confirm errors are visible and no success state is shown.

## Limits

The Wails binding passes plaintext passwords and TOTP codes only as transient method arguments. JavaScript and Go runtime memory cannot be guaranteed fully erased. The selector is local metadata, not protection against a process that can rewrite all user files. v2 remains AES-256-GCM with Argon2id; MGM is not implemented. No v1 file is automatically deleted, migrated in place, or used as fallback from active v2.

The current v2 engine requires a master password of at least 12 characters. A shorter legacy v1 password cannot be migrated by this flow; it fails before activation and leaves v1 unchanged. A password-change workflow for upgrading such a password is a separate follow-up.
