# PasswordSaver Standard 2.0.0 — Windows manual test plan

Run all destructive checks with synthetic data in disposable folders. Do not point the test app at a personal vault.

## Preparation

1. Use a Windows 10/11 x64 test machine with Microsoft Edge WebView2 Runtime installed.
2. Copy the Standard `password-saver.exe` into a new empty folder, for example `%TEMP%\PasswordSaver-standard-v2-test`.
3. Launch it with that folder as its working directory. From PowerShell:

   ```powershell
   $testDir = Join-Path $env:TEMP 'PasswordSaver-standard-v2-test'
   New-Item -ItemType Directory -Force $testDir | Out-Null
   Copy-Item .\password-saver.exe $testDir
   Start-Process -FilePath (Join-Path $testDir 'password-saver.exe') -WorkingDirectory $testDir
   ```

4. Create a test-only master password with at least 12 characters. Use synthetic service names, logins, and passwords such as `Example Test`, `tester@example.invalid`, and `NotARealSecret-123!`.

## Checklist

- [ ] **First run and save:** unlock the new empty vault; add a synthetic record; lock and reopen. Confirm the record remains and its password is hidden until its own Show button is used.
- [ ] **Password form and copy:** add/edit a synthetic password and confirm the input is masked by default. Copy the saved password while it remains hidden.
- [ ] **Clipboard safety:** set 15 seconds, copy a test password, then copy unrelated text from Notepad before the timeout. Confirm the newer Notepad text remains. Repeat for 30/60-second settings if practical. If clipboard read permission is denied, confirm the app reports the error and leaves the clipboard alone.
- [ ] **Backup creation:** save a record, then change and save it again. Confirm `vault_data.enc` and `vault_data.enc.bak` exist in the test working directory. Close the app before inspecting or changing files.
- [ ] **Backup recovery:** make a separate copy of the test folder. In that copy only, replace `vault_data.enc` with a short dummy string while retaining `.bak`. Launch the app, enter the test master password, accept the explicit recovery prompt, and confirm the backup record opens. Confirm the damaged primary was retained as `vault_data.enc.corrupt-*`.
- [ ] **Wrong recovery password:** in another disposable copy, damage the primary again and try an incorrect test master password. Confirm restore is unavailable and the damaged primary remains unchanged.
- [ ] **Legacy compatibility:** from the source checkout, copy `testdata/vault_data_v1_legacy.enc` to a separate test folder as `vault_data.enc`, run the app from that folder, and unlock with the fixture-only password `legacy-fixture-key`. Confirm the fixture record appears. Do not use this fixture procedure with user data.
- [ ] **TOTP:** enable TOTP using a test authenticator, verify one incorrect code is rejected and a current valid code succeeds. Lock and log in again; confirm the second factor is required. Optionally enter five wrong codes to verify the backend lockout, wait one minute, and retry.
- [ ] **Idle lock with a modal open:** set idle timeout to one minute, open the TOTP setup modal, then do not interact for at least 70 seconds. Confirm the login screen returns, the modal closes, and the vault remains locked. Reopen only with the test master password and complete TOTP if enabled.
- [ ] **State cleanup on manual lock:** while logged in, show a password, start an edit, and open a sensitive setup modal. Lock manually. Confirm the login screen is shown and no password, code, edit form, or modal remains visible.
- [ ] **State cleanup on idle lock:** repeat the previous check with the one-minute idle lock, including while a modal is open.
- [ ] **Reset challenge:** only in the disposable test folder, start reset, cancel it, and confirm both files remain. Repeat and explicitly confirm; confirm only the test vault and its backup are removed.
- [ ] **HIBP privacy:** use only synthetic test passwords. Confirm the UI explains the network request before starting it and reports network failure clearly when offline. Never use personal credentials for this check.
- [ ] **V2 migration and backup:** in a disposable folder with a synthetic v1 vault, prepare and explicitly confirm migration to v2. Confirm `vault_data.enc` and its `.bak` remain unchanged. Make two synthetic v2 saves and close the application so `vault_data.v2.enc.bak` contains a known earlier state.
- [ ] **V2 backup recovery:** copy the entire disposable folder, including `vault_format.state`, to another test folder. In the copy only, damage `vault_data.v2.enc`. Start the app and use **Восстановить из резервной копии v2** with the test master password. Confirm the dialog warns about restoring the backup snapshot, accept it, and complete TOTP if enabled. Verify the damaged file is preserved as `vault_data.v2.enc.corrupt-*`, the backup bytes are unchanged, the selector stays `v2-active`, and the recovered entries match the backup snapshot.
- [ ] **Missing V2 primary:** in another copy, remove `vault_data.v2.enc` while retaining the active selector and `.bak`. Confirm the UI does not offer v1 login, recovery remains explicitly available, and the restored v2 vault opens with the test password.
- [ ] **V2 recovery failures:** with copies only, try a wrong master password, cancel the confirmation, and change the backup after preparation. Each case must leave the primary/backup unchanged and the app locked. Confirm a valid primary cannot be replaced by an older backup; future version/algorithm containers are refused without file changes.
- [ ] **TOTP rollback boundary:** make a v2 backup before enabling TOTP, then enable TOTP and create a newer save. In a copy, damage the primary and explicitly restore the older backup. Confirm the dialog warns that TOTP settings are restored from the backup and the restored older snapshot does not request TOTP. Record that full local filesystem access can also replace backups and selector state, so the app cannot guarantee rollback detection.
- [ ] **Recovery requires a fully locked app:** begin a v2 login and stop at the TOTP prompt. Confirm backup recovery cannot start until the pending session is closed with Logout. Repeat while fully logged in and confirm recovery is unavailable.

Record the Windows edition/build, app SHA-256, tester/date, pass/fail per item, and any reproduction steps. Stop release approval for any data loss, recovery without confirmation, damaged primary not preserved, stale secret shown after lock, failed valid TOTP retry, unexpected network request, or an active-v2 fallback to v1.
