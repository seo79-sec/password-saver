# PasswordSaver 1.1.0 — Windows manual test plan

Run all destructive checks with synthetic data in disposable folders. Do not point the test app at a personal vault.

## Preparation

1. Use a Windows 10/11 x64 test machine with Microsoft Edge WebView2 Runtime installed.
2. Copy `password-saver.exe` into a new empty folder, for example `%TEMP%\PasswordSaver-v1.1-test`.
3. Launch it with that folder as its working directory. From PowerShell:

   ```powershell
   $testDir = Join-Path $env:TEMP 'PasswordSaver-v1.1-test'
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

Record the Windows edition/build, app SHA-256, tester/date, pass/fail per item, and any reproduction steps. Stop release approval for any data loss, recovery without confirmation, stale secret shown after lock, failed valid TOTP retry, or unexpected network request.
