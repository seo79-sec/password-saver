# Preparing a PasswordSaver Standard 2.0.0 Windows release

This project builds the Windows x64 Standard executable. Release candidate preparation does not publish a GitHub Release. A separate manual workflow creates a **draft release** with verified archive checksums; public publication remains a separate, human-approved action.

## Build the candidate

The repository contains `.github/workflows/release-candidate.yml`. After that workflow has landed on `main`, open **Actions → Build Windows release candidate → Run workflow**, select the reviewed `main` commit, and run it. The workflow runs the Go tests/build, frontend tests/build, and Wails Windows build, then uploads `password-saver-standard-v2.0.0-windows-amd64` as a short-lived Actions artifact. It builds Standard only; there is no GOST Lab build. It does not create a tag or release.

For a local Windows build, install Go 1.26.4+, Node.js 24, Wails CLI v2.12.0, and the Windows build tools/WebView2 prerequisites listed in the README. From the repository root:

```powershell
go test ./...
go test -race ./...
go build ./...
Push-Location frontend
npm ci
npm test
npm run build
Pop-Location
wails build -platform windows/amd64 -clean
```

The executable is `build\bin\password-saver.exe`. Calculate its SHA-256 and distribute that checksum beside the executable:

```powershell
$hash = (Get-FileHash .\build\bin\password-saver.exe -Algorithm SHA256).Hash.ToLower()
"$hash  password-saver.exe" | Set-Content .\build\bin\password-saver.exe.sha256 -NoNewline
```

## Manual release gate

Before making a release public:

1. Confirm all required GitHub Actions checks are green on the exact `main` commit being released, including Windows Wails build.
2. Complete and record [`WINDOWS_MANUAL_TEST.md`](WINDOWS_MANUAL_TEST.md) on a Windows 10/11 x64 machine using disposable test data only. Verify v1 recovery and explicit v2 backup recovery before approving release.
3. Review the [2.0.0 changelog](../CHANGELOG.md), `wails.json` product version, Standard edition metadata, binary checksum, and packaged startup on a clean machine with WebView2 Runtime.
4. Ensure no `vault_data.enc`, `.bak`, diagnostic archive, or test secret is included with release assets.

## Create the release draft and publish after approval

1. Merge the reviewed release packaging PR into `main` after all required checks pass on its commit.
2. In **Actions → Publish PasswordSaver Standard 2.0.0 draft → Run workflow**, select `main`. The workflow runs Go/frontend tests, Windows Wails build, checks the archive and SHA-256 values, creates a tag `v2.0.0` at exactly the workflow commit, and creates a **draft release** (not public).
3. Verify that the draft includes `PasswordSaver-Standard-2.0.0-Windows-x64.zip` and `.zip.sha256`. Download and independently verify both the ZIP hash and the inner `password-saver.exe.sha256`.
4. Run and document the final Windows manual test plan against this exact binary. Review `docs/RELEASE_NOTES_V2.0.0.md` and the SHA-256 checksums.
5. Only after approval, press **Publish release** on the draft in GitHub. Do not edit or replace assets without a new security review.

Do not run the draft workflow on a feature branch, force-move tags, or publish a release before verifying the binary.

Do not commit or upload a real vault or any user data. Re-check the artifact contents before attaching files.
