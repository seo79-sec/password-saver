# Preparing a PasswordSaver Windows release

This project currently prepares a Windows x64 executable. Release preparation does not create or publish a GitHub Release.

## Build the candidate

The repository contains `.github/workflows/release-candidate.yml`. After that workflow has landed on `main`, open **Actions → Build Windows release candidate → Run workflow**, select the reviewed `main` commit, and run it. The workflow runs the Go tests/build, frontend tests/build, and Wails Windows build, then uploads `password-saver-v1.1.0-windows-amd64` as a short-lived Actions artifact. It does not create a tag or release.

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

1. Confirm all required GitHub Actions checks are green on the exact `main` commit being released.
2. Complete and record [`WINDOWS_MANUAL_TEST.md`](WINDOWS_MANUAL_TEST.md) on a Windows 10/11 x64 machine using disposable test data only.
3. Review the [1.1.0 changelog](../CHANGELOG.md), app version metadata, binary checksum, and packaged startup on a clean machine with WebView2 Runtime.
4. Ensure no `vault_data.enc`, `.bak`, diagnostic archive, or test secret is included with release assets.

## Publish manually after approval

1. Create and push the annotated tag `v1.1.0` at the approved `main` commit.
2. In GitHub, choose **Releases → Draft a new release**, select `v1.1.0`, and use the changelog as release notes.
3. Attach `password-saver.exe` and `password-saver.exe.sha256` from the reviewed candidate. Verify the checksum against the uploaded executable.
4. Save as a draft for review. Publish only after the release owner explicitly approves.

Do not commit or upload a real vault or any user data. Re-check the artifact contents before attaching files.
