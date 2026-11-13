# PasswordSaver

![Version](https://img.shields.io/badge/version-1.1.0-blue.svg)
![Go](https://img.shields.io/badge/Go-1.26.4+-00ADD8?logo=go)
![Svelte](https://img.shields.io/badge/Svelte-3.x-FF3E00?logo=svelte)
![Wails](https://img.shields.io/badge/Wails-v2.12-red.svg)

PasswordSaver is a local desktop password manager built with Go, Svelte, and Wails. The encrypted vault uses AES-256-GCM and Argon2id. The 1.1 release keeps the existing `vault_data.enc` format.

## Features

- Encrypted local vault with an encrypted `.bak` backup and an explicit recovery flow.
- Optional TOTP two-factor authentication.
- Password generator, categories, search, and password health indicators.
- Password values are hidden by default and can be copied without displaying them.
- Configurable idle lock (1, 5, 10, or 15 minutes) and clipboard clearing (15, 30, or 60 seconds).
- Optional Have I Been Pwned (HIBP) check. The app computes a SHA-1 hash locally and sends only its first five hexadecimal characters to the HIBP range API; it does not send the clear-text password.
- Service names are not sent to a third-party favicon service.

## Storage and privacy

The application reads and writes `vault_data.enc` relative to its current working directory. Keep the executable and its working directory in a writable location that you control. On subsequent saves, the previous encrypted vault is kept in `vault_data.enc.bak`. When the primary file is missing or damaged, the app checks the backup and asks before restoring it; a damaged primary is retained for diagnostics.

HIBP checks make a network request when the user explicitly starts a check. Use synthetic credentials when testing this feature. No clear-text password is sent to HIBP.

The UI drops references to sensitive values when the session locks, but JavaScript and the operating system do not provide a guarantee that every copy has been erased from memory. Clipboard clearing is best effort and depends on operating-system clipboard access.

## Build requirements

- Go **1.26.4 or newer**, according to `go.mod`.
- Node.js **24** and npm (use the version bundled with Node.js; CI runs `npm ci`).
- Wails CLI **v2.12.0**.
- For Windows builds from source: Windows 10/11, a supported MinGW-w64 C compiler as required by Wails, and WebView2 tooling/runtime. See the [Wails Windows installation guide](https://wails.io/docs/gettingstarted/installation).
- For running the packaged Windows app: Microsoft Edge WebView2 Runtime.

## Build and test

```sh
go test ./...
go test -race ./...
go build ./...

cd frontend
npm ci
npm test
npm run build
cd ..

go install github.com/wailsapp/wails/v2/cmd/wails@v2.12.0
wails doctor
wails build -platform windows/amd64 -clean
```

The executable is written to `build/bin/password-saver.exe`. The supported release build is Windows x64. For the release-candidate workflow and manual Windows test plan, see [Release preparation](docs/RELEASING.md) and [Windows test plan](docs/WINDOWS_MANUAL_TEST.md).

## Install

Download `password-saver.exe` from the GitHub Releases page, verify its published SHA-256 checksum, and run it from a writable directory. WebView2 Runtime must be installed. Back up `vault_data.enc` and `vault_data.enc.bak` together before moving or replacing the application files. Never use a real vault for manual or destructive tests.

## Project

PasswordSaver was created as a student project at MTUSI. See the repository history for contributors and acknowledgements.
