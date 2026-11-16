# PasswordSaver editions

## PasswordSaver Standard (2.0.0)

Standard is the only edition built and supported by this release. Its v2
Crypto Engine is constructed without optional providers, so new v2 containers
use AES-256-GCM by default and the Standard registry accepts only
`aes-256-gcm`. The existing `AEADAlgorithm` interface and registry remain
modular for a future provider; no algorithm-specific branch is added to the
vault or UI.

New installations create a native v2 AES-256-GCM container and an encrypted
backup directly, without first writing v1. Initialization uses a distinct
`nativeV2` selector flag and does not touch existing files. A new folder
requires an explicit master-password creation step (at least 12 characters).
Partial setup artifacts block automatic retries rather than silently replacing
files; inspect them in a disposable test folder before resetting.

Standard continues to read the existing v1 `vault_data.enc` format and keeps
its explicit, user-confirmed migration to the v2 container. The v1 format and
active files are not rewritten by a release or by opening the application.
V2 records carry their algorithm ID; unsupported IDs fail closed, with no
fallback to AES or v1.

For data recovery, v1 backup restoration remains explicit and preserves a
damaged primary for diagnosis. Active v2 storage now has the same explicit
recovery boundary: the backup must authenticate with the supplied master
password; the user must confirm; an unchanged damaged primary is archived;
and the exact verified backup bytes replace it atomically. The selector stays
`v2-active`; recovery never falls back to v1. A recovery restores the backup's
snapshot and can lose edits made after that backup was created.

## PasswordSaver GOST Lab (future)

GOST Lab is a possible future educational and experimental edition using
Kuznyechik-MGM. It is not implemented, registered, built, or selectable in
2.0.0. The prior library assessment found that available Go providers have
material side-channel or licensing/review limitations; known-answer vectors
alone do not establish safety for password storage. Standard therefore does
not include a GOST dependency or provider.

If a future provider passes security, licensing, platform, and interoperability
review, it should implement the existing `AEADAlgorithm` contract and be
registered only in the GOST Lab engine constructor. It must receive a distinct
container ID. Standard must continue to reject that ID. Separate edition
builds and release artifacts would be introduced only in a later reviewed
change; this release has one Windows Standard artifact.

Neither edition may silently change the algorithm recorded by a container,
retry decryption with another algorithm, migrate v1 files in place, or rewrite
user data as part of installation or update.
