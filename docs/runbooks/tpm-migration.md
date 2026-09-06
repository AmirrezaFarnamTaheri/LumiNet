# TPM authorization migration

TPM migration is an explicit operator action. LumiNet does not migrate TPM
material during daemon or desktop startup.

## Support boundary

- Windows uses the current-user DPAPI native secret store.
- macOS uses Keychain Services in cgo-enabled builds. A build without cgo
  returns `native secret store unavailable`; it does not fall back to file
  storage.
- Linux uses the current user's D-Bus Secret Service. The user session must
  expose an unlocked default collection before migration; a missing service or
  an operation that would require an interactive unlock is a preflight failure,
  not permission to downgrade to file storage.
- `FileStore` is development or recovery-only and is rejected by production
  migration and verification.

## Preflight

Back up the existing public/private blobs and record their checksums. Confirm
the host has a usable TPM and choose a future RFC3339 compatibility cutoff.
The authorization reference is an identifier namespace only; do not place
secret bytes on the command line, in configuration, or in an environment
variable. Each attempt appends a fresh record identity to that namespace. If a
host loses power after the native-store write but before activation, a retry
uses a different reference and cannot overwrite or delete the staged value.

## Migrate and verify

```text
luminet tpm migrate \
  --record <data-dir>/tpm-envelope.json \
  --legacy-public <backup>/crypto.pub \
  --legacy-private <backup>/crypto.priv \
  --authorization-ref tpm/master-key/2026-07 \
  --legacy-cutoff 2026-08-29T00:00:00Z

luminet tpm verify --record <data-dir>/tpm-envelope.json
luminet tpm inventory --record <data-dir>/tpm-envelope.json
```

Migration recovers the legacy key, creates a per-envelope authorization in the
selected native store, seals a versioned envelope, reopens and compares it,
then atomically activates the record. A failure before activation leaves the
previous record active. Repository writes use a cross-process lock, a synced
same-directory temporary file, atomic rename, and directory sync where the
platform supports it.

The inventory output omits authorization references, TPM blobs, and secret
material.

## Roll back during the compatibility window

Stop the service before exporting rollback blobs:

```text
luminet tpm rollback \
  --record <data-dir>/tpm-envelope.json \
  --output-dir <recovery>/legacy-tpm-rollback
```

The output directory must not already exist. The command holds the lifecycle
lock while staging `crypto.pub`, `crypto.priv`, and a checksum manifest. It
checks cutoff authorization again immediately before publication and performs
the complete-directory rename as the next operation. This is an authorization
check under lock, not a claim that wall-clock time cannot advance after the
check. It refuses export when that check is at or after the recorded cutoff.
Restore the exported pair using the previous binary's documented offline
recovery process.

## Shorten or close the compatibility window

```text
luminet tpm cutoff \
  --record <data-dir>/tpm-envelope.json \
  --at 2026-08-01T00:00:00Z
```

A cutoff can be preserved or shortened, never extended. At or after the
cutoff, the isolated legacy reader and rollback export reject access. Retained
blob metadata remains in the repository for audit and an explicitly approved
retirement action; normal startup never reads it.
