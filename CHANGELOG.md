# Changelog

## 0.0.4

### Added

- Resumable Better Auth agent connect, status, execute, and revoke commands with private local registration storage.
- Server-authoritative approval status, persisted retry timing, and provider-origin transport checks.

### Changed

- `identity create` mints a Type42 `rootPk` directly (`PrivateKey.fromRandom().toWif()`). No HD wallet, mnemonic, seed, or `m/0'/0` hop. Existing Type42 `.bep` files keep working; no re-key.

### Removed

- `--show-mnemonic` and `--mnemonic-file`

## 0.0.3

### Added

- `diagnose bap` — public `GET /api/bap/profile`; optional `--pubkey` checks `GET /api/user/bap-ids`
- `diagnose identities` — list registered BAP ids by `--pubkey` or session
- `diagnose last-oauth` — last selected identity for `--pubkey` `--client-id`
- `diagnose client` — public OAuth client metadata

## 0.0.2

### Security

- `backup push` requires a bitcoin-backup ciphertext envelope; WIF, mnemonic, xprv, and raw text are refused
- Whitespace-only `SIGMA_BACKUP_PASSWORD` fails closed without trimming the env value

### Fixed

- `identity create --signin` with `--password-stdin` no longer consumes stdin twice
- Failed BAP registration signs out and deletes the cookie jar
- HTTP errors include `Retry-After` when the server sent it
- `doctor --json` failure includes `data.checks`

## 0.0.1

### Added

- Initial `@sigma-auth/cli` (`sigma`) for headless Sigma Auth
- `identity create` — Type42 master + first BAP, encrypted `.bep` locally
- `identity info` — public fields from a local backup
- `backup encrypt` — JSON → `.bep`
- `backup push` — ciphertext only (plaintext refused)
- `auth sign-in` — member-key Bitcoin-Auth, cookie jar, BAP register
- `oauth register` — session `/api/oauth-clients` or RFC 7591 DCR
- `doctor` — env, files, RFC 8414, session
- Password from `--password-file`, `--password-stdin`, or `SIGMA_BACKUP_PASSWORD` only; `--password` on argv is rejected
- Empty `SIGMA_AUTH_URL` fails closed; default unset is `https://auth.sigmaidentity.com`
