# Changelog

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
