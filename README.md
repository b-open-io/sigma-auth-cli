# @sigma-auth/cli

Headless CLI for [Sigma Auth](https://auth.sigmaidentity.com). Create a Bitcoin (BAP) identity key **locally**, sign in with Bitcoin-Auth, push `bitcoin-backup` ciphertext, and register OAuth clients.

The server never sees private keys. Identity is a BAP member key, not an API key.

```bash
bunx @sigma-auth/cli --help
```

## Agent one-shot

```bash
export SIGMA_AUTH_URL=https://auth.sigmaidentity.com
export SIGMA_BACKUP_PASSWORD="$(openssl rand -base64 32)"

bunx @sigma-auth/cli identity create \
  --label "agent" \
  --out ./identity.bep \
  --signin \
  --push-backup \
  --json
```

## Commands

| Command | Job |
| --- | --- |
| `sigma identity create` | Create Type42 master + first BAP, encrypt `.bep` |
| `sigma identity info` | Public fields from a local backup |
| `sigma backup encrypt` | JSON → `.bep` |
| `sigma auth sign-in` | Member-key Bitcoin-Auth; cookie jar; register BAP |
| `sigma backup push` | POST ciphertext only |
| `sigma oauth register` | Session `/api/oauth-clients` or RFC 7591 DCR |
| `sigma doctor` | Env, files, RFC 8414, session |
| `sigma diagnose bap` | Public BAP profile; optional `--pubkey` registered-list check |
| `sigma diagnose identities` | `GET /api/user/bap-ids` (`--pubkey` or session cookie) |
| `sigma diagnose last-oauth` | Last selected BAP for `--pubkey` `--client-id` |
| `sigma diagnose client` | Public OAuth client metadata |

Password sources (exactly one): `--password-file`, `--password-stdin`, or `SIGMA_BACKUP_PASSWORD`. `--password` on argv is rejected.

## Diagnose (no private keys)

Public HTTP lookups against `https://auth.sigmaidentity.com`. Use these when a Sigma login shows the wrong faucet, a profile 404s, or last-selected identity looks stuck.

```bash
bunx @sigma-auth/cli diagnose bap --bap-id 3QpdyNb9HScYmWEyfqtRQbKzwyf --json
bunx @sigma-auth/cli diagnose bap --bap-id 33mGVYzkGE9XMbu346XkUaMHyzwV --pubkey 03a42932… --json
bunx @sigma-auth/cli diagnose identities --pubkey 03a42932… --json
bunx @sigma-auth/cli diagnose last-oauth --pubkey 03a42932… --client-id droplit --json
```

`diagnose bap` treats a profile 404 as a successful diagnosis (`found: false`), not a command failure.

Contract: `docs/specs/sigma-cli-v1.md` in [sigma-auth](https://github.com/b-open-io/sigma-auth).
