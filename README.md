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

Password sources (exactly one): `--password-file`, `--password-stdin`, or `SIGMA_BACKUP_PASSWORD`. `--password` on argv is rejected.

Contract: `docs/specs/sigma-cli-v1.md` in [sigma-auth](https://github.com/b-open-io/sigma-auth).
