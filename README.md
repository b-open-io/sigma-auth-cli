# @sigma-auth/cli

Headless CLI for [Sigma Auth](https://auth.sigmaidentity.com). Create a Bitcoin (BAP) identity key **locally**, sign in with Bitcoin-Auth, push `bitcoin-backup` ciphertext, and register OAuth clients.

The server never sees private keys. Identity is a BAP member key, not an API key.

`identity create` mints a Type42 `rootPk` directly. Existing Type42 `.bep` files keep working; no re-key.

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
| `sigma identity create` | Mint a Type42 `rootPk` + first BAP, encrypt `.bep` |
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


### Delegated agent authorization

```sh
sigma agent capabilities --json
sigma agent connect --name "My agent" --capability list_my_identities --capability list_authorized_apps --json
# Complete the returned verificationUri in your browser, using userCode when provided.
# Save the returned agentId; connect does not wait for approval.
sigma agent status --agent-id AGENT_ID --json
printf '{}\n' > arguments.json
sigma agent execute --agent-id AGENT_ID --capability list_my_identities --args-file arguments.json --json
sigma agent disconnect --agent-id AGENT_ID --json
```

Use capability names from discovery and a JSON object in `arguments.json`.
Repeat `status` after its `nextPollAt` (Unix milliseconds). It makes at most one
status request, preserves server throttling across restarts, and reports terminal
approval states. Reuse the agent ID instead of repeating registration. After a
failed connect request, do not blindly reconnect: the registration may have
reached the provider. Retain `SIGMA_HOME` for diagnosis.

This uses Better Auth Agent Auth via `@auth/agent` 0.6.2, with delegated human
approval. It is not WorkOS auth.md, RFC 8628 device authorization, or a BRC100
wallet signer. The CLI never submits human approval or uses browser session
cookies. Execution requires an active capability explicitly requested at connect.
Agent and host keys live separately under `SIGMA_HOME/agent-auth`, with private
atomic files (0600) and directory (0700). Revocation failures retain credentials
for a retry. Keep this directory private and use one CLI process per SIGMA_HOME
at a time; the SDK's index updates are not a multi-process transaction.

`--base-url` or `SIGMA_AUTH_URL` selects the provider. HTTPS is required except
explicit localhost HTTP testing; discovery and execution URLs must share the
provider origin. Redirects are rejected. Approval URL query strings and complete
claim URLs are omitted from output because they may contain bearer artifacts.
