# `tk`

`tk` is focused on general agent authorization, attribution, and credential management with Turnkey backed keys.

- [Turnkey account administration](./docs/core.md)
- [Secrets manager](./docs/secrets.md)
- [Git signing](./docs/git-signing.md)
- [SSH agent](./docs/ssh-agent.md)
- [GPG signing](./docs/gpg-signing.md)

## Installation

Install the latest release binary (Linux and macOS, x86_64 and arm64):

```bash
curl --proto '=https' --tlsv1.2 -LsSf https://raw.githubusercontent.com/tkhq/tk/main/install.sh | sh
```

## Commands

```bash
tk api-key generate --output ./agent-key.json
tk login NAME --organization-id ORG_UUID --api-key-file ./key.json
tk auth status
tk profile show NAME
tk ssh keys add --private-key-id PRIVATE_KEY_ID
tk ssh keys list
tk ssh public-key
tk ssh git-sign
tk ssh agent
tk gpg keys create
tk gpg keys add
tk gpg keys remove
tk gpg keys list
tk gpg keys export
tk gpg sign
```

## Configuration

`tk` resolves configuration in this order:

1. An explicit `--profile` (or `TK_PROFILE`)
2. A complete `TURNKEY_*` environment bundle
3. The active profile in the identity registry

The identity registry is stored at:

```bash
~/.config/turnkey/tk.config.toml
```

```bash
# Generate a credential, then register its public key with Turnkey.
tk api-key generate --output ./agent-key.json

# Save the registered credential as a profile.
tk login agent --organization-id ORG_UUID --api-key-file ./agent-key.json

# Register a Turnkey Ed25519 key locally for SSH.
tk ssh keys add --private-key-id PRIVATE_KEY_ID
tk ssh keys list
```

Profiles hold credentials. OpenPGP and SSH keys belong to organizations and
are registered locally for signing.

### Environment Overrides

```bash
export TURNKEY_ORGANIZATION_ID="<org-id>"
export TURNKEY_API_PUBLIC_KEY="<api-public-key>"
export TURNKEY_API_PRIVATE_KEY="<api-private-key>"
export TURNKEY_API_BASE_URL="https://api.turnkey.com" # optional
```

### GPG Environment

- `TK_GPG_PROGRAM` names the real GnuPG binary the git shim runs for verification calls.

Registered OpenPGP keys live in the identity registry under `gpg_keys`, keyed by fingerprint. See [GPG signing](./docs/gpg-signing.md).
