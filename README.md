# `tk`

`tk` is focused on general agent authorization, attribution, and credential management with Turnkey backed keys.

- [Turnkey account administration](./docs/core.md)
- [Secrets manager](./docs/secrets.md)
- [Git signing](./docs/git-signing.md)
- [SSH agent](./docs/ssh-agent.md)
- [GPG signing](./docs/gpg-signing.md)

## Installation

From the root of this repo:

```bash
cargo install -p tk
```

The installed binary is named `tk`.

## Commands

```bash
tk login NAME --organization-id ORG_UUID --api-key-file ./key.json
tk auth status
tk profile show NAME
tk api-key generate --output ./agent-key.json
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

Use `--config` or `TK_CONFIG` to select another registry path. Profiles hold
credentials and organizations; registered OpenPGP and SSH keys live in the
registry tables and are independent of any one profile.

Create and register a credential, then save a profile and register its SSH key:

```bash
tk api-key generate --output ./agent-key.json
tk login agent --organization-id <org-id> --api-key-file ./agent-key.json
tk ssh keys add --private-key-id <ed25519-private-key-id>
tk ssh keys list
```

`tk ssh keys add` captures the public key and organization locally. Subsequent
SSH signing and agent operations use this registry without a network lookup to
discover the key.

### Environment Overrides

```bash
export TURNKEY_ORGANIZATION_ID="<org-id>"
export TURNKEY_API_PUBLIC_KEY="<api-public-key>"
export TURNKEY_API_PRIVATE_KEY="<api-private-key>"
export TURNKEY_API_BASE_URL="https://api.turnkey.com" # optional
export TK_CONFIG="$HOME/.config/turnkey/tk.config.toml" # optional
```

The environment bundle is useful for CI. Register the SSH key once in the CI
environment, then configure Git to select it by its registered public key:

```bash
tk ssh keys add --private-key-id "$TURNKEY_SSH_KEY_ID"
git config --global gpg.ssh.program "$(command -v tk)"
git config --global user.signingkey "key::$(tk ssh public-key)"
```

`tk.toml`, `TURNKEY_TK_CONFIG_PATH`, and `TURNKEY_PRIVATE_KEY_ID` are no longer
read.

### GPG Environment

- `TK_GPG_PROGRAM` names the real GnuPG binary the git shim runs for verification calls.

Registered OpenPGP keys live in the identity registry under `gpg_keys`, keyed by fingerprint. See [GPG signing](./docs/gpg-signing.md).
