# SSH

Use Turnkey Ed25519 private keys for SSH through a background agent.

Follow [authentication](./authentication.md) first.

## Keys

```bash
# Create an Ed25519 private key in Turnkey and register it locally in one step.
tk ssh keys create --name hermes-ssh

# Or register a Turnkey private key that already exists.
tk ssh keys add --private-key-id PRIVATE_KEY_ID
tk ssh keys list

# Print a public key, for authorized_keys or GitHub.
tk ssh public-key
tk ssh public-key --key SSH_FINGERPRINT

# Forget a key. The Turnkey private key is unchanged.
tk ssh keys remove SSH_FINGERPRINT
```

## Agent

```bash
tk ssh agent start
export SSH_AUTH_SOCK=~/.config/turnkey/ssh-agent.sock

ssh-add -L
ssh user@host
tk ssh agent status

tk ssh agent stop
```

Limit the keys served:

```bash
# Serve selected keys.
tk ssh agent start --key SSH_FINGERPRINT --key ANOTHER_SSH_FINGERPRINT

# Serve keys belonging to one profile's organization.
tk ssh agent start --profile agent
```

A session key rotated with `tk session activate` is picked up automatically on
the next signature, without a restart. The set of keys served is read only at
start, so restart after adding or removing keys:

```bash
tk ssh agent stop
tk ssh agent start
```

To sign Git commits with a registered key, see
[git signing](./git-signing.md).
