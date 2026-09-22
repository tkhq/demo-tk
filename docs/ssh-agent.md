# SSH

Use Turnkey Ed25519 private keys for SSH through a background agent.

Follow [authentication](./authentication.md) first.

## Keys

```bash
# Create an Ed25519 private key in Turnkey and register it locally. Names are
# unique; rerunning with an existing name registers that key.
tk ssh keys create --name agent-ssh

# Or register an existing Turnkey private key.
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

Restart after adding or removing keys:

```bash
tk ssh agent stop
tk ssh agent start
```

To sign Git commits with a registered key, see
[git signing](./git-signing.md).

## Skills

- [sidecar-patterns](../skills/sidecar-patterns/SKILL.md): where each command runs in a deployment and the renewal state machine around them.
- [using-ssh](../skills/using-ssh/SKILL.md): creating and registering the key, serving it as a non-root agent, and restarting after rotation.
