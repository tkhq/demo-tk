# SSH

Use Turnkey Ed25519 private keys for SSH through a background agent.

Follow [authentication](./authentication.md) first.

## Keys

```bash
# Create an Ed25519 private key in Turnkey and register it locally.
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

`create` prints `ssh_key_created`, or `ssh_key_registered` when the name
already exists; `add` prints `ssh_key_registered`. Re-adding a registered key
overwrites its entry.

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

```bash
# Move the socket and pid file off their defaults under ~/.config/turnkey/.
# `status` and `stop` take the same two flags.
tk ssh agent start --socket /run/agent/ssh.sock --pid-file /run/agent/ssh.pid
```

Restart after adding or removing keys:

```bash
tk ssh agent stop
tk ssh agent start
```

To sign Git commits with a registered key, see
[git signing](./git-signing.md).

## Skills

- [sidecar-patterns](../skills/sidecar-patterns/SKILL.md): serving keys from a socket under the agent's `HOME` and restarting the daemon after each renewal.
- [using-ssh](../skills/using-ssh/SKILL.md): creating and registering the key, serving it as a non-root agent, and restarting after rotation.
- [signing-git-commits](../skills/signing-git-commits/SKILL.md): the SSH signing alternative built on a registered key.
