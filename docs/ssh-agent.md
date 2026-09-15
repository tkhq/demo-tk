# SSH agent

Run `tk` as a background SSH agent for registered Turnkey Ed25519 keys.

Follow the [configuration section of the repository readme](../README.md#configuration).

```bash
# Register a key and start the agent.
tk ssh keys add --private-key-id PRIVATE_KEY_ID
tk ssh agent start
export SSH_AUTH_SOCK=~/.config/turnkey/ssh-agent.sock

# List the served keys and connect.
ssh-add -L
ssh user@host
tk ssh agent status

# Stop the agent.
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
