# SSH agent

Run `tk` as a background SSH agent when you want plain `ssh` to authenticate
with registered Turnkey Ed25519 keys. Register keys before starting the agent:

Ensure you have followed the [configuration section of the repository readme](../README.md#configuration).

```bash
tk ssh keys add --private-key-id <private-key-id>
tk ssh agent start
```

```bash
export SSH_AUTH_SOCK=~/.config/turnkey/ssh-agent.sock

ssh-add -L
ssh user@host
tk ssh agent status
```

To kill the background agent:

```bash
tk ssh agent stop
```

The agent snapshots the registry when it starts. `ssh-add -L` prints every
registered key it serves, and `ssh user@host` uses the matching key for
signing. Narrow the set with repeatable `--key` values (fingerprints, public
key lines, or private-key IDs), or use `--profile` to serve only keys owned by
that profile's organization:

```bash
tk ssh agent start --key SHA256:... --key SHA256:...
tk ssh agent start --profile agent
```

Adding or removing a key does not hot-reload a running agent; restart it to
pick up registry changes. `tk ssh agent status` reports the served
fingerprints. The socket and pid files default to `~/.config/turnkey/ssh-agent.sock`
and `~/.config/turnkey/ssh-agent.pid`.
