# Git signing

`tk` signs Git commits and tags as Git's SSH signing program, backed by a
Turnkey Ed25519 key, or as its GPG program, backed by a Turnkey OpenPGP key.

Follow [authentication](./authentication.md) first.

## SSH signing

Register the key as in [SSH](./ssh-agent.md#keys), then point Git at `tk`:

<!-- shared: git-ssh-signing-config -->
```bash
SSH_PUBLIC_KEY=$(tk ssh public-key)
git config --global gpg.format ssh
git config --global gpg.ssh.program "$(command -v tk)"
git config --global user.signingkey "key::$SSH_PUBLIC_KEY"
mkdir -p ~/.config/git
printf '%s %s\n' "you@example.com" "$SSH_PUBLIC_KEY" \
  >> ~/.config/git/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers
```

With several registered keys, select one for the current repository:

```bash
git config user.signingkey \
  "key::$(tk ssh public-key --key SSH_FINGERPRINT)"
```

```bash
# Choose a credential when several profiles can access the key's organization.
export TK_PROFILE=agent

# Sign and verify a commit.
git commit -S --allow-empty -m test
git verify-commit HEAD

# Override the ssh-keygen used for verification if needed.
export TK_SSH_KEYGEN_PROGRAM=/path/to/ssh-keygen
```

For CI:

```bash
# TURNKEY_ORGANIZATION_ID, TURNKEY_API_PUBLIC_KEY, and
# TURNKEY_API_PRIVATE_KEY must already be set.
export TURNKEY_SSH_KEY_ID=PRIVATE_KEY_ID
tk ssh keys add --private-key-id "$TURNKEY_SSH_KEY_ID"
git config user.signingkey \
  "key::$(tk ssh public-key --key "$TURNKEY_SSH_KEY_ID")"
```

## GPG signing

Create and import the key as in [GPG signing](./gpg-signing.md), which leaves
its fingerprint in `$FINGERPRINT`.

Start a foreground agent for the one key Git should use in a supervised
service. The Unix socket is the signing-authority boundary: anyone who can
open it can request signatures, so protect its path. When the client and
broker use different users, give them a shared group and use socket mode
`660`.

```bash
tk gpg agent serve --key "$FINGERPRINT" \
  --socket /run/tk-gpg-agent/agent.sock --socket-mode 660
```

In Git's environment:

<!-- shared: git-gpg-signing-config -->
```bash
# Point git at tk as the GPG program.
git config --global gpg.format openpgp
git config --global gpg.program tk
git config --global user.signingkey "$FINGERPRINT"
git config --global commit.gpgsign true

# Sign and verify a commit. `git tag -s` works the same way.
git commit -S --allow-empty -m test
git verify-commit HEAD
```

If the GPG agent runs in a broker container, mount its socket into the Git
client container and set:

```bash
export TK_GPG_AGENT_SOCK=/run/tk-gpg-agent/agent.sock
```

The serving process holds the selected Turnkey credential; Git and `tk` only
need socket access. With `TK_GPG_AGENT_SOCK` set, an unavailable agent fails
the signing operation rather than falling back to local credentials. Commit
verification is performed locally by GnuPG through `tk`'s passthrough.

## Skills

- [signing-git-commits](../skills/signing-git-commits/SKILL.md): the GPG-first procedure, scoped policies, and the HOME wrapper.
