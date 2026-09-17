# Git signing

`tk` signs Git commits and tags as Git's SSH signing program, backed by a
Turnkey Ed25519 key, or as its GPG program, backed by a Turnkey OpenPGP key.

Follow [authentication](./authentication.md) first.

## SSH signing

Register the key as in [SSH](./ssh-agent.md#keys), then point Git at `tk`:

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
