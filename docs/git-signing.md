# Git signing

`tk` can sign Git commits and tags either as Git's SSH signing program, backed
by your Turnkey Ed25519 key, or as its GPG program, backed by a Turnkey
OpenPGP key.

Ensure you have followed the [configuration section of the repository readme](../README.md#configuration).

## SSH signing

Register the Turnkey private key once. The registry captures its public key,
fingerprint, and owning organization:

```bash
tk ssh keys add --private-key-id <private-key-id>
tk ssh keys list
```

Configure Git to use `tk` and select the registered key:

```bash
git config --global gpg.format ssh
git config --global gpg.ssh.program "$(command -v tk)"
git config --global user.signingkey "key::$(tk ssh public-key)"
printf '%s %s\n' "you@example.com" "$(tk ssh public-key)" >> ~/.config/git/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers
```

For several registered keys, pin one per repository with
`git config user.signingkey "key::<public-key-line>"`. Git passes the selected
public key in `-f`; `tk` matches that key
in the registry and fails by name if it is not registered. There is no fallback
to an active profile's key.

After this setup, Git invokes `tk -Y` to sign commits and tags. Verification
operations such as `git verify-commit` and `git log --show-signature` are
passed through to the real `ssh-keygen`. `TK_SSH_KEYGEN_PROGRAM` can select the
`ssh-keygen` binary when needed.

The same signing path is available for debugging with `tk ssh git-sign`; use
`--profile` there to choose the credential for the key's organization.

For CI, provide the complete `TURNKEY_*` environment bundle, register the key
with `tk ssh keys add --private-key-id "$TURNKEY_SSH_KEY_ID"`, and set
`user.signingkey` from `tk ssh public-key` as above.

## GPG signing

First create and register a Turnkey OpenPGP key and import it into your local
keyring, as described in [GPG signing](./gpg-signing.md). That setup leaves
the key's fingerprint in `$FINGERPRINT`.

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
