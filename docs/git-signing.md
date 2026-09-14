# Git signing

`tk` can sign Git commits and tags either as Git's SSH signing program, backed
by your Turnkey Ed25519 key, or as its GPG program, backed by a Turnkey
OpenPGP key.

Ensure you have followed the [configuration section of the repository readme](../README.md#configuration).

## SSH signing

```bash
git config --global gpg.format ssh
git config --global gpg.ssh.program "$(which tk)"
git config --global user.signingkey "key::$(tk public-key)"
printf '%s %s\n' "you@example.com" "$(tk public-key)" >> ~/.config/git/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers
```

After this setup, Git can use `tk git-sign` through the configured SSH signing program when creating signed commits or tags. It is invoked with `tk -Y` since that is how Git expects to invoke the given ssh program.

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
