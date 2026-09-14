# GPG signing

`tk` signs Git commits with an OpenPGP key backed by a Turnkey wallet
account. The private key never leaves Turnkey.

```sh
# Create a wallet to hold the signing key, if you don't have one.
tk wallet create --input-json '{"walletName": "gpg", "accounts": []}'

# Create and register a signing key under that wallet, keeping its fingerprint.
FINGERPRINT=$(tk gpg keys create --wallet-id <wallet uuid> --user-id "Your Name <you@example.com>" \
  --message-format json | jq -r .fingerprint)

# Import the public key into your local GnuPG keyring.
tk gpg keys export | gpg --import

# Trust the key so gpg doesn't warn when verifying.
echo "$FINGERPRINT:6:" | gpg --import-ownertrust
```

To sign commits with this key, see [Git signing](./git-signing.md#gpg-signing).

To add the key to GitHub, paste the output of `tk gpg keys export` into
Settings, SSH and GPG keys, New GPG key.

## Key management

```sh
tk gpg keys list                                          # registered keys (add --wallet-id to scope to one wallet)
tk gpg keys add --wallet-id <uuid> [--key <fingerprint>]  # register an existing wallet key
tk gpg keys remove <fingerprint>                          # forget a key; leaves the wallet account in place
```

## Notes

- `user.signingkey` must be a registered key's fingerprint (hex, 16+ chars)
  or, if unset, must equal the committer's user ID exactly.
- The registered key's organization selects the credential; use `--profile`,
  `TK_PROFILE`, or `--organization-id` to pick explicitly when you have more
  than one profile for that organization.
- `git verify-commit` runs the real `gpg` binary; set `TK_GPG_PROGRAM` if
  `gpg` isn't on `PATH`.
