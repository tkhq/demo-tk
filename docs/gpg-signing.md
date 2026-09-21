# GPG signing

Sign with an OpenPGP key backed by a Turnkey wallet account. The private key
never leaves Turnkey.

Follow [authentication](./authentication.md) first.

```bash
# Create a wallet to hold the signing key, if you don't have one.
tk wallet create --input-json '{"walletName": "gpg", "accounts": []}'

# Create and register a signing key under that wallet, keeping its fingerprint.
FINGERPRINT=$(tk gpg keys create --wallet-id WALLET_ID --user-id "Your Name <you@example.com>" \
  --message-format json | jq -r .fingerprint)

# Import the public key into your local GnuPG keyring and trust it.
tk gpg keys export | gpg --import
echo "$FINGERPRINT:6:" | gpg --import-ownertrust

# Sign a file, or stdin.
tk gpg sign ./release.tar.gz --output ./release.tar.gz.asc
echo hello | tk gpg sign
```

To sign commits with this key, see [Git signing](./git-signing.md#gpg-signing).
To add the key to GitHub, paste the output of `tk gpg keys export` into
Settings, SSH and GPG keys, New GPG key.

## Key management

```bash
tk gpg keys list
tk gpg keys list --wallet-id WALLET_ID
tk gpg keys add --wallet-id WALLET_ID --key FINGERPRINT
tk gpg keys export --key FINGERPRINT
tk gpg keys remove FINGERPRINT   # forgets the key; the wallet account stays
```

```bash
# Choose a credential when several profiles can access the key's organization.
export TK_PROFILE=agent

# Name the GnuPG binary used for verification if gpg isn't on PATH.
export TK_GPG_PROGRAM=/path/to/gpg
```

## GPG agent

Run the GPG agent in a broker container that holds the Turnkey credential.
Mount its socket into the credential-free agent container:

```bash
tk gpg agent serve --key FINGERPRINT \
  --socket /run/tk-gpg-agent/agent.sock --socket-mode 660
```

In the agent container:

```bash
export TK_GPG_AGENT_SOCK=/run/tk-gpg-agent/agent.sock
```

The broker serves one registered key. Socket access grants signing authority,
so protect the socket and its directory. A missing or unavailable agent is a
hard failure, with no local signing fallback.

Verification remains local GnuPG work:

```bash
gpg --verify release.tar.gz.asc release.tar.gz
```

## Skills

- [deploying-signing-broker](../skills/deploying-signing-broker/SKILL.md): isolate the signing credential and session provisioner in separate containers.
- [signing-git-commits](../skills/signing-git-commits/SKILL.md): creating, registering, and using the key for commits as a non-root agent.
