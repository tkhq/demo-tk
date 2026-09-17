# `tk`

`tk` is focused on general agent authorization, attribution, and credential
management with Turnkey backed keys.

## Installation

Install the latest release binary (Linux and macOS, x86_64 and arm64):

```bash
curl --proto '=https' --tlsv1.2 -LsSf https://raw.githubusercontent.com/tkhq/tk/main/install.sh | sh
```

Every pull request push also publishes a prerelease tagged `pr-<number>`,
replaced on each push with a build of the latest commit. Install one by naming it:

```bash
curl --proto '=https' --tlsv1.2 -LsSf https://raw.githubusercontent.com/tkhq/tk/main/install.sh | TK_VERSION=pr-44 sh
```

## Guides

Start with [authentication](./docs/authentication.md), then pick a workflow:

- [Resources](./docs/resources.md): users, policies, API keys, and wallets
- [Signing](./docs/signing.md): payloads and serialized transactions
- [Activities](./docs/activities.md): inspect, approve, reject, and wait
- [Raw requests](./docs/requests.md): sign and send an exact request body
- [Secrets](./docs/secrets.md)
- [Session keys](./docs/sessions.md): request, provision, and activate expiring API keys
- [SSH](./docs/ssh-agent.md): registered keys and the SSH agent
- [Git signing](./docs/git-signing.md)
- [GPG signing](./docs/gpg-signing.md)

Every command accepts `--message-format json` for one JSON object per line.
See `tk --help` for the error code taxonomy and exit codes.

For maintainers: [releasing](./docs/releasing.md).
