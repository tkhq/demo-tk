<img width="1500" height="500" alt="tk" src="assets/banner.png" />

<h4 align="center">
    A CLI for machines to use Turnkey for git, ssh, and credential management.
</h4>

`tk` is the CLI for agent authorization on Turnkey: credentials, users and
tags, policies, secrets, sessions, SSH, and Git signing backed by Turnkey keys.

## Getting started

Paste this into your agent:

```
Install the Turnkey tk CLI with
`curl --proto '=https' --tlsv1.2 -LsSf https://raw.githubusercontent.com/tkhq/tk/main/install.sh | sh`.
Install the tk skills by downloading https://github.com/tkhq/tk/tree/main/skills
into your skills directory, read its SKILL.md, and walk me through
bootstrapping my Turnkey organization at https://app.turnkey.com.
```

The skills in [skills/](./skills/SKILL.md) cover bootstrapping an
organization, managing identities, policies, activities, and secrets.

## Manual installation

```bash
curl --proto '=https' --tlsv1.2 -LsSf https://raw.githubusercontent.com/tkhq/tk/main/install.sh | sh
```

## Docs

- [Authentication](./docs/authentication.md): profiles and the environment bundle
- [Resources](./docs/resources.md): users, policies, API keys, and wallets
- [Signing](./docs/signing.md): payloads and serialized transactions
- [Activities](./docs/activities.md): inspect, approve, reject, and wait
- [Raw requests](./docs/requests.md): sign and send an exact request body
- [Secrets](./docs/secrets.md)
- [Sessions](./docs/sessions.md): expiring keys minted by a provisioner
- [SSH](./docs/ssh-agent.md): registered keys and the SSH agent
- [Git signing](./docs/git-signing.md)
- [GPG signing](./docs/gpg-signing.md)

## Contact us

`tk` is part of Turnkey's agent auth beta. To ask a question or tell us what
your agents need, reach us at
[turnkey.com/agent-auth-beta](https://www.turnkey.com/agent-auth-beta).

For the thinking behind this project, see
[this thread](https://x.com/ZekeMostov/status/2100277046207266887).
