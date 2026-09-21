---
name: turnkey-tk
description: Set up and operate Turnkey agent authorization with the tk CLI: root and agent identities, tags, policies, approvals, and secrets. Use for any request about who may act on Turnkey and how an unattended agent authenticates; not for wallets, chain signing, or broadcasting.
---

# Turnkey `tk` workflows

`tk` is the CLI for agent authorization on Turnkey: named profiles holding
P-256 API credentials, users and tags, policies, Secrets, expiring session
keys, SSH keys served by an agent, and OpenPGP signing. An agent here is any
principal that acts without a person watching: an LLM agent, a service, a
cron job, a CI runner. These workflows set one up and operate it.

Read [cli-convention.md](references/cli-convention.md) once per task. It
defines the JSON record every command prints, how pending work is resumed,
and the placeholders the examples use. Then load only the workflow the
request selects and the references that workflow names.

## Which workflow

| Request sounds like | Load |
|---|---|
| "set up Turnkey for our agents", "create the root profile", "which approval model" | [bootstrapping-organization](bootstrapping-organization/SKILL.md) |
| "create a user", "add a tag", "rotate an API key", "revoke this credential", "add a profile on this machine" | [managing-identities](managing-identities/SKILL.md) |
| "write a policy", "why was this denied", "require approval for X", "update the consensus" | [managing-policies](managing-policies/SKILL.md) |
| "approve this", "what is pending", "wait for the activity", "reject it", "who voted" | [monitoring-activities](monitoring-activities/SKILL.md) |
| "store a secret", "give the agent its environment", "finish a pending export", "rotate a secret" | [managing-secrets](managing-secrets/SKILL.md) |

Provisioning an agent user with its policies, session keys minted by a
provisioner, SSH, Git signing, and deployment patterns are documented in
[docs/](../docs/) until their workflows land here. Wallets, chain signing, and
broadcasting belong to the wallet package, not this one.

A continuation ("the export is pending", "renew the key", "the activity was
rejected") loads the workflow that owns the step, not the bootstrap. Loading a
workflow grants no permission: export, delete, and organization scope stay
with the user's authorization.

## References

| Reference | Read when |
|---|---|
| [cli-convention.md](references/cli-convention.md) | always, once |
| [policy-language.md](references/policy-language.md) | writing or debugging a `condition` or `consensus` |
| [policy-patterns.md](references/policy-patterns.md) | applying the tag- and property-based policy set |
| [approval-models.md](references/approval-models.md) | choosing how much a human approves |

## Vocabulary

| Term | Meaning |
|---|---|
| root | a member of the organization's root quorum; a satisfied quorum bypasses policies; never an agent runtime credential |
| agent | a non-root user tagged `agent`; holds only the credentials its route needs |
| provisioner | a non-root user tagged `provisioner`; proposes expiring API keys for an explicit set of agent users |
| human-approver | tag on the people who approve `allow-once` activities |
| allow-always | ALLOW policy whose consensus is the agent tag alone |
| allow-once | ALLOW policy whose consensus also requires a distinct `human-approver`; approval is per activity |
| `consensus=unilateral`, `consensus=approval` | static properties on Secrets choosing which export policy applies |
| long-lived route | agent with one non-expiring API key, scoped by policy |
| session route | agent on expiring keys minted by a provisioner; the agent generates each keypair and hands over only the public key |
| anchor key | a never-expiring key whose private half is discarded, so an API-key-only user on the session route stays valid |
