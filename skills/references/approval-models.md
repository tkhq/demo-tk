# Approval models

Every workflow that sets up an agent asks the operator to pick a cell of this
matrix first. Columns apply per secret (its `consensus` property); rows apply
to the minting policy for a provisioner and its target set. One agent can
hold unilateral configuration values and approval-gated credentials at the
same time.

## Contents

- [The matrix](#the-matrix)
- [Choosing a cell](#choosing-a-cell)
- [Approvals per day](#approvals-per-day)
- [Policy set per cell](#policy-set-per-cell)
- [What no cell gives you](#what-no-cell-gives-you)

## The matrix

| | Export needs a human | Export is unilateral |
|---|---|---|
| **Minting needs a human** | approval-gated exports and key registration | unattended exports; each new key needs human approval |
| **Minting is unilateral** | a provisioner renews without a human; each export needs approval | unattended registration and exports; a trusted provisioner service must enforce lifetime and target binding |

An agent on the long-lived route has no minting row: its one key never
expires and only the export column applies.

## Choosing a cell

| Requirement | Pick |
|---|---|
| A person must see every use of a credential | export needs a human |
| The workload starts unattended and reads its configuration at boot | export is unilateral for those secrets |
| A person must see every new key the agent receives | minting needs a human |
| Renewal must survive nights and weekends | minting is unilateral, with a provisioner service that pins lifetime and target |
| Git or SSH signing | resource-scoped unilateral ALLOW; these operations wait synchronously for a signature |

## Approvals per day

Approximate mint approvals per day as `24h / (lifetime - renewal lead time)`,
before outages or retries. A 4-hour key renewed 30 minutes early is about 7
approvals per day; a 7-day key renewed a day early is one per six days.
Export approvals count one per export activity, so an approval-gated secret
read at every start is one approval per start.

## Policy set per cell

Names refer to the commands in [policy-patterns.md](policy-patterns.md).

| Cell | Policies |
|---|---|
| exports need a human, minting needs a human | `agents-export-with-approval`, `agents-no-credentials`, `provisioners-mint-agent-keys` with the human clause, `provisioners-nothing-else` |
| exports unilateral, minting needs a human | `agents-export-unilateral`, `agents-no-credentials`, `provisioners-mint-agent-keys` with the human clause, `provisioners-nothing-else` |
| exports need a human, minting unilateral | `agents-export-with-approval`, `agents-no-credentials`, `provisioners-mint-agent-keys` without the human clause, `provisioners-nothing-else` |
| exports unilateral, minting unilateral | `agents-export-unilateral`, `agents-no-credentials`, `provisioners-mint-agent-keys` without the human clause, `provisioners-nothing-else` |

Organizations with both kinds of secrets apply both export policies; the
`consensus` property on each secret selects which one fires.

## What no cell gives you

- No cell bounds a key's lifetime by policy. `expirationSeconds` is not
  policy-visible. In the human-minting rows the approver reads the lifetime
  from `tk session provision`'s record or the console; in the unilateral row a
  compromised provisioner credential can mint a permanent key for any
  allowed target.
- No cell revokes an already exported value. Reducing access to a secret means
  rotating the credential at its provider, then replacing the secret.
- Tag and property selection is shared by every agent with that tag. Use a
  distinct tag and scope property per isolation boundary.
