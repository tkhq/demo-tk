# Secrets

Import, list, and export UTF-8 secret values. One trailing newline is
stripped on import.

```bash
# From stdin, from a file, or prompted with input hidden.
echo -n "$API_TOKEN" | tk secret import --name api-token
tk secret import --name db-password --from-file ./password.txt
tk secret import --name ssh-passphrase

# Metadata only; values are never listed.
tk secret list
tk secret list --limit 100 --cursor SECRET_ID

# Values.
tk secret export --name api-token
tk secret export --id SECRET_ID
```

Scripting:

```bash
API_TOKEN=$(tk secret export --name api-token)
tk secret export --name db-password --out ./password.txt   # new file, mode 0600
tk secret export --name api-token --message-format json | jq -r .data.value
```

## Policy-visible metadata

```bash
# Properties are bound to the secret forever.
echo -n "$TOKEN" | tk secret import --name api-token --property env=prod --property team=payments

# Context is attached to one export request only.
tk secret export --name api-token --context purpose=deploy --context ticket=OPS-123
```

## Consensus

```bash
# Submitter: status pending, activity ID printed, nothing written yet.
tk secret export --name prod-signing-key

# Approver.
tk --profile approver activity approve --id ACTIVITY_ID

# Submitter: the same command now prints the value.
tk secret export --name prod-signing-key
```

Only the submitting credential on the submitting machine can complete the
export. A rejected export fails with `api_error`; running the command again
starts a new one.

Abandon a pending export by rejecting its activity, or leave it: the pending
state is swept after 8 hours and the activity expires after 24.

```bash
tk --profile approver activity reject --id ACTIVITY_ID
```
