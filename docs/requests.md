# Raw requests

Sign and send an exact request body to any Turnkey endpoint. The bytes are
sent as given, with no rewriting and no retries.

Follow [authentication](./authentication.md) first.

```bash
BODY='{"organizationId": "ORG_UUID"}'
tk request --path /public/v1/query/whoami --body "$BODY"

# Read the body from a file, or - for stdin.
tk request --path /public/v1/submit/create_wallet --body-file ./intent.json

# Print the URL, stamp header, and body without sending.
tk request --path /public/v1/query/whoami --body "$BODY" --stamp-only
```

The body's `organizationId` must match the selected organization. An
ambiguous submission is reported as `submission_unknown` with the activity to
inspect; see [activities](./activities.md).
