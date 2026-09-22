# Signing

Sign with a wallet account. Inputs follow the [resources](./resources.md)
conventions.

Follow [authentication](./authentication.md) first.

```bash
# Sign a 32-byte digest as is.
tk sign payload --input-json '{
  "signWith": "0xYourAddress",
  "payload": "0x…",
  "encoding": "PAYLOAD_ENCODING_HEXADECIMAL",
  "hashFunction": "HASH_FUNCTION_NO_OP"
}'

# Hash text before signing.
tk sign payload --input-json '{
  "signWith": "0xYourAddress",
  "payload": "hello",
  "encoding": "PAYLOAD_ENCODING_TEXT_UTF8",
  "hashFunction": "HASH_FUNCTION_KECCAK256"
}'

# Sign a serialized transaction. tk does not broadcast it.
tk sign transaction --input-json '{
  "signWith": "0xYourAddress",
  "unsignedTransaction": "02…",
  "type": "TRANSACTION_TYPE_ETHEREUM"
}'
```

Scripting:

```bash
tk sign payload --input-file ./sign.json --message-format json \
  | jq -r '.data.activity.result.signRawPayloadResult'
```

When a policy requires approval the command exits zero with status `pending`.
Have an approver run `tk activity approve`, then collect the result with
`tk activity wait`; see [activities](./activities.md).

For Git commits, SSH, and OpenPGP, see [git signing](./git-signing.md),
[SSH](./ssh-agent.md), and [GPG signing](./gpg-signing.md).
