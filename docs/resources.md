# Resources

Manage users, policies, API keys, and wallets. Create and update commands
take the request's parameters object as `--input-json JSON` or
`--input-file PATH` (`-` for stdin), without organization ID or activity
envelope.

Follow [authentication](./authentication.md) first.

## Users

```bash
tk user list
tk user get --id USER_ID
tk user create --input-json '{"users": [{
  "userName": "agent",
  "apiKeys": [{"apiKeyName": "agent-key", "publicKey": "02…", "curveType": "API_KEY_CURVE_P256"}],
  "authenticators": [], "oauthProviders": [], "userTags": []
}]}'
tk user update --input-file ./user-update.json
tk user delete --id USER_ID

tk user tag list
tk user tag create --input-json '{"userTagName": "agents", "userIds": []}'
tk user tag update --input-file ./tag-update.json
tk user tag delete --id TAG_ID
```

## Policies

```bash
tk policy list
tk policy get --id POLICY_ID
tk policy create --input-file - <<'EOF'
{
  "policyName": "agents-sign-only",
  "effect": "EFFECT_ALLOW",
  "condition": "activity.type == 'ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2'",
  "consensus": "approvers.any(user, user.tags.contains('TAG_ID'))",
  "notes": "agents may sign"
}
EOF
tk policy create-batch --input-file ./policies.json
tk policy update --input-json '{"policyId": "POLICY_ID", "policyNotes": "revised"}'
tk policy delete --id POLICY_ID

# See how policies evaluated an activity.
tk policy evaluations --activity-id ACTIVITY_ID
```

Updates use `policyEffect`, `policyCondition`, `policyConsensus`, and
`policyNotes`.

## API keys

```bash
tk api-key list --user-id USER_ID
tk api-key register --input-json '{
  "userId": "USER_ID",
  "apiKeys": [{"apiKeyName": "ci", "publicKey": "02…", "curveType": "API_KEY_CURVE_P256"}]
}'
tk api-key delete --user-id USER_ID API_KEY_ID
```

## Wallets

```bash
tk wallet list
tk wallet get --id WALLET_ID
tk wallet create --input-file - <<'EOF'
{"walletName": "treasury", "accounts": [{
  "curve": "CURVE_SECP256K1",
  "pathFormat": "PATH_FORMAT_BIP32",
  "path": "m/44'/60'/0'/0/0",
  "addressFormat": "ADDRESS_FORMAT_ETHEREUM"
}]}
EOF
tk wallet update --input-json '{"walletId": "WALLET_ID", "walletName": "ops"}'

tk wallet account list --wallet-id WALLET_ID --limit 50
tk wallet account list --wallet-id WALLET_ID --cursor ACCOUNT_ID
tk wallet account create --input-file ./accounts.json
```

A command that needs approval exits zero with status `pending` and an
activity ID; see [activities](./activities.md).
