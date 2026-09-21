# Session keys

A session key is a Turnkey API key with an expiration. `tk session` splits its
lifecycle so that the private key never leaves the machine that uses it and the
identity allowed to register keys never sees it.

```
agent host                                provisioner host              human
----------                                ----------------              -----
tk session request --profile-name agent
  -> new keypair under ~/.config/turnkey/tk/api-keys/
  -> prints publicKey and userId
                     ---- public key + user id (any transport) ---->
                                          tk --profile provisioner \
                                            session provision --user-id U \
                                            --public-key PK --expires-in 7d
                                          -> status pending, activity id
                                                                       approves
                                          same command again
                                          -> completed, apiKeyId
                     <---- done ----
tk session activate --profile-name agent
  -> profile now uses the new key; old generated key file removed
tk session status --profile-name agent
  -> expiresAt, secondsLeft; exit 1 with code session_expiring
     when under --warn-before (default 48h)
```

## Request

```bash
tk session request --profile-name agent
tk session request --profile-name agent --replace   # drop an unregistered request
```

The profile must already exist. The request is remembered under
`~/.config/turnkey/tk/sessions/pending/<profile>.json` until `activate` uses it.
`userId` is read with the profile's current credential and is `null` only when
that credential is no longer authorized; pass the user id to the provisioner
by other means then. Any other lookup failure, such as a rate limit or a
network error, fails the command before it generates a key, so it can be rerun.

## Provision

```bash
tk --profile provisioner session provision --user-id USER_UUID --public-key PK --expires-in 7d
```

Runs as the provisioner and submits `CREATE_API_KEYS_V2` with
`expirationSeconds`. The record always shows `userId`, `expiresIn`, and
`publicKey` so an approver can check them. If the key is already registered on
that user the command reports it with `alreadyRegistered: true` and submits
nothing, so re-running after approval is safe.

Durations take `s`, `m`, `h`, or `d` suffixes, from `1s` to `365d`.

## Activate

```bash
tk session activate --profile-name agent
```

Verifies the pending key with `whoami`, then repoints the profile at it. Until
the key is registered the command fails with `unauthorized` and the profile is
unchanged. A previous key file is deleted only if `tk` generated it under
`~/.config/turnkey/tk/api-keys/`.

## Status

```bash
tk session status --profile-name agent
tk session status --profile-name agent --warn-before 24h
```

Looks up the profile's key on its user and reports `expiresAt` (unix ms),
`secondsLeft`, and `expiresIn`. A key without expiration reports `null` for
those and always exits 0. Inside the warning window the command exits 1 with
code `session_expiring` and the same fields under `details`, which makes it
usable as a cron check.

## Policies

The provisioner needs an ALLOW policy on `ACTIVITY_TYPE_CREATE_API_KEYS_V2`,
usually with a consensus expression that also requires a human approver. The
agent needs a DENY on `activity.resource == 'CREDENTIAL'`; without it Turnkey
lets a user register keys on itself by default, and a short-lived key could
mint a permanent one. Neither the target user's tags nor `expirationSeconds`
are visible to policies, so the approver checks both from the record.
