---
name: inspecting-agents
description: Answer operational questions about an organization's Turnkey agents with tk list and get commands, explicit pagination, and jq: what is pending and for how long, who voted, which users carry a tag, which keys each agent holds and when they expire, which secrets carry which properties, which policies mention a tag, who minted a key. Use for audits and "what is the state of X" questions; not for changing anything.
---

# Inspecting agents

Result: a read-only report that answers each question with the command that
produced it and the field the answer came from. Nothing is created, voted
on, or deleted.

There are no server-side filters in this checkout. Every question below is a
full traversal of one or more lists plus a local `jq` selection, so each
answer states its provenance: the command, the page or pages read, and the
field.

## Reference

- [resources](../../docs/resources.md): `user`, `user tag`, `api-key`, and `policy` list records.
- [activities](../../docs/activities.md): `activity list` pages and `activity get`.
- [secrets](../../docs/secrets.md): `secret list` metadata and paging.

## Rules

- Read only. Approving, rejecting, or waiting on what you find belongs to
  [monitoring-activities](../monitoring-activities/SKILL.md).
- Page to the end before answering "none". `activity list` and
  `secret list` page with `--limit` and `--cursor`; a page is the last one
  when `data.nextCursor` is `null`. `user list`, `user tag list`,
  `policy list`, and `api-key list` return everything in one response.
- Resolve tag names once, with `user tag list`, and match by `tagId`
  everywhere else. `userTags[]` on a user and the text of a policy carry
  ids, not names.
- `expiresAt` on an API key is a Unix-millisecond string, or `null` for a
  key that never expires. On the session route the anchor is the only
  permanent key an agent should hold; on the long-lived route the one
  runtime key is permanent.
- Who minted a key is a join, never a guess: the key's
  `credential.publicKey` against the `publicKey` inside an activity's
  `intent` (`createApiKeysIntentV2.apiKeys[]` or
  `createUsersIntentV4.users[].apiKeys[]`). When no activity in the pages
  you traversed matches, the answer is "unknown". Do not infer a minter from
  voters on other activities.
- A textual search of policy `consensus` and `condition` for a tag id is a
  candidate list, not a parsed dependency graph. Read each candidate before
  claiming it governs the tag.

## Instructions

Inputs: any profile in the organization (`admin` below), and the tag names
or ids the question is about. Every command below prints one JSON record;
`jq` selects from it.

1. **Resolve tag ids.**

   <!-- example: inspecting.tags -->
   ```sh
   tk --profile admin --message-format json user tag list | jq -r '.data.userTags[] | "\(.tagId) \(.tagName)"'
   AGENT_TAG=$(tk --profile admin --message-format json user tag list | jq -r '.data.userTags[] | select(.tagName == "agent") | .tagId')
   ```

   `data.userTags[]` carries `tagId`, `tagName`, and `userIds`. Steps 2 and
   7 use `$AGENT_TAG`. A name that matches nothing leaves the variable
   empty; stop and report that, do not fall back to a substring match.

2. **Which users carry a tag.**

   <!-- example: inspecting.tagged-users -->
   ```sh
   tk --profile admin --message-format json user list | jq --arg tag "$AGENT_TAG" '.data.users[] | select(.userTags | any(. == $tag)) | {userId, userName}'
   ```

   `data.users[].userTags[]` is the list of tag ids on each user. The list
   is complete in one response.

3. **Which keys an agent holds and when they expire.**

   <!-- example: inspecting.keys -->
   ```sh
   tk --profile admin --message-format json api-key list --user-id AGENT_USER_ID | jq '.data.apiKeys[] | {apiKeyId, apiKeyName, publicKey: .credential.publicKey, expiresAt}'
   tk --profile admin --message-format json api-key list --user-id AGENT_USER_ID | jq -r '.data.apiKeys[] | select(.expiresAt == null) | .apiKeyId'
   ```

   The second command lists the permanent keys. A session-route agent
   should show exactly one, its anchor; more than one permanent key on such
   an agent is a finding. Run step 3 once per user id from step 2.

4. **What is pending and for how long.**

   <!-- example: inspecting.pending -->
   ```sh
   tk --profile admin --message-format json activity list --limit 50 | jq --arg now "$(date +%s)" '.data.items[] | select(.status == "ACTIVITY_STATUS_CONSENSUS_NEEDED") | {id, type, ageSeconds: (($now | tonumber) - (.createdAt.seconds | tonumber))}'
   ```

   `data.items[]` is one page, newest first; `createdAt.seconds` is a
   Unix-second string. Continue with the cursor until it prints `null`:

   <!-- example: inspecting.next-page -->
   ```sh
   NEXT_ACTIVITY_ID=$(tk --profile admin --message-format json activity list --limit 50 | jq -r '.data.nextCursor')
   tk --profile admin --message-format json activity list --limit 50 --cursor $NEXT_ACTIVITY_ID | jq -r '.data.nextCursor'
   ```

   Apply the step 4 filter to every page and concatenate. A pending
   activity appears on exactly one page.

5. **Who voted on an activity.**

   <!-- example: inspecting.votes -->
   ```sh
   tk --profile admin --message-format json activity get ACTIVITY_ID | jq '.data.activity.votes[] | {userId, selection}'
   ```

   `selection` is `VOTE_SELECTION_APPROVED` or `VOTE_SELECTION_REJECTED`.
   The submitter's own approval is the first vote; the missing approver is
   whoever the policy consensus names and this list does not.

6. **Which secrets carry which properties.**

   <!-- example: inspecting.secrets -->
   ```sh
   tk --profile admin --message-format json secret list --limit 100 | jq '.data.secrets[] | {name, properties: (.staticProperties | map("\(.key)=\(.value)"))}'
   tk --profile admin --message-format json secret list --limit 100 --cursor SECRET_ID | jq -r '.data.nextCursor'
   ```

   `staticProperties[]` is `key` and `value`; values of the secrets
   themselves are never listed. Page with `--cursor` as in step 4.

7. **Which policies mention a tag.**

   <!-- example: inspecting.policies -->
   ```sh
   tk --profile admin --message-format json policy list | jq --arg tag "$AGENT_TAG" '.data.policies[] | select((.consensus // "") + (.condition // "") | contains($tag)) | {policyId, policyName, effect}'
   ```

   These are candidates. Read each one's `consensus` and `condition` to say
   whether the tag is an approver, a target, or both.

8. **Who minted a key.** Take the key's `credential.publicKey` from step 3
   into `$KEY_PUBLIC_KEY`, then join it against each page of activities:

   <!-- example: inspecting.minted-by -->
   ```sh
   tk --profile admin --message-format json activity list --limit 50 | jq --arg pk "$KEY_PUBLIC_KEY" '.data.items[] | select(any(.intent.createApiKeysIntentV2.apiKeys[]?, .intent.createUsersIntentV4.users[]?.apiKeys[]?; .publicKey == $pk)) | {id, type, status, minted: .createdAt.seconds, voters: [.votes[].userId]}'
   ```

   Page as in step 4. One match gives the activity and its voters, the
   first of which submitted it. No match across every page is "unknown".
   Empty output on the first page alone proves nothing.

9. **Hand off.** One line per question: the answer, the command, the pages
   read (`1 of 1`, `3 of 3`), and the field it came from. Pending ids,
   permanent-key findings, and "unknown" minters are listed explicitly.
   Stop.

## Verified by

| Examples | Test |
|---|---|
| inspecting.tags, inspecting.tagged-users, inspecting.keys, inspecting.pending, inspecting.next-page, inspecting.votes, inspecting.secrets, inspecting.policies, inspecting.minted-by | users::inspecting_agents_questions |

## Troubleshooting

- `jq: command not found`: install `jq`; every recipe here selects from the
  JSON record with it. Nothing in `tk` depends on it.
- `user get` or `api-key list` fails with `not_found`: the user id belongs
  to another organization or was mistyped. Check `--profile` and the id
  from step 2.
- Step 1 leaves `$AGENT_TAG` empty: the tag name is different in this
  organization. Read the full `user tag list` output and pick the id by
  hand; do not guess from a similar name.
- A page has zero items but the previous page had a cursor: the previous
  page was exactly `--limit` long. That empty page is the end.
- `activity list` shows nothing pending but a command reported `pending`:
  the vote may have landed since. `activity get ACTIVITY_ID` shows the
  current status of that one activity.
- Step 8 finds no match: widen the traversal to every page before saying
  "unknown"; an activity older than the pages read is not evidence of
  anything.

## Related Skills

- [monitoring-activities](../monitoring-activities/SKILL.md): approve, reject,
  or wait on what step 4 found.
- [managing-identities](../managing-identities/SKILL.md): rotate or revoke a
  key that step 3 flagged.
- [provisioning-session-agent](../provisioning-session-agent/SKILL.md): the
  expiring keys and anchor that step 3 reads.
- [managing-policies](../managing-policies/SKILL.md): read or change the
  policies step 7 listed.
