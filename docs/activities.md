# Activities

Every mutation is an activity. Inspect, vote on, and wait for them.

```bash
tk activity list --limit 50
tk activity list --limit 50 --cursor ACTIVITY_ID
tk activity get --id ACTIVITY_ID
```

Consensus:

```bash
# Approver: one vote per command.
tk --profile approver activity approve --id ACTIVITY_ID
tk --profile approver activity reject --id ACTIVITY_ID

# Submitter: block until the activity ends.
tk activity wait --id ACTIVITY_ID --timeout 60
```

`wait` fails with `api_error` when the activity ends rejected or failed and
with `wait_timeout` when time runs out. Run it again with the same ID to
resume.

To see which policies decided an activity:

```bash
tk policy evaluations --activity-id ACTIVITY_ID
```
