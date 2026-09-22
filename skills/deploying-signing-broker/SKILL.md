---
name: deploying-signing-broker
description: Deploy a credential-free application beside a single-key tk GPG signing broker and a separate session provisioner, each in its own isolation boundary. Use when isolating OpenPGP Git signing so the application receives only a constrained Unix socket and public key, or when rotating the broker's expiring Turnkey credential; not for creating the signing key or choosing policies.
---

# Deploying a signing broker

Result: three isolation boundaries with separate authority. The application requests
signatures from one OpenPGP key through a Unix socket; the broker alone holds
that key's profile; the provisioner renews the broker's key but cannot sign.

## Reference

- [GPG signing](../../docs/gpg-signing.md): key registration and export, the foreground agent, and the client socket.
- [git-signing](../../docs/git-signing.md): the Git configuration that points commit signing at `tk` as its GPG program.
- [resources](../../docs/resources.md): the `policy create` record.
- [sessions](../../docs/sessions.md): the request, provision, activate, and status records.

## Rules

- Three principals, each in its own boundary (a container, VM, sandbox, or OS
  user) with its own process tree: application, GPG broker, provisioner.
  Never share one principal's `HOME` with another; publish no ports.
- The broker is its own principal: tag `BROKER_TAG`, profile `broker`, one
  signing ALLOW scoped to `WALLET_ID`, one credential DENY, no export policy.
- The application never receives the broker's profile, registry, or signing
  credential. Its own profile, if it has one, has no signing policy on this
  wallet. It gets the runtime and public key read-only, no provisioner state.
- The broker serves one pinned fingerprint. Its socket grants signing
  authority, so share it only with the application's supplemental group.
- The provisioner gets neither the broker runtime nor broker `HOME`, only the
  expected broker user id, generated public API key, and bounded lifetime.
- Drop capabilities, use a read-only root filesystem, and keep writable state in explicit bind mounts.
- Socket loss and broker failure fail closed: no fallback to an application credential or a second signing path.

## Instructions

Inputs: the wallet (`WALLET_ID`) and fingerprint (`FINGERPRINT`) from
[signing-git-commits](../signing-git-commits/SKILL.md) steps 1 and 3 (skip
its agent policy), the broker tag (`BROKER_TAG`, created like the agent
tag), the `broker` and `provisioner` profiles, the socket group id (`10000`
below), and the session lifetime.

1. **Authorize the broker tag.** Root. The pair below is its whole policy set:

   <!-- shared: brokers-sign-gpg -->
   <!-- example: signing-broker.policy-sign -->
   ```sh
   tk --profile admin --message-format json policy create --name brokers-sign-gpg --effect allow \
     --consensus "approvers.any(user, user.tags.contains('BROKER_TAG'))" \
     --condition "activity.type == 'ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2' && wallet.id == 'WALLET_ID'"
   ```

   <!-- example: signing-broker.policy-deny -->
   ```sh
   tk --profile admin --message-format json policy create --name brokers-no-credentials --effect deny \
     --consensus "approvers.any(user, user.tags.contains('BROKER_TAG'))" \
     --condition "activity.resource == 'CREDENTIAL'"
   ```

   Create the broker user and provision its expiring key with
   [provisioning-session-agent](../provisioning-session-agent/SKILL.md)
   steps 1, 2, 4, and 5, tag `BROKER_TAG`, profile `broker`; from step 3
   take only `provisioners-mint-agent-keys` extended with `BROKER_USER_ID`
   and `provisioners-no-self-keys`. Skip its export policy: the broker gets none.

2. **Lay out host state.** Create mode-`0700` homes for the application,
   broker, and provisioner, owned by their uids. The application home never
   holds the broker's profile, registry, or credential; any profile of its
   own has no signing policy on the wallet. Create its writable worktree, a
   mode-`0770` runtime directory owned by the broker uid and socket gid, and
   a world-readable `/opt/tk-gpg-public` for the armored public key. Persist
   the broker user id outside the application.

3. **Define the boundaries.** Example: this Compose layout realizes the three
   boundaries; a VM or sandbox per principal substitutes as long as the runtime
   directory is the only shared mount. Pin the image by digest in production; the
   application image needs `tk`, Git, and GnuPG. The `provisioner` service is the
   broker image as uid `10001` with `TK_PROFILE: provisioner`, only
   `/opt/tk-provisioner:/home/provisioner` mounted, and `command: [sleep, infinity]`.
   Do not add `depends_on` as a readiness claim; gate application startup on the
   socket being a Unix socket with the expected owner, group, and mode.

   ```yaml
   services:
     app:
       image: your-agent@sha256:PINNED
       user: "1000:1000"
       group_add: ["10000"]
       environment:
         HOME: /home/app
         GNUPGHOME: /home/app/.gnupg
         TK_GPG_AGENT_SOCK: /run/tk-gpg-agent/agent.sock
       volumes:
         - /opt/tk-app-home:/home/app
         - /opt/tk-app-workspace:/workspace
         - /opt/tk-gpg-runtime:/run/tk-gpg-agent:ro
         - /opt/tk-gpg-public:/opt/tk-gpg-public:ro
       read_only: true
       cap_drop: [ALL]
     gpg-broker:
       image: your-tk-image@sha256:PINNED
       user: "10000:10000"
       environment:
         HOME: /home/broker
         TK_PROFILE: broker
       command: [tk, gpg, agent, serve, --key, FINGERPRINT, --socket, /run/tk-gpg-agent/agent.sock, --socket-mode, "660", --non-interactive]
       volumes:
         - /opt/tk-gpg-broker:/home/broker
         - /opt/tk-gpg-runtime:/run/tk-gpg-agent
         - /opt/tk-gpg-public:/opt/tk-gpg-public
       read_only: true
       tmpfs: [/tmp]
       cap_drop: [ALL]
       restart: unless-stopped
   ```

4. **Register and publish the key.** As `broker`, once, before serving. The
   export self-certifies with the key, so it proves the step 1 ALLOW holds:

   <!-- example: signing-broker.export -->
   ```sh
   tk --profile broker --message-format json gpg keys add --wallet-id WALLET_ID --key FINGERPRINT
   tk --profile broker gpg keys export --key FINGERPRINT > /opt/tk-gpg-public/FINGERPRINT.asc
   ```

5. **Start the broker.** The Compose command above is equivalent to:

   <!-- example: signing-broker.serve -->
   ```sh
   tk --profile broker gpg agent serve --key FINGERPRINT \
     --socket /run/tk-gpg-agent/agent.sock --socket-mode 660 --non-interactive
   ```

   Supervise it in the foreground. SIGTERM must reach `tk`; after shutdown,
   require its owned socket to be gone before starting a replacement.

6. **Configure the application.** Import the mounted public key, stop unless
   GnuPG lists exactly `FINGERPRINT`, then point Git at the local `tk`:

   <!-- example: signing-broker.client -->
   ```sh
   gpg --import /opt/tk-gpg-public/FINGERPRINT.asc
   gpg --with-colons --list-keys FINGERPRINT | grep -qF "fpr:::::::::FINGERPRINT:"
   export TK_GPG_AGENT_SOCK=/run/tk-gpg-agent/agent.sock
   git config --global gpg.format openpgp
   git config --global gpg.program tk
   git config --global user.signingkey FINGERPRINT
   git config --global commit.gpgsign true
   git commit -S --allow-empty -m test
   git verify-commit HEAD
   ```

   Signing needs no `TK_PROFILE` here: `tk` talks only to the socket. Pin
   `TK_GPG_PROGRAM` to the system GnuPG path when `gpg` is not on `PATH`.

7. **Rotate the broker session.** A host timer runs the state machine from
   [provisioning-session-agent](../provisioning-session-agent/SKILL.md):
   status, request, and activate execute in `gpg-broker`; provision executes
   in `provisioner`, bound to `BROKER_USER_ID` and the configured lifetime.
   After activation, restart `gpg-broker` so it builds a new API client.

8. **Gate the deployment.** Inspect mounts without printing file contents:
   the application has only the read-only runtime and public key; the broker
   alone has its home and runtime writable; the provisioner alone has its
   home. Require a mode-`0660` socket and a verified signed commit. Stop the
   broker and require signing to fail; start it, rotate, restart, sign again.

9. **Hand off.** Report image digests, uid/gid assignments, host mount paths,
   fingerprint, broker user id, policy ids, lifetime and timer, socket
   metadata, and gate results. Report no credential values or private material.

## Verified by

| Examples | Test |
|---|---|
| signing-broker.policy-sign, signing-broker.policy-deny, signing-broker.export, signing-broker.serve, signing-broker.client | gpg_agent::foreground_agent_signs_for_a_credential_free_git_client |

Mounts, ownership, supervision, broker loss, and rotation are manual gates;
the test proves a broker holding only the step 1 pair signs for a
credential-free client, refuses an unserved key, cannot register a credential,
and removes its socket on shutdown.

## Troubleshooting

- The application gets `permission denied`: its supplemental gid does not
  match the runtime and socket group, or the directory lacks group execute.
- Signing reports the agent is unavailable: the path is not a socket on both
  sides, or the broker left the foreground.
- `gpg keys export` or signing fails `unauthorized`: the broker user lacks
  `BROKER_TAG`, or the ALLOW names another wallet. Do not export as root.
- Signing fails only after rotation: stale API client in the broker. Restart it.
- `tk whoami` in the application resolves to the broker user, or it can sign
  or export with the broker's profile: the broker's credential crossed over.

## Related Skills

- [signing-git-commits](../signing-git-commits/SKILL.md): create the wallet and OpenPGP key.
- [provisioning-session-agent](../provisioning-session-agent/SKILL.md): create, provision, and rotate the broker user.
- [sidecar-patterns](../sidecar-patterns/SKILL.md): operate the general renewal loop and independent alert.
