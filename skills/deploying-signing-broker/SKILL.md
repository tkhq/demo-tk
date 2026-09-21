---
name: deploying-signing-broker
description: Deploy a credential-free application beside a single-key tk GPG signing broker and a separate session provisioner container. Use when containerizing OpenPGP Git signing so the application receives only a constrained Unix socket and public key, or when rotating the broker's expiring Turnkey credential; not for creating the signing key or choosing policies.
---

# Deploying a signing broker

Result: three containers with separate authority. The application can request
signatures from one OpenPGP key through a Unix socket. The broker alone holds
that key's Turnkey profile. The provisioner can renew the broker's expiring
API key but cannot sign or mint a key for itself.

## Reference

- [GPG signing](../../docs/gpg-signing.md): the foreground agent and client socket.
- [sessions](../../docs/sessions.md): the request, provision, activate, and status records.

## Rules

- Use three services and three process trees: application, GPG broker, and
  provisioner. Never mount one principal's `HOME` into another service.
- The application gets the broker runtime read-only. It gets no Turnkey
  profile, API key, registry, signing wallet credential, or provisioner state.
- The broker serves one pinned fingerprint. Its socket grants signing
  authority, so share it only with the application's supplemental group.
- The provisioner gets neither the broker runtime nor broker `HOME`. A host
  renewal controller passes it only the expected broker user id, generated
  public API key, and bounded lifetime.
- Publish no container ports. Drop capabilities, use a read-only root
  filesystem, and keep writable state in explicit bind mounts.
- Socket loss and broker failure fail closed. Do not fall back to an
  application credential or a second signing path.

## Instructions

Inputs: the signing fingerprint (`FINGERPRINT`), broker user id
(`BROKER_USER_ID`), broker profile (`broker`), provisioner profile
(`provisioner`), shared socket group id (`10000` below), and session
lifetime. Create the key and signing policy with
[signing-git-commits](../signing-git-commits/SKILL.md), then create the two
profiles and renewal policies with
[provisioning-session-agent](../provisioning-session-agent/SKILL.md).

1. **Lay out host state.** Create mode-`0700` homes for the application,
   broker, and provisioner, owned by their respective uids; the application
   home holds only Git configuration and a public GnuPG keyring. Create its
   writable worktree and a mode-`0770` runtime directory owned by the broker
   uid and socket gid. Persist the broker user id outside the application.
   Host root remains trusted.

2. **Define the services.** Adapt this Compose skeleton; pin the image by
   digest in production. The application image must contain `tk`, Git, and
   GnuPG for client framing and local verification.

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
       working_dir: /workspace
       volumes:
         - /opt/tk-app-home:/home/app
         - /opt/tk-app-workspace:/workspace
         - /opt/tk-gpg-runtime:/run/tk-gpg-agent:ro
       read_only: true
       cap_drop: [ALL]

     gpg-broker:
       image: your-tk-image@sha256:PINNED
       user: "10000:10000"
       environment:
         HOME: /home/broker
         TK_PROFILE: broker
       command:
         - tk
         - gpg
         - agent
         - serve
         - --key
         - FINGERPRINT
         - --socket
         - /run/tk-gpg-agent/agent.sock
         - --socket-mode
         - "660"
         - --non-interactive
       volumes:
         - /opt/tk-gpg-broker:/home/broker
         - /opt/tk-gpg-runtime:/run/tk-gpg-agent
       read_only: true
       tmpfs: [/tmp]
       cap_drop: [ALL]
       restart: unless-stopped

     provisioner:
       image: your-tk-image@sha256:PINNED
       user: "10001:10001"
       environment:
         HOME: /home/provisioner
         TK_PROFILE: provisioner
       command: [sleep, infinity]
       volumes:
         - /opt/tk-provisioner:/home/provisioner
       read_only: true
       tmpfs: [/tmp]
       cap_drop: [ALL]
       restart: unless-stopped
   ```

   Do not add `depends_on` as a readiness claim; gate application startup on
   the socket being a Unix socket with the expected owner, group, and mode.

3. **Start the broker.** The Compose command above is equivalent to:

   <!-- example: signing-broker.serve -->
   ```sh
   tk --profile broker gpg agent serve --key FINGERPRINT \
     --socket /run/tk-gpg-agent/agent.sock --socket-mode 660 --non-interactive
   ```

   Supervise it in the foreground. SIGTERM must reach `tk`; after shutdown,
   require its owned socket to be gone before starting a replacement.

4. **Configure the application.** Import only the armored public key into its
   GnuPG home, then point Git at the local `tk` binary:

   <!-- example: signing-broker.client -->
   ```sh
   export TK_GPG_AGENT_SOCK=/run/tk-gpg-agent/agent.sock
   git config --global gpg.format openpgp
   git config --global gpg.program tk
   git config --global user.signingkey FINGERPRINT
   git config --global commit.gpgsign true
   git commit -S --allow-empty -m test
   git verify-commit HEAD
   ```

   The application needs no `TK_PROFILE`. Pin `TK_GPG_PROGRAM` to the
   system GnuPG path when `gpg` is not on `PATH`.

5. **Rotate the broker session.** A host timer runs the state machine from
   [provisioning-session-agent](../provisioning-session-agent/SKILL.md):
   status and request execute in `gpg-broker`; provision executes in
   `provisioner`; activate executes in `gpg-broker`. Bind every provision
   request to `BROKER_USER_ID` and the configured lifetime. After activation,
   restart `gpg-broker` so it constructs a client from the new credential.

6. **Gate the deployment.** Inspect mounts without printing file contents:
   the application has only the read-only runtime; the broker alone has its
   home and runtime writable; the provisioner alone has its home. Require a
   mode-`0660` socket, a signed commit, and successful `git verify-commit`.
   Stop the broker and require signing to fail with no fallback. Start it,
   rotate its session, restart it, and repeat signing and verification.

7. **Hand off.** Report image digests, uid/gid assignments, host mount paths,
   fingerprint, broker user id, lifetime and timer, socket metadata, and gate
   results. Report no credential values or private material.

## Verified by

| Examples | Test |
|---|---|
| signing-broker.serve, signing-broker.client | gpg_agent::foreground_agent_signs_for_a_credential_free_git_client |

Container mounts, ownership, supervision, broker-loss failure, and rotation
are manual deployment gates; the test proves one-key socket confinement,
credential-free signing, local verification, and cleanup.

## Troubleshooting

- The application gets `permission denied`: its supplemental gid does not
  match the runtime and socket group, or the directory lacks group execute.
- Signing reports the agent is unavailable: check that the path is a socket
  inside both containers and that the broker remained in the foreground.
- Signing works before rotation but fails after it: activation changed the
  profile, but the broker still holds its old API client. Restart the broker.
- The application can run `tk login`: a credential store or ambient
  `TURNKEY_*` variable crossed the boundary. Remove it before proceeding.

## Related Skills

- [signing-git-commits](../signing-git-commits/SKILL.md): create and authorize the OpenPGP key.
- [provisioning-session-agent](../provisioning-session-agent/SKILL.md): provision and rotate the broker profile.
- [sidecar-patterns](../sidecar-patterns/SKILL.md): operate the general renewal loop and independent alert.
