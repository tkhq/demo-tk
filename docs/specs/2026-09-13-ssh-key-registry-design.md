# SSH key registry for git signing and the agent

Status: proposed. Base: `zeke/akshar-gpg-signing-v2` (#34). Supersedes
`2026-09-09-profile-identity-for-ssh-design.md`.

## Summary

The SSH commands (`tk ssh public-key`, `tk ssh git-sign`, `tk ssh agent`, and
the `tk -Y` git passthrough) still read `tk.toml` through
`turnkey_auth::config`, and each of them signs with the one Ed25519 key that
file names. The superseded spec kept that shape and only moved the key ID onto
the resolved profile. This spec replaces the "one identity carries one key"
model with a key registry, the SSH analogue of the OpenPGP key table that #34
adds for `tk gpg`:

- The identity registry gains an `ssh_keys` table. Each entry maps an OpenSSH
  public key to the Turnkey private key that produces it and the organization
  that owns it. The public key is captured when the key is registered, so
  listing keys, matching git's `-f <keyfile>`, and answering
  `SSH_AGENTC_REQUEST_IDENTITIES` never need the network.
- `tk -Y` parses git's `ssh-keygen -Y sign` invocation, reads the public key
  git passes in `-f`, and selects the registered entry with that key. It errors
  by name when the key is not registered. It never falls back to "whatever the
  active profile carries".
- The agent daemon serves every registered key. `SSH_AGENTC_REQUEST_IDENTITIES`
  lists all of them; `SSH_AGENTC_SIGN_REQUEST` signs with the entry whose blob
  the client named and fails only for a blob that is not registered.
- The credential for a signing call is chosen from the entry's organization
  with `auth::resolve_for_organization`, exactly as the gpg shim does.

The configuration goals of the superseded spec stand: `tk.toml`,
`TURNKEY_TK_CONFIG_PATH`, `tk config`, and `TURNKEY_PRIVATE_KEY_ID` are gone.
Profiles, the `TURNKEY_*` environment bundle, and the registry under
`~/.config/turnkey` are the only configuration.

## Goals

- One selection model for both git signing programs: gpg and SSH keys live in
  the identity registry, a signing request names a key, and the shim selects
  that key or fails saying which key it could not find.
- An SSH key is registered once, with its public key, and is then usable by
  the passthrough, `tk ssh public-key`, `tk ssh git-sign`, and the agent
  without a network round trip to discover it.
- The agent serves the whole registry, or a declared subset, and the subset is
  fixed and reported before the socket is bound.
- `tk.toml`, `TURNKEY_TK_CONFIG_PATH`, `tk config`, and `TURNKEY_PRIVATE_KEY_ID`
  are removed. README, `docs/git-signing.md`, and `docs/ssh-agent.md` describe
  the registry workflow end to end, including CI.
- Every new failure is a typed error classified by the existing taxonomy and
  named after the key or organization it concerns.

## Non-goals

- Migrating `tk.toml` or any `ssh_signing_key_id` written by an unreleased
  build of the superseded spec. `tk` is alpha; users run `tk ssh keys add`.
- Key types other than Ed25519. Turnkey signs SSH payloads with
  `HASH_FUNCTION_NOT_APPLICABLE`, which only Ed25519 supports here, and
  everything downstream (`ssh-ed25519` blobs, 64 byte signatures) is fixed
  to it. A registered key of another curve is rejected at registration.
- Changing the SSH wire format, SSHSIG layout, or agent protocol beyond
  returning more than one identity.
- Hot reloading the agent. A running daemon serves the table it started with;
  `tk ssh keys add` and `remove` say so in their human output.
- Adding the Async I/O Policy to `AGENTS.md`. The superseded spec called it a
  restoration, but the text has never been in `AGENTS.md` on any branch, and
  no workspace lint enforces it today. Whether to add it is an open question
  below, separate from this change.
- Prompting. Inputs stay flags, environment, and the registry.

## Design

### Where the code lives

The split follows `tk gpg`: the format layer stays in `turnkey_auth` and knows
nothing about identities, and the registry, selection, credential choice, and
commands live in `tk`.

`turnkey_auth::ssh` keeps `mod.rs` (public key line and blob codec, SSHSIG
payload and armor), `protocol.rs` (agent frames), and `agent.rs` (the socket
server, now generic over a keyring, see below). `turnkey_auth::config`,
`turnkey_auth::git_sign`, `turnkey_auth::public_key`, and
`turnkey_auth::turnkey` are deleted with their tests; `turnkey_auth::ssh::git`
moves into the tk shim.

`tk` gains `src/ssh/` mirroring `src/gpg/`:

| File | Holds |
|---|---|
| `ssh/mod.rs` | `SshCommand` (`keys`, `public-key`, `git-sign`, `agent`), outcome types, `selection_error`, `client_for_entry` |
| `ssh/registry.rs` | `SshKeyEntry`, `StoredSshKey`, `SshKeyTable`, `SshKeyName`, `SshFingerprint`, `SelectError` |
| `ssh/keys.rs` | `get_private_key` lookup that turns a private key ID into an `Ed25519PublicKey` |
| `ssh/signer.rs` | `TurnkeySigner`: `sign_raw_payload` for one entry, approval error enrichment |
| `ssh/shim.rs` | the `tk -Y` path: argument parsing, `-f` read, selection, signature file |
| `ssh/agent/{mod,daemon,lock}.rs` | the existing agent commands, moved from `commands/agent/` |

`commands/ssh.rs`, `commands/git_sign.rs`, `commands/public_key.rs`, and
`commands/config.rs` are deleted. `Outcome` keeps the agent variants and gains
the key and signing variants listed under Commands.

### Registry schema

`Registry` gains a table beside `gpg_keys`, absent from the file until the
first key is registered so version stays 1:

```rust
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Registry {
    version: u32,
    active_profile: Option<String>,
    #[serde(default)]
    profiles: BTreeMap<String, Profile>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    gpg_keys: BTreeMap<String, StoredGpgKey>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    ssh_keys: BTreeMap<String, StoredSshKey>,
}
```

`Profile` does not change. It carries no signing key; the table is the one
place that says which keys exist and which organization each belongs to.

An entry is keyed by the OpenSSH fingerprint of its public key, the
`SHA256:<base64>` string `ssh-keygen -lf` prints and `ssh-add -l` shows, so a
user can read a key name off any SSH tool and find it in the file:

```toml
[ssh_keys."SHA256:U6rF4v6c9z2g0Zt9k3n1YxQq8mE0Vb2Xc4Wd5Ye6Zf8"]
organization_id = "0f6c4e3e-7d1c-4b18-9f25-1c2b8d1a9e77"
private_key_id = "3d7b9d7c-2a0e-4b7f-8f8e-5e1f2d3c4b5a"
public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI..."
```

The persisted shape is its own type, distinct from the runtime entry:

```rust
/// The persisted shape of one entry, kept separate from [`SshKeyEntry`].
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredSshKey {
    organization_id: Uuid,
    /// Opaque: the API documents private key IDs as strings.
    private_key_id: String,
    /// The `ssh-ed25519 <base64>` line, without a comment.
    public_key: String,
}

#[derive(Clone)]
pub struct SshKeyEntry {
    pub organization_id: Uuid,
    pub private_key_id: PrivateKeyId,
    pub public_key: Ed25519PublicKey,
}
```

`Ed25519PublicKey` is a `[u8; 32]` newtype in `turnkey_auth::ssh` with
`blob()`, `line()`, and `fingerprint()`; `parse_public_key_line` returns it.
`SshFingerprint` is a newtype over the `SHA256:` string, parsed by `FromStr`.

`SshKeyTable::from_stored(stored, path)` parses each entry, recomputes the
fingerprint from `public_key`, and rejects an entry whose key does not produce
its own map key, naming the file and entry in an `InvalidInput`. The
`api_base_url` is deliberately not stored on the entry: the URL belongs to the
profile that holds the credential for the entry's organization, and storing it
twice would let them diverge.

### Naming a key

`SshKeyName` is the request side of selection, the counterpart of the gpg
`KeyName`. It is parsed from the one string a user or git supplies, and its
format decides which field it matches:

```rust
pub enum SshKeyName {
    /// `SHA256:...`, as SSH tools print it.
    Fingerprint(SshFingerprint),
    /// A full `ssh-ed25519 <base64>` line, as git writes to `-f`.
    PublicKey(Ed25519PublicKey),
    /// Anything else: the Turnkey private key ID used at registration.
    PrivateKeyId(PrivateKeyId),
}
```

`SshKeyTable::select(self, requested: Option<SshKeyName>) -> Result<SshKeyEntry,
SelectError>` reuses the generic `gpg::registry::select` (moved to a shared
`registry` module so both tables call it) with the same four outcomes:

| Table and request | Result |
|---|---|
| Empty table | `SelectError::Empty` |
| One entry, no name | that entry |
| Several entries, no name | `SelectError::Unnamed { count }` |
| Name matches none | `SelectError::NoMatch { requested }` |
| Name matches several | `SelectError::Ambiguous { requested }` |

A fingerprint or public key can match at most one entry because the
fingerprint is the map key. Only a `PrivateKeyId` name can be ambiguous, and
only when a hand-edited file lists the same private key twice; the variant
exists so the behavior is defined, and its remediation says to name the key
by fingerprint.

### Registering keys

Registration is the only place the network is needed to learn a public key.
It reads the private key through `get_private_key` with the resolved identity,
checks the curve, and stores the result:

```
tk ssh keys add --private-key-id <ID>
tk ssh keys list
tk ssh keys remove <KEY>
```

`keys add` resolves the identity as any API command does (`--profile`, then
the environment bundle, then the active profile), calls `get_private_key` for
`ID` in that organization, and inserts an `SshKeyEntry` for that organization.
The response is destructured exhaustively; a curve other than
`CURVE_ED25519` is `InvalidInput` naming the ID and its curve, an absent
private key is `MissingResource::new("private key", id)`, and a public key
that is not 32 hex bytes is an `ActivityError` of kind `MalformedResponse`
naming the field. Re-adding a registered key overwrites its entry.

`keys add` and `keys remove` are the only way a key enters or leaves the
table. The superseded spec's `--ssh-signing-key-id` flag on `login` and
`profile set` is not added: a key belongs to an organization, not a profile,
and a second registration path would only restate `keys add` with the
profile's credential. `login` is unchanged. `profile set` is kept for editing
a saved profile:

```
tk profile set NAME [--organization-id ID] [--api-base-url URL]
```

At least one flag is required by a clap `ArgGroup`, `--api-base-url` is
parsed by `ApiBaseUrl::parse`, an unknown profile is `InvalidInput("profile
NAME does not exist")`, and the rewrite is atomic under the registry lock.
Its record is `{"name", "profile"}` with the profile as `profile show`
renders it.

`keys remove <KEY>` takes an `SshKeyName`, selects, and removes the entry. The
Turnkey private key is untouched. `keys list` reads the table with no
credential.

`keys add` calls `auth::register_ssh_key(options, entry)`, which locks,
loads, inserts, and saves, the twin of `register_gpg_key`.

### Choosing a credential for an entry

Every signing path goes through the function #34 introduced:

```rust
async fn client_for_entry(
    options: &AuthOptions,
    entry: &SshKeyEntry,
) -> Result<(TurnkeyClient<TurnkeyP256ApiKey>, Uuid)> {
    let auth = auth::resolve_for_organization(options, entry.organization_id)
        .await
        .with_context(|| format!("select a credential for SSH key {}", entry.fingerprint()))?;
    Ok((build_turnkey_client(auth.stamper, &auth.api_base_url)?, auth.organization_id))
}
```

Its rules are unchanged. An explicit `--organization-id`, `--profile`, or
environment bundle must belong to the entry's organization or the call fails
with `OrganizationMismatch`. Otherwise the profiles for that organization are
searched: the only one, or the active profile among several, or a typed
`InvalidInput` naming the organization and the profiles.

### Git passthrough (`tk -Y`)

`main.rs` keeps the first argument check and hands `-Y` lines to
`ssh::shim::run`, which is its own output boundary like the gpg shim: stdout
and stderr are ssh-keygen's contract, errors are one `error: ...` line on
stderr with the rendered chain, and the exit code is 1.

The parser is the existing `GitSignInvocation`, extended with the operation:

```rust
pub enum Invocation {
    /// `-Y sign -n git -f <keyfile> [-U] <payload>`.
    Sign { public_key_path: PathBuf, payload_path: PathBuf },
    /// `-Y verify`, `-Y find-principals`, `-Y check-novalidate`: run ssh-keygen.
    Passthrough,
}
```

Verification calls are handed to the real `ssh-keygen` with `exec`, honoring
`TK_SSH_KEYGEN_PROGRAM`, so `git log --show-signature` works with
`gpg.ssh.program` set to `tk`. Today they fail with "unsupported ssh signer
operation". A namespace other than `git` and any unknown flag are rejected
during parsing as `InvalidInput`.

Signing:

1. Parse the arguments; read the payload and the `-f` file.
2. `parse_public_key_line` on the first line of the key file. A key of another
   algorithm is `InvalidInput("SSH key in <path> is <algorithm>; tk signs with
   ssh-ed25519 keys")`. A file that does not parse is `InvalidInput` naming the
   path.
3. `ShimOptions::from_environment()` (clap with no arguments, so only
   `TK_CONFIG` and `TK_PROFILE` bind), exactly as the gpg shim.
4. `auth::load_ssh_keys(&options).await?.select(Some(SshKeyName::PublicKey(key)))`.
   The request is always named, so `Unnamed` cannot occur here; `NoMatch` is
   rendered for git as "no registered SSH key matches SHA256:...; register it
   with tk ssh keys add --private-key-id <id>, or set user.signingkey to a
   registered key".
5. `client_for_entry`, build the SSHSIG payload, sign with `TurnkeySigner`,
   write `<payload>.sig` with the blob from the entry, which is the blob git
   supplied.

The public key comes from the entry rather than being read back from Turnkey,
so a signing call is one request. There is no path that ignores `-f`.

`tk ssh git-sign <ssh-keygen args>` stays as the clap-fronted way to run the
same signing, so a user can pass `--profile` when debugging.

### `tk ssh public-key`

```
tk ssh public-key [--key <KEY>]
```

Selects from the table with `key.map(SshKeyName::from)` and prints the
entry's line. No network. With several registered keys and no `--key` it is
the `Unnamed` error with the remediation "name one with --key". This replaces
the old command that fetched the key of the configured private key ID.

### Agent

#### Server generic over a keyring

`turnkey_auth::ssh::agent::run(socket, keyring)` takes an `Arc<dyn Keyring>`
in place of a `Config`:

```rust
pub struct AgentIdentity {
    pub public_key: Ed25519PublicKey,
    /// Shown by `ssh-add -L`.
    pub comment: String,
}

#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("no registered key has this public key blob")]
    UnknownKey,
    #[error(transparent)]
    Signer(#[from] anyhow::Error),
}

pub trait Keyring: Send + Sync {
    fn identities(&self) -> Vec<AgentIdentity>;
    fn sign<'a>(&'a self, public_key: &'a Ed25519PublicKey, data: &'a [u8]) -> SignFuture<'a>;
}
```

`SignFuture` is the boxed future alias the OpenPGP `SignDigest` trait already
uses. `SSH_AGENTC_REQUEST_IDENTITIES` encodes every identity;
`encode_request_identities_response` takes the slice. `SSH_AGENTC_SIGN_REQUEST`
parses the blob, converts it with `Ed25519PublicKey::from_blob` (a blob of
another algorithm is `UnknownKey` without a lookup), calls `sign`, and answers
`SSH_AGENT_FAILURE` for any error. The protocol carries no reason, so the
daemon logs `UnknownKey` at `debug` with the fingerprint and a `Signer` error
at `warn` with the chain; `tk ssh agent status` output is unchanged. A
malformed frame keeps its current `SSH_AGENT_FAILURE` answer.

#### The tk keyring

`ssh::agent::daemon` implements `Keyring` over the table:

```rust
struct RegistryKeyring {
    entries: BTreeMap<Ed25519PublicKey, SshKeyEntry>,
    clients: BTreeMap<Uuid, TurnkeyClient<TurnkeyP256ApiKey>>,
}
```

`internal-run` builds it before binding the socket: load the table, apply the
narrowing below, fail on an empty result, then call
`auth::resolve_for_organization` once for each distinct organization and keep
one client per organization. Credentials are read from disk exactly once, at
start, and a resolution failure exits the child nonzero with the error on
stderr before any socket exists, which `start` surfaces as its own error. The
comment for each identity is `turnkey:<private_key_id>`.

`sign` looks the blob up in `entries`, then signs with the client for the
entry's organization through `TurnkeySigner`. There is no equality gate
against one configured key; a blob that is not in `entries` is `UnknownKey`.

#### Start, narrowing, and forwarding

```
tk ssh agent start [--key <KEY>]... [--socket PATH] [--pid-file PATH]
```

By default the daemon serves every registered key across every organization
the registry holds a credential for. Two things narrow that:

- The global identity flags. When `--profile`/`TK_PROFILE` selects a profile,
  or the environment bundle is present, or `--organization-id` is given, only
  entries of that organization are served and that identity is the credential
  for them. This is the same rule `resolve_for_organization` applies per
  entry, stated once over the table rather than failing entry by entry.
- `--key <KEY>` (repeatable) serves only the named entries. Each name must
  select exactly one entry or `start` fails with the selection error for that
  name.

`start` performs the same load and narrowing itself before spawning, so
"nothing to serve" is reported without a child process, and then forwards the
selection to the child: `--config`, `--profile`, `--organization-id`,
`--api-base-url`, and every `--key`. The environment bundle is inherited as
today. The child repeats the computation and is authoritative; the parent's
copy exists to fail fast. `AgentRunning` gains `keys: Vec<String>` (the served
fingerprints) so `start` and `status` report what the agent holds.

Socket and pid files move to `~/.config/turnkey/ssh-agent.sock` and
`~/.config/turnkey/ssh-agent.pid`, beside the registry. `--socket` and
`--pid-file` keep working.

### Removing `tk config` and the environment key ID

`auth/src/config.rs`, `tk/src/commands/config.rs`, the `Config` outcome
variants, `tk/tests/config_command.rs`, and `auth/tests/config_resolution.rs`
are deleted. `tk config` becomes an unknown command (`usage_error`, exit 2).
`TURNKEY_TK_CONFIG_PATH` is read nowhere.

`TURNKEY_PRIVATE_KEY_ID` is removed rather than turned into an implicit
one-entry registry. CI registers its key once with the bundle in the
environment:

```sh
tk ssh keys add --private-key-id "$TURNKEY_SSH_KEY_ID"
git config --global gpg.ssh.program "$(command -v tk)"
git config --global user.signingkey "key::$(tk ssh public-key)"
```

The bundle then supplies the credential for that organization at each signing
call, as it does for `tk gpg`. One model, no environment-only special case.

### Errors

All failures are typed and classified by the existing taxonomy. `SelectError`
states the fact and the entry point adds the remediation, so git users are
told about `user.signingkey` and terminal users about a flag.

| Situation | Type | Code | Remediation in message |
|---|---|---|---|
| Registry has no SSH keys (any entry point, agent start included) | `SelectError::Empty` | `invalid_input` | `tk ssh keys add --private-key-id ID` |
| Several keys, none named (`public-key`, `keys remove`) | `SelectError::Unnamed` | `invalid_input` | `--key` / the positional key |
| Named key not registered (`-Y`, `public-key --key`, `agent start --key`) | `SelectError::NoMatch` | `invalid_input` | `tk ssh keys add --private-key-id ID`; git: also `user.signingkey` |
| Private key ID name matches several entries | `SelectError::Ambiguous` | `invalid_input` | name it by `SHA256:` fingerprint |
| Narrowed agent set is empty (profile or bundle org holds no registered key) | `InvalidInput` naming organization and source | `invalid_input` | `tk ssh keys add`, or drop `--profile` |
| Explicit identity belongs to another organization than the key | `OrganizationMismatch` | `invalid_input` | existing message |
| No profile holds a credential for the key's organization | `InvalidInput` (from `resolve_for_organization`) | `invalid_input` | `tk login ... --organization-id ORG` |
| `-f` file missing or unreadable | `io::Error` with path context | `command_error` | |
| `-f` key not `ssh-ed25519`, or not an OpenSSH line | `InvalidInput` naming path and algorithm | `invalid_input` | |
| `keys add` on a non-Ed25519 private key | `InvalidInput` naming ID and curve | `invalid_input` | |
| `keys add`: `get_private_key` returned no key | `MissingResource("private key", id)` | `not_found` | |
| `keys add`: public key field not 32 hex bytes | `ActivityError::MalformedResponse` naming the field | `api_error` | |
| Registry entry whose key does not produce its fingerprint, or malformed field | `InvalidInput` naming file and entry | `invalid_input` | |
| `profile set` with no flags | clap `ArgGroup` | `usage_error` | |
| `profile set` on an unknown profile | `InvalidInput` | `invalid_input` | existing message |
| Agent sign request for an unregistered blob | `SignError::UnknownKey` | wire: `SSH_AGENT_FAILURE`; log `debug` | |
| Agent sign request that Turnkey refuses or that needs approval | `SignError::Signer` carrying `TurnkeyClientError` | wire: `SSH_AGENT_FAILURE`; log `warn` | |
| Daemon startup failure (empty set, credential) | child stderr line | `start` returns `invalid_input` or `command_error` from the chain | |

### Commands and outcome records

| Command | Outcome variant | Record |
|---|---|---|
| `ssh keys add` | `SshKeyRegistered` | `{fingerprint, publicKey, organizationId, privateKeyId}` |
| `ssh keys list` | `SshKeysRegistered` | `{keys: [{fingerprint, publicKey, organizationId, privateKeyId}]}` |
| `ssh keys remove` | `SshKeyRemoved` | same shape as registered |
| `ssh public-key` | `PublicKeyPrinted` | `{fingerprint, publicKey}`; human output is the bare line |
| `ssh git-sign` | `GitSignCompleted` | unchanged |
| `ssh agent start` / `status` | `AgentStarted` / `AgentStatusReport` | `{pid, socket, keys: [fingerprint]}` |
| `profile set` | (operation output) | `{name, profile}` |

Human output of `keys add` and `keys remove` ends with "restart tk ssh agent
to pick this up" when the pid file's lock is held.

### Documentation

- **README**: Commands lists `tk login`, `tk auth`, `tk profile`,
  `tk api-key generate`, `tk ssh keys`, `tk ssh public-key`, `tk ssh agent`,
  and points to `docs/core.md` for API commands and `docs/secrets.md`.
  Configuration describes the three step identity resolution, the registry
  at `~/.config/turnkey/tk.config.toml` and `TK_CONFIG`, a walkthrough
  (`api-key generate`, register the credential, `login`, `ssh keys add`), the
  bundle for CI, and a line stating `tk.toml` is no longer read.
- **docs/git-signing.md**: `ssh keys add`, `user.signingkey` from
  `tk ssh public-key`, the allowed signers file, verification through the
  passthrough, and how a user with several keys pins one per repository with
  `git config user.signingkey`.
- **docs/ssh-agent.md**: the new socket path, `ssh-add -L` listing every
  registered key, `--key` and `--profile` narrowing, and the restart note.
- **docs/core.md**: remove any statement that SSH commands use `tk.toml`.

## Testing

The e2e suite covers everything the live API can produce; unit and mock
tests cover only what it cannot.

### End-to-end (`crates/tk/tests/e2e/ssh.rs`)

Each test starts with `Run::new()` and runs through the runner's bundles. An
Ed25519 private key is created in the sub-organization with
`run.submit(run.admin().args(["request", ...create_private_keys...]))`; the
sub-organization deletion removes it.

- **Register, list, print, remove**: `ssh keys add --private-key-id`,
  `keys list` equals the expected record, `ssh public-key` prints the line
  whose fingerprint matches, `keys remove` by fingerprint, by line, and by
  private key ID, `keys list` is empty. Registry stays mode 0600.
- **Real git signing through the passthrough**: two keys registered; a
  repository with `gpg.format ssh`, `gpg.ssh.program` set to the test binary,
  `user.signingkey key::<line of key B>`; `git commit -S`; then
  `git verify-commit` with an allowed signers file, which exercises the
  `-Y verify` passthrough to the real `ssh-keygen`. Asserts the signature
  names key B, proving `-f` drove the selection with key A also present.
- **Passthrough errors by name**: `user.signingkey` set to an unregistered
  Ed25519 key fails with the `NoMatch` message carrying that fingerprint; an
  RSA key fails naming `ssh-rsa`; an empty registry fails with the `Empty`
  message.
- **Agent serves the registry**: `ssh agent start` with two keys, `ssh-add -L`
  against the socket lists both lines, `ssh-keygen -Y sign -U -f <key B>`
  produces a signature that `ssh-keygen -Y verify` accepts (a real client
  driving `SSH_AGENTC_SIGN_REQUEST` for a chosen key), `status` reports both
  fingerprints, `stop`.
- **Agent narrowing**: `start --key <fingerprint A>` lists only A;
  `ssh-keygen -Y sign -U -f <key B>` fails; `start --profile` of a second
  profile in the same organization serves the set; `start` with an empty
  registry fails before any socket exists.
- **profile set**: `--api-base-url` and `--organization-id` rewrite the
  profile and the record matches `profile show`; the profile shows no key
  field; `profile set` on an unknown name is `invalid_input`.
- **Removals**: `tk config list` exits 2 with `usage_error`;
  `TURNKEY_PRIVATE_KEY_ID` and `TURNKEY_TK_CONFIG_PATH` in the environment
  change nothing.

### Unit and mock-server tests

- **Wire protocol** (`crates/auth/tests/ssh_agent.rs`): identities answer with
  zero, one, and three blobs; sign request parsing unchanged.
- **Agent server with a stub keyring** (`crates/auth/tests`): an in-process
  socket and a `Keyring` that knows two keys and signs with a fixed pattern.
  Asserts `REQUEST_IDENTITIES` frames both, `SIGN_REQUEST` for the second key
  returns the stub signature, an unregistered blob and an RSA blob return
  `SSH_AGENT_FAILURE`, a truncated frame returns `SSH_AGENT_FAILURE`. The live
  suite cannot hand-craft frames.
- **Shim parsing** (`ssh/shim.rs`): `Sign` for git's real argument lines with
  and without `-U`; `Passthrough` for `-Y verify` and `-Y find-principals`; an
  unknown flag and a non-`git` namespace are `InvalidInput`.
- **Registry** (`ssh/registry.rs`): `from_stored` rejects a fingerprint that
  does not match its key, a non-Ed25519 line, and a bad UUID, each naming the
  entry and file; `SshKeyName::from` classifies the three formats; `select`
  covers the four errors including `Ambiguous` from a duplicated private key
  ID.
- **Registration against wiremock** (`ssh/keys.rs`): `get_private_key`
  returning a P-256 key is `InvalidInput` naming the curve; a public key of 31
  bytes is `MalformedResponse` naming the field; an absent key is
  `MissingResource`. The live API does not return these on demand.
- **Daemon signing failures against wiremock**: `ACTIVITY_STATUS_CONSENSUS_NEEDED`
  and an HTTP 500 during `sign_raw_payload` both yield `SSH_AGENT_FAILURE`
  and a `warn` log; the port of today's `turnkey.rs` approval tests.
- **Clap**: `profile set` with no flags is a usage error; `--key` repeats on
  `agent start`; `keys remove` requires its positional.

Delete `crates/tk/tests/git_sign.rs`, `public_key_command.rs`,
`agent_command.rs`, and `config_command.rs` where an e2e test above covers the
behavior; keep the wiremock cases listed here.

All four gates pass: `cargo fmt --check`, `cargo clippy --all-targets --
-D warnings`, `cargo build --workspace`, `cargo test --workspace`, and the
e2e suite with `cargo test -p tk --test e2e -- --ignored`.

## Implementation order

1. Rebase onto `zeke/akshar-gpg-signing-v2`; move `gpg::registry::select`,
   `Scope`, and `SelectError` to a shared `registry` module.
2. `Ed25519PublicKey` and `SshFingerprint` in `turnkey_auth::ssh`; make
   `parse_public_key_line` return the typed key.
3. `ssh/registry.rs`, the `ssh_keys` table, `load_ssh_keys`,
   `register_ssh_key`, `remove_ssh_key` in `auth.rs`.
4. `ssh/keys.rs` and `ssh/signer.rs`; `tk ssh keys add|list|remove` and
   `tk ssh public-key` over the table.
5. `ssh/shim.rs`: move `GitSignInvocation`, add `Passthrough`, select by `-f`,
   wire `main.rs`; port `tk ssh git-sign`.
6. `Keyring` in `turnkey_auth::ssh::agent`; `RegistryKeyring`, narrowing,
   forwarding, and the new socket path in `ssh/agent/`.
7. `profile set`.
8. Delete `auth::config`, `git_sign`, `public_key`, `turnkey`, `tk config`,
   `TURNKEY_PRIVATE_KEY_ID`, and their tests; drop the dead names from the e2e
   `SCRUBBED` list.
9. `tests/e2e/ssh.rs`, the stub keyring test, wiremock cases.
10. README, `docs/git-signing.md`, `docs/ssh-agent.md`, `docs/core.md`.

## Open questions

Decisions taken in this draft that the reviewer should confirm:

- `TURNKEY_PRIVATE_KEY_ID` is dropped; CI runs `tk ssh keys add` once. The
  alternative, an environment-only implicit entry, would need a network read
  of the public key on every passthrough call and a second selection path.
- The agent snapshots the table at start. Reloading per request would make
  `keys add` visible to a running agent but moves credential failures to sign
  time, where the protocol cannot report them.
- `-Y verify` and `-Y find-principals` are handed to the real `ssh-keygen`,
  as the gpg shim hands verification to gpg. Without it, `git log
  --show-signature` fails once `gpg.ssh.program` points at `tk`.
- The Async I/O Policy (`tokio::fs` over `std::fs`, `spawn_blocking` for
  unavoidable blocking work) is not part of this spec. If it is wanted, it is
  an `AGENTS.md` change on its own, and a `disallowed-methods` entry for
  `std::fs::*` in `clippy.toml` would enforce it better than prose.
- `Profile` carries no SSH field and neither `login` nor `profile set` takes
  `--ssh-signing-key-id`; `tk ssh keys add` and `remove` are the only
  registration commands.
