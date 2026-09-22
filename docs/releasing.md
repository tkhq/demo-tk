# Releasing `tk`

Push a `v*` tag to start the `release` workflow. The workflow builds a native
binary for every supported target, checksums each one, and publishes a GitHub
release. `install.sh` installs from that release.

1. Open a pull request that bumps `version` under `[workspace.package]` in the
   root `Cargo.toml` and refreshes the pinned entries in `Cargo.lock`, and wait
   for CI to pass. Every crate inherits that one version with
   `version.workspace = true`, so the whole workspace moves together. CI, the
   tag validation, and the release build run with `--locked`, so a stale
   lockfile fails all three:

   ```sh
   cargo update -p tk -p turnkey_auth --offline
   ```
2. Merge it to `main`.
3. Tag the merge commit with the same version prefixed by `v` and push the
   tag:

   ```sh
   git switch main && git pull --ff-only
   git tag v0.2.0
   git push origin v0.2.0
   ```

## Rules

- **The tag must equal `v` plus the `tk` manifest version and point at a
  commit already on `main`.** The `validate` job refuses any other tag,
  including release candidates, which the installer would otherwise treat as
  the latest stable release, and any tagged commit that is not an ancestor of
  `origin/main`.
- **Wait for `main` CI to pass on the commit before tagging it.** The release
  workflow builds the binaries but does not run the test suite.
- **Never move or reuse a published tag.** Bump to a new version instead. The
  installer resolves versions by tag name.

## The manifest is the version

`tk --version` reports the `tk` manifest version, and the release tag must match
it. That version lives in `[workspace.package]`, so bumping it there is what
moves the release.

## Artifact contract

Each release publishes two files for every target:

```
tk-<target>-<vX.Y.Z>.tar.gz          # one directory, tk-<target>-<vX.Y.Z>/, holding tk and README.md
tk-<target>-<vX.Y.Z>.tar.gz.sha256   # `shasum -a 256` output (hash and filename)
```

## Live end-to-end job

The `e2e` workflow runs `cargo test -p tk --test e2e -- --ignored` against a
real Turnkey organization whose root credential lives in the repository
secrets `TK_E2E_ORGANIZATION_ID`, `TK_E2E_API_PUBLIC_KEY`,
`TK_E2E_API_PRIVATE_KEY`, and optionally `TK_E2E_API_BASE_URL`. Those
secrets never reach a fork: the job runs only for pushes to `main`, manual
dispatch, and pull requests whose head lives in this repository. One run at a
time holds the `e2e-turnkey-org` concurrency group, and the suite is capped
at four threads because the API rate-limits the whole organization family
for a minute once its shared request bucket empties.

Every skill under `skills/` names the tests that execute its steps in its
`## Verified by` table, and the e2e binary's own listing checks those names
compile. A merge that changes a skill's commands therefore needs a green
run of that job, or an attached local run with the same command, before it
lands. Locally, copy the same values into `.env.test` at the repository
root (gitignored) and run:

```sh
cargo test -p tk --test e2e -- --ignored --test-threads 4
```
