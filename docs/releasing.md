# Releasing `tk`

Push a `v*` tag to start the `release` workflow. The workflow builds a native
binary for every supported target, checksums each one, and publishes a GitHub
release. `install.sh` installs from that release.

```sh
git switch main && git pull --ff-only
git tag v0.2.0
git push origin v0.2.0
```

## Rules

- **The tag must point at a commit already on `main`.** The `validate` job
  refuses a tagged commit that is not an ancestor of `origin/main`.
- **Wait for `main` CI to pass on the commit before tagging it.** The release
  workflow builds the binaries but does not run the test suite.
- **Never move or reuse a published tag.** Bump to a new version instead. The
  installer resolves versions by tag name.

## The tag is the version

The workflow passes the tag to the build as `TK_RELEASE_VERSION`.
`crates/tk/build.rs` bakes it into the binary as `TK_VERSION`, which
`tk --version` reports. A local build falls back to `git describe --tags`, then
to the manifest version.

## Artifact contract

Each release publishes two files for every target:

```
tk-<target>-<vX.Y.Z>.tar.gz          # one directory, tk-<target>-<vX.Y.Z>/, holding tk and README.md
tk-<target>-<vX.Y.Z>.tar.gz.sha256   # `shasum -a 256` output (hash and filename)
```
