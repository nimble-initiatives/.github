# Image scan action

Scans a tenant image with [Trivy](https://github.com/aquasecurity/trivy), by digest, and fails
when Strife's image policy blocks it (OPS-483). The policy is
[wieldyapp/wieldy](https://github.com/wieldyapp/wieldy)'s (OPS-247), vendored here so every
repo in this org judges images the same way.

**Blocks on:** a fixable CRITICAL vulnerability, any secret in an image layer, or an image that
couldn't be scanned. **Counts, doesn't block:** HIGH findings and CRITICAL ones with no fix.

## Use

In the workflow that pushes the image, add a job of its own after the build and make the
deploy depend on it. It needs `packages: read` (the image is private) and nothing else:
no secrets, no write scopes.

```yaml
  scan:
    needs: build
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: read
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
          sparse-checkout: .github/trivy        # only the exceptions file
      - uses: nimble-initiatives/.github/actions/image-scan@<full commit sha>
        with:
          name: web
          image: ghcr.io/nimble-initiatives/my-app@${{ needs.build.outputs.digest }}
          # enforce: "false"   # report-only while the current image still fails (see below)
```

`needs.build.outputs.digest` is `docker/build-push-action`'s `digest` output, passed up as a
job output. Pin this action by **full commit SHA**, never a branch or tag.

| Input | Default | |
|---|---|---|
| `image` | | the image, `repo@sha256:…` (a tag is refused: it can move after the scan) |
| `name` | `image` | name in the summary, `[a-z0-9-]` |
| `platforms` | `linux/amd64` | comma-separated; hosting's nodes are all amd64 |
| `targets` | | several images at once: `[{"name", "image", "platforms": [...]}]` |
| `ignorefile` | `.github/trivy/ignore.yaml` | the repo's exceptions; missing means none |
| `enforce` | `"true"` | `"false"` reports without failing |
| `token` | `github.token` | presented to ghcr.io for this org's images only |

The run's step summary has a table per image; the full JSON reports are kept as the
`trivy-reports-<job>-<name>` artifact (`-targets` when `targets` is used) for 90 days.

## When it blocks

Fix first: rebuild to pick up a patched base image, or bump the dependency. If neither is
possible yet, add an exception to `.github/trivy/ignore.yaml` in your repo. Every entry needs an
`id`, a `statement` (why, who decided, the Linear issue) and an `expired_at` at most 90 days
ahead. The step checks this and refuses an entry without them:

```yaml
vulnerabilities:
  - id: CVE-2026-12345
    purls:
      - pkg:npm/some-package@1.2.3
    statement: No fixed release yet; not reachable because … Decided by <name>, OPS-NNN.
    expired_at: 2026-12-01
```

`enforce: "false"` is for rolling the gate into a repo whose current image already fails. It
still writes the summary and annotations, but the step passes. Set a date to switch it on.

## Maintaining

- `image_scan.py` and `test_image_scan.py` are wieldy's `.github/ci/image-scan/` files at
  `585d3454a18b` with one change: the token's image prefix comes from the action
  (`IMAGE_SCAN_AUTH_PREFIX`). Refresh them together; CI runs the tests.
- Trivy is a pinned release binary checked against a committed sha256, never
  `aquasecurity/trivy-action` (its tags were hijacked in March 2026). Bump version and checksum
  together, to a release at least two weeks old.
