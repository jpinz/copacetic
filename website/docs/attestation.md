---
title: SLSA/in-toto Attestations
---

# SLSA / in-toto Attestations

Copa can generate an **in-toto Statement** for every patched image.
The attestation follows a Copa-specific predicate (`https://copacetic.dev/patch/v0.1`)
modelled on SLSA provenance and records:

- The **subject** — the patched image (by tag and digest, when available).
- The **original image** as an input material (including its digest when resolvable
  before patching begins).
- **Invocation parameters** — which image was patched, the target platform, the
  vulnerability report file, and key Copa options.
- **Package update details** — packages updated, packages that errored, and an
  aggregate summary.
- **Build timestamps** — start and finish times.
- The Copa **builder version**.

## Why attestations matter

A Copa patch changes the image content, which means:

1. The *digest* of the image changes — any prior attestation signature over the
   original digest is no longer valid for the patched image.
2. Downstream verifiers need a chain-of-custody record to understand *what*
   changed and *who* changed it.

Copa follows the regenerate-not-mutate principle:

- The original image and any of its attestations are **not modified**.
- A **new attestation is generated** for the patched image, referencing the
  original image digest as a material input.
- The chain `original image → Copa patch → patched image` is preserved
  cryptographically via digest references.

## Usage

Pass `--attestation-output <path>` to `copa patch` to write the attestation:

```bash
copa patch \
  --image nginx:1.21.6 \
  --report trivy.json \
  --attestation-output nginx-patched-attestation.json
```

The output file contains a JSON-encoded in-toto Statement that you can inspect
directly:

```bash
cat nginx-patched-attestation.json | jq .
```

### Example output

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    {
      "name": "docker.io/library/nginx:1.21.6-patched",
      "digest": {
        "sha256": "abc123..."
      }
    }
  ],
  "predicateType": "https://copacetic.dev/patch/v0.1",
  "predicate": {
    "buildType": "https://copacetic.dev/patch/v0.1",
    "builder": {
      "id": "https://github.com/project-copacetic/copacetic",
      "version": "v0.8.0"
    },
    "invocation": {
      "configSource": {
        "uri": "https://github.com/project-copacetic/copacetic"
      },
      "parameters": {
        "originalImageRef": "docker.io/library/nginx:1.21.6",
        "platform": "linux/amd64",
        "reportFile": "trivy.json",
        "ignoreError": false,
        "pkgTypes": "os",
        "scanner": "trivy"
      }
    },
    "materials": [
      {
        "uri": "docker.io/library/nginx:1.21.6",
        "digest": {
          "sha256": "original-digest-hex..."
        }
      }
    ],
    "metadata": {
      "buildStartedOn": "2024-01-15T10:00:00Z",
      "buildFinishedOn": "2024-01-15T10:02:30Z",
      "completeness": {
        "parameters": true,
        "materials": true,
        "environment": false
      }
    },
    "patchDetails": {
      "patchedImageRef": "docker.io/library/nginx:1.21.6-patched",
      "packagesUpdated": [
        {
          "name": "libssl1.1",
          "installedVersion": "1.1.1k-1+deb11u2",
          "fixedVersion": "1.1.1n-1+deb11u3",
          "vulnerabilityID": "CVE-2022-0778",
          "type": "deb"
        }
      ],
      "summary": {
        "total": 3,
        "patched": 3,
        "skipped": 0
      }
    }
  }
}
```

## Two cases

### Case 1 — Image has no existing attestation

Copa generates a **new attestation** covering the whole patched image.  
The `materials` list contains the original image (with digest when available),
and the `patchDetails` section lists which packages were updated.

### Case 2 — Image already has attestation(s)

Copa **does not modify the original attestation**.  
Instead it generates a **new attestation for the patched image** and records the
original image digest as a material input.  The consumer can chain these together
to form the full provenance lineage:

```
upstream SLSA provenance (original image)
  ↓ original image digest recorded as material
Copa attestation (patched image)
```

If you want to discover and record the original attestation digests as additional
materials, use a tool such as `cosign` or `oras` to enumerate the referrers of
the original image digest and incorporate them into your supply-chain tooling.

## Storage model and limitations

| Scenario | Attestation storage |
|---|---|
| `--push` (image pushed to registry) | File written to `--attestation-output` path. You can then push the attestation as an OCI referrer using `cosign attest --predicate`. |
| Local image (no `--push`) | File written to `--attestation-output` path as the only available fallback. OCI referrer attachment is not possible without a registry. |
| Multi-platform patching | Attestation is **not yet generated** for multi-platform patching. This is a known limitation to be addressed in a future release. |

### Attaching the attestation to a registry

After pushing the patched image, you can attach the Copa attestation as an OCI
referrer using `cosign`:

```bash
# Push the patched image first
copa patch --image nginx:1.21.6 --report trivy.json --push \
  --attestation-output nginx-attestation.json

# Attach as a cosign attestation (requires a signing key)
cosign attest \
  --predicate nginx-attestation.json \
  --type https://copacetic.dev/patch/v0.1 \
  nginx:1.21.6-patched

# Or attach as a raw OCI artifact with oras
oras attach \
  --artifact-type application/vnd.copacetic.attestation.v0.1+json \
  nginx:1.21.6-patched \
  nginx-attestation.json
```

## Security considerations

- The Copa attestation is **unsigned** by default. To make it verifiable,
  sign it with `cosign sign-blob` or attach it via `cosign attest` with a key
  or keyless signing (Sigstore).
- The original image signatures are **not transferred** to the patched image.
  Signatures are mathematically bound to the original digest and cannot be
  reused for the patched image.
- The `environment: false` completeness flag acknowledges that Copa does not
  currently record its full build environment in the attestation.

## Predicate schema reference

| Field | Type | Description |
|---|---|---|
| `buildType` | string | Always `https://copacetic.dev/patch/v0.1` |
| `builder.id` | string | Copa GitHub URL |
| `builder.version` | string | Copa release version |
| `invocation.parameters.originalImageRef` | string | Source image reference |
| `invocation.parameters.platform` | string | Target platform (e.g. `linux/amd64`) |
| `invocation.parameters.reportFile` | string | Vulnerability report filename |
| `invocation.parameters.ignoreError` | bool | Value of `--ignore-errors` flag |
| `invocation.parameters.pkgTypes` | string | Package types patched |
| `invocation.parameters.scanner` | string | Scanner used |
| `materials[].uri` | string | Original image reference |
| `materials[].digest` | map | Algorithm → hex digest map |
| `metadata.buildStartedOn` | RFC3339 | Patch operation start time |
| `metadata.buildFinishedOn` | RFC3339 | Patch operation finish time |
| `metadata.completeness.parameters` | bool | Always `true` |
| `metadata.completeness.materials` | bool | `true` when original digest resolved |
| `metadata.completeness.environment` | bool | Always `false` |
| `patchDetails.patchedImageRef` | string | Output image reference |
| `patchDetails.packagesUpdated` | array | Package update records |
| `patchDetails.packagesErrored` | array | Package names that failed |
| `patchDetails.summary.total` | int | Total vulnerabilities considered |
| `patchDetails.summary.patched` | int | Vulnerabilities patched |
| `patchDetails.summary.skipped` | int | Vulnerabilities skipped |
