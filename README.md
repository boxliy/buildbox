# buildbox

Buildbox contains the GitHub Actions runner contract for immutable Hawk
Build Spec v1 attempts. Phase A focuses on Swan Android artifacts (`apk`, `aab`)
with compile/sign runner separation; `ipa` is accepted in the contract loader
for forward alignment with Hawk but is not compiled in this repository yet.

## Android workflow

Run `.github/workflows/build.yml` manually with one input. A push that only
changes this workflow file is skipped and does not start a product build.
GitHub otherwise records that push as a failed run with zero jobs:

- `build_run_id`: Hawk platform workflow run id for one immutable attempt

No repository, commit, upload URL, token, or business configuration is accepted
as workflow input. Runtime authority comes from these repository secrets:

- `HAWK_BASE_URL`
- `HAWK_BUILDBOX_TOKEN`
- `AVIARY_SOURCE_TOKEN`: read-only access to the private Aviary repository

Jobs run on separate runners:

| Job | Hawk token | Role |
|-----|------------|------|
| `prepare` | yes | Load spec, verify hash, reject a public repository, then report `running` |
| `compile` | no | Checkout Aviary at `commitSha`, build `unsigned_release` outputs |
| `sign` | no | Isolated signing step; fails closed without a real signer |
| `finalize` | yes | Upload only after sign succeeds; otherwise report `failed` |

The compile job never receives `HAWK_BUILDBOX_TOKEN`, signing material, the
Hawk response body, or presigned upload URLs. `prepare` exports a compile
slice (`spec` without `uploads`, targets, dart defines, swan config) and a
sign slice (run id, spec hash, targets). Unsigned artifacts move to `sign`
as their own artifact. `build-android` rejects debug-signed and already-signed
zip outputs. `sign-android` rejects those same states and exits non-zero when
signing material is absent or when no production signer is implemented.
Phase A does not copy unsigned bytes forward or report `succeeded`.

## Spec v1 targets and object keys

Canonical Hawk target names are `apk`, `aab`, and `ipa`. `load-build-spec`
canonicalizes legacy `android_apk` / `android_aab` in API responses when
present. Object keys use `{artifactPrefix}{target}.{ext}` (for example
`builds/.../apk.apk`, `builds/.../aab.aab`).

`specHash` is `sha256:` + hex(SHA-256(JCS-sorted compact JSON of `config`)).
The loader recomputes and rejects mismatches.

## Hawk response contract

`scripts/load-build-spec` requires:

- `sourceRepo`, `commitSha`, `targets`, `runId`, `config`, `specHash`
- `artifactPrefix`, `uploads[]` with `target`, `url`, `contentType`, `headers`, `objectKey`
- `config.androidApplicationId`, `config.appDisplayName`

Optional: `config.dartDefines`, `config.swanConfig`.

Callbacks: `POST /api/v1/buildbox/runs/{runId}/callback` with `status`,
`githubRunId`, and `artifacts[]` on success.

## OIDC and short-lived credentials (phase B)

Phase A still uses the shared bearer for prepare/finalize against Hawk.
GitHub OIDC exchange (`POST /api/v1/buildbox/auth/exchange`), stage-scoped
tokens, and reusable workflow SHA pinning for prepare/sign/finalize will land
with Hawk integration in AVIARY-47 phase B.

## Local contract tests

Fixtures and mock `curl` / `flutter` / `git` only:

```sh
tests/contract.sh
```

## Phase A limitations

- `sign-android` has no production signer. Missing material and a present
  material directory both fail. That failure is not a signed delivery.
- Compile and sign artifacts omit presigned URLs. `prepare` rejects a public
  repository before it reports `running`. That rejection reports `failed` from
  the prepare job, so Hawk does not stay `running` when `finalize` is skipped.
  Unsigned outputs are not published as Actions artifacts until a private
  runner is available.
- OIDC, reusable workflow SHA pins, and real keystore signing remain phase B.
