# buildbox

Buildbox contains the GitHub Actions runner contract for immutable Hawk
Build Spec v1 attempts. Phase A focuses on Swan Android artifacts (`apk`, `aab`)
with compile/sign runner separation; `ipa` is accepted in the contract loader
for forward alignment with Hawk but is not compiled in this repository yet.

## Android workflow

Run `.github/workflows/build.yml` manually with one input:

- `build_spec_id`: Hawk-issued `<spec_id>:<run_id>` identity for one immutable attempt

No repository, commit, upload URL, token, or business configuration is accepted
as workflow input. Runtime authority comes from these repository secrets:

- `HAWK_BASE_URL`
- `HAWK_BUILDBOX_TOKEN`
- `AVIARY_SOURCE_TOKEN`: read-only access to the private Aviary repository

Jobs run on separate runners:

| Job | Hawk token | Role |
|-----|------------|------|
| `prepare` | yes | Load spec, verify hash, report `running` |
| `compile` | no | Checkout Aviary at `commitSha`, build `unsigned_release` outputs |
| `sign` | no | Isolated signing step (`sign-android`; production keys wired in phase B) |
| `finalize` | yes | Refresh upload URLs, upload to OSS, report `succeeded` / `failed` |

The compile job never receives `HAWK_BUILDBOX_TOKEN` or signing material.
Unsigned artifacts are passed to `sign` via workflow artifacts only.

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

- `sign-android` uses a stub when signing secrets are not configured; this is not
  production signing.
- Public repo workflow artifacts may expose unsigned builds; treat as a known
  visibility constraint until private runners or OIDC-scoped fetch is available.
