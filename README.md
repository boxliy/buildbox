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
- `HAWK_OIDC_AUDIENCE`: audience Hawk expects on the Actions OIDC token
- `AVIARY_SOURCE_TOKEN`: read-only access to the private Aviary repository

Prepare and finalize exchange a short-lived stage credential with
`POST /api/v1/buildbox/auth/exchange`. The shared `HAWK_BUILDBOX_TOKEN` is not
a substitute and is not sent. Compile and sign have no platform credential.

Jobs run on separate runners:

| Job | Platform credential | Role |
|-----|--------------------|------|
| `prepare` | prepare stage | Exchange OIDC, load spec without uploads, reject a public repository |
| `compile` | none | Checkout Aviary at `commitSha`, build `unsigned_release` outputs |
| `sign` | none | Isolated signing step; fails closed without a real signer |
| `finalize` | finalize stage | Report `running` after prepare, then upload or report one terminal status |

The compile job never receives `HAWK_BUILDBOX_TOKEN`, signing material, the
Hawk response body, or presigned upload URLs. `prepare` exports a compile
slice (`spec` without `uploads`, targets, dart defines, swan config) and a
sign slice (run id, spec hash, targets). Unsigned artifacts move to `sign`
as their own artifact. `build-android` rejects debug-signed and already-signed
zip outputs. `sign-android` rejects those same states and exits non-zero when
signing material is absent or when no production signer is implemented.
Phase A does not copy unsigned bytes forward or report `succeeded`.
A missing keystore is a failed build. The workflow does not fall back to
debug signing or publish the unsigned APK as a downloadable artifact.

## Spec v1 targets and object keys

Canonical Hawk target names are `apk`, `aab`, and `ipa`. `load-build-spec`
canonicalizes legacy `android_apk` / `android_aab` in API responses when
present. Object keys use `{artifactPrefix}{target}.{ext}` (for example
`builds/.../apk.apk`, `builds/.../aab.aab`).

`specHash` is `sha256:` + hex(SHA-256(JCS-sorted compact JSON of `config`)).
The loader recomputes and rejects mismatches.

## Hawk response contract

`scripts/load-build-spec` requires:

- `sourceRepo`, `commitSha`, `targets`, `runId`, `config`, `specHash`, `artifactPrefix`
- `config.androidApplicationId`, `config.appDisplayName`

The prepare response has no `uploads`. Finalize requests each target with
`POST /api/v1/buildbox/runs/{runId}/artifact-uploads` after signing.

Optional: `config.dartDefines`, `config.swanConfig`.

Callbacks: `POST /api/v1/buildbox/runs/{runId}/callback` with the finalize
stage credential, `status`, `githubRunId`, and `artifacts[]` on success.
Prepare does not callback. Finalize exchanges its credential before restoring
any artifact. Prepare failure, including the public-repository refusal, and
compile or sign cancellation each send one `failed` callback. That path does
not read a job artifact. After a successful prepare that was not cancelled,
finalize reports `running`, then `succeeded` or `failed`. A prepare credential
is rejected. Hawk has no `cancelled` status, so cancellation is `failed`.

## OIDC and short-lived credentials

Prepare and finalize call `scripts/exchange-stage` before any Hawk read or
callback. Exchange sends `runId` as a decimal string and writes the stage
credential only to `GITHUB_ENV`. The workflow grants `id-token: write` only
on those two jobs.
Reusable workflow SHA pinning for the sign job remains unimplemented. A
missing signing key still fails closed and is not a signed delivery.

## Local contract tests

Fixtures and mock `curl` / `flutter` / `git` only:

```sh
tests/contract.sh
```

## Phase A limitations

- `sign-android` has no production signer. Missing material and a present
  material directory both fail. That failure is not a signed delivery.
- Compile and sign artifacts omit presigned URLs. `prepare` rejects a public
  repository before later jobs and publishes the reason as a job output.
  Finalize reports that failure, and a cancelled compile or sign, with a
  finalize credential. The failure callback does not restore an artifact.
  Prepare never sends the callback.
  Unsigned outputs are not published as Actions artifacts until a private
  runner is available.
- OIDC, reusable workflow SHA pins, and real keystore signing remain phase B.
