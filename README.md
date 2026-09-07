# buildbox

Buildbox contains the GitHub Actions runner contract for immutable Hawk build
specs. The first supported target is Swan Android artifacts.

## Android workflow

Run `.github/workflows/build.yml` manually with one input:

- `build_spec_id`: immutable Hawk build spec id

No repository, commit, upload URL, token, or business configuration is accepted
as workflow input. Runtime authority comes from these repository secrets:

- `HAWK_BASE_URL`
- `HAWK_BUILDBOX_TOKEN`

The workflow:

1. Loads the immutable build spec from
   `GET /api/v1/buildbox/build-specs/{id}`.
2. Checks out `sourceRepo` at `commitSha` into `aviary-source`.
3. Verifies `HEAD` exactly matches `commitSha`.
4. Builds each requested target from `waterfowl/apps/swan`.
5. Computes SHA-256 and byte size for each artifact.
6. Uploads each artifact with its matching presigned `PUT` URL and headers.
7. Posts a running callback followed by a success or failure callback to
   `POST /api/v1/buildbox/runs/{runId}/callback`.

## Hawk response contract

`scripts/load-build-spec` requires the response to expose these fields:

- `sourceRepo`: GitHub `owner/repo`, `https://github.com/owner/repo.git`, or
  `git@github.com:owner/repo.git`
- `commitSha`: full 40-character commit SHA
- `targets`: 1-2 unique values from `android_apk` and `android_aab`
- `runId`
- `config`: immutable build input object
- `specHash`: SHA-256 of the canonical JSON `config`; the loader verifies it
- `uploads`: an array with an entry matching the target
- `uploads[].url`: presigned `PUT` URL
- `uploads[].contentType`: artifact content type
- `uploads[].headers`: presigned upload headers as an object

Optional config fields:

- `config.dartDefines` as an object
- `config.swanConfig` as an object

`dartDefines` entries are passed to every Flutter build as
`--dart-define=KEY=VALUE`.
`swanConfig`, when present, is passed as a compact JSON value through
`--dart-define=SWAN_CONFIG_JSON=...`.

Success callbacks send:

- `status: "succeeded"`
- `githubRunId`
- `artifacts[]` with `target`, `fileName`, `contentType`, `byteSize`,
  `sha256`, and `objectKey`

Before compiling, the workflow sends `status: "running"`, `githubRunId`, and an
empty `artifacts` array.

Failure callbacks send:

- `status: "failed"`
- `githubRunId`
- `artifacts: []`
- `errorCode: "BUILD_FAILED"`
- `errorMessage`

## Local contract tests

The tests use fixtures and mock commands only; they do not call Hawk, Flutter, or
OSS.

```sh
tests/contract.sh
```
