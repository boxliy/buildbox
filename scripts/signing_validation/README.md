# Signing material validation v1

Offline validator for one authorized Android keystore, Apple certificate, or
Apple provisioning profile. It does not compile an app, sign a product, or
accept a compile/sign stage token.

The JSON shape matches the Hawk material envelope from AVIARY-88:

- `GET /api/v1/buildbox/validations/{id}/material`
- `POST /api/v1/buildbox/validations/{id}/result`

## Request

JSON on stdin, or a mode-0600 file. `schemaVersion` must be `1`.
`evaluatedAt` is an explicit UTC instant (`...Z`); the process clock is not the
validity authority. `stage`, when present, must be `validate`.

```json
{
  "schemaVersion": 1,
  "validationId": "val-1",
  "tenantId": "tenant-1",
  "assetId": "asset-1",
  "versionId": "version-1",
  "kind": "android_keystore",
  "toolchainSha": "0123456789abcdef0123456789abcdef01234567",
  "evaluatedAt": "2026-06-01T00:00:00Z",
  "material": {
    "containerBase64": "<keystore bytes>",
    "password": "from-the-authorized-request",
    "keyPassword": "from-the-authorized-request"
  },
  "expected": {
    "purpose": "direct_distribution",
    "storeType": "PKCS12",
    "alias": "release"
  }
}
```

`kind` is `android_keystore`, `apple_certificate`, or `apple_profile`.
Certificate and profile are separate requests. Tests may pass `material.path`
instead of `containerBase64`. Passwords are read from the JSON object and
handed to tools through the environment, never through argv.

Android `expected.purpose` is `direct_distribution` or `play_upload`.
`play_upload` records upload-key metadata only. It does not claim Play
app-signing identity.

Apple `expected` may include `teamId`, `bundleId`, `distributionMethod`,
`certificateSha256`, and `entitlements`. A caller-supplied distribution never
overrides the derived one. Entitlement comparison checks values, not only the
`get-task-allow` flag.

## Result

Public JSON echoes `schemaVersion`, the validation identity, `kind`, and
`toolchainSha`, then adds `status`, `reasonCodes`, `validatedAt`, `metadata`,
and `evidence`.

Android `metadata.aliases[]` contains `alias`, `certificateSha256`,
`notBefore`, `expiresAt`, `algorithm`, `signingCapable`, and `purpose`.
Apple certificate metadata contains `teamId`, `certificateSha256`,
`notBefore`, and `expiresAt`. Profile metadata contains `uuid`, `teamId`,
`applicationIdentifier`, `distributionMethod`, `certificateSha256s`,
`entitlements`, and `expiresAt`.

`status` is `valid` only when this toolchain actually ran the trust checks and
no reason other than `ok` remains. On this Linux host those checks are
`security_cms_anchor_verify`, `keychain_import`, and `codesign_identity_check`.
They stay in `evidence.notExecuted`, and the result is `invalid` with
`macos_capability_unavailable`. OpenSSL `cms -verify -noverify` only parses a
profile. `installable` and `trustedByPlatform` stay false. `signingCapable`
reports the synthetic challenge only.

Passwords, private keys, PKCS#12 bytes, profiles, tokens, and URLs are rejected
if they appear in the result. Tool stderr is discarded and is not copied into
the JSON.

## Reason codes

`ok`, `scope_mismatch`, `unsupported_input`, `malformed_material`,
`unknown_format`, `size_limit`, `path_rejected`, `wrong_password`,
`wrong_key_password`, `private_key_mismatch`, `alias_not_found`,
`ambiguous_alias`, `unsupported_algorithm`, `certificate_not_yet_valid`,
`certificate_expired`, `chain_invalid`, `cms_invalid`, `profile_tampered`,
`team_mismatch`, `bundle_mismatch`, `certificate_mismatch`,
`entitlements_mismatch`, `distribution_mismatch`, `profile_not_yet_valid`,
`profile_expired`, `macos_capability_unavailable`, `tool_failed`,
`idempotent_terminal_failure`.

A failure exits 2 and still prints one terminal JSON object, including the
validation identity when the request supplied it. The validator does not retry
or upload.

## Workflow boundary

`validate-material.yml` is the private caller. Its only inputs are
`validation_id`, `dispatch_proof`, and `hawk_base_url`. It calls
`validate-signing-material.yml` with `validator_sha` set to the commit that
contains this validator.

The reusable job refuses `pull_request` and public repositories. It checks out
`validator_sha` with `actions/checkout` v4.2.2
(`11bd71901bbe5b1630ceea73d27597364c9af683`) and Python setup v5.6.0
(`a26af69be951a213d495a4c3e4e4022e16d87065`). `scripts/signing_validation/exchange-validation`
calls `POST /api/v1/buildbox/validations/{id}/auth/exchange`.
`scripts/signing_validation/validate-material` reads the envelope and posts the
public result. The dispatch proof is read from `GITHUB_EVENT_PATH` and is not
interpolated into the workflow.
The job does not sign an application.

Hawk still owns the API, SQL, and generated client. This repository does not
guess a URL beyond the paths Rowan published on AVIARY-89.
