# Signing material validation v1

Offline validator for one authorized Android keystore, Apple certificate, or
Apple provisioning profile. It does not compile an app, sign a product, or
accept a compile/sign stage token.

The offline contract is `signing-material-validation/v1`. Hawk's HTTP envelope
(`schemaVersion: 1`, top-level identity, `toolchainSha`, `material.containerBase64`)
is translated by `scripts/signing_validation/validate-material`. The offline
result is not posted as a Hawk result.

## Request

JSON on stdin. `contract` must be `signing-material-validation/v1`.
`evaluatedAt` is an explicit UTC instant (`...Z`); the process clock is not the
validity authority. `scope.stage` must be `validate`.

```json
{
  "contract": "signing-material-validation/v1",
  "evaluatedAt": "2026-06-01T00:00:00Z",
  "platform": "android",
  "purpose": "direct_distribution",
  "storeType": "PKCS12",
  "scope": {
    "validationId": "val-1",
    "tenantId": "tenant-1",
    "assetId": "asset-1",
    "versionId": "version-1",
    "kind": "android_keystore",
    "stage": "validate"
  },
  "material": {
    "path": "/controlled/keystore.p12",
    "storePassword": "from-the-authorized-request",
    "keyPassword": "from-the-authorized-request",
    "alias": "release"
  }
}
```

Apple uses `platform: ios` and `kind: certificate` or `provisioning_profile`.
The scope kind is `apple_certificate` or `apple_profile`. Certificate and
profile are separate requests. Passwords are read from the JSON object and
handed to tools through the environment, never through argv. Tests may pass
`material.bytesBase64` instead of `material.path`.

Android `purpose` is `direct_distribution` or `play_upload`. `play_upload`
records upload-key metadata only. It does not claim Play app-signing identity.
Each alias reports `purpose: signing`, which is the material capability. The
App distribution choice stays on the request `purpose`.

Apple `expectations` may include `teamId`, `bundleId`, `distribution`,
`certificateSha256`, and `entitlements`. A caller-supplied distribution never
overrides the derived one. Entitlement comparison checks values.

## Result

Public JSON keeps `contract`, `scope` (including `validationId`), `status`,
`reasonCodes`, `evaluatedAt`, and `evidence`.

Android `aliases[]` contains `alias`, `certificateSha256`, `notBefore`,
`expiresAt`, `algorithm`, `signingCapable`, and `purpose`. Apple certificate
metadata contains `teamId`, `certificateSha256`, `notBefore`, and `expiresAt`.
Profile metadata contains `uuid`, `teamId`, `applicationIdentifier`,
`distribution`, `developerCertificateSha256`, `entitlements`, and `expiresAt`.
`evidence` reports `privateKeyProven`, `chainTrusted`, and
`cmsSignatureVerified`. The adapter maps those facts into the Hawk result
without inventing missing chain or entitlement values.

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
calls `POST /api/v1/buildbox/validations/{id}/auth/exchange` with
`{oidcToken, dispatchProof}`. The dispatch proof is read from
`GITHUB_EVENT_PATH` and is not interpolated into the workflow.
`scripts/signing_validation/validate-material` reads `GET /material`, writes
the offline request, and posts the translated public body to `POST /result`.
The job does not sign an application.

Hawk still owns the API, SQL, and generated client. This repository does not
guess a URL beyond the paths Rowan published on AVIARY-89.
