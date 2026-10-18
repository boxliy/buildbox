# Signing material validation v1

Offline validator for one authorized Android keystore or Apple certificate /
provisioning profile. It does not compile an app, sign a product, or accept a
compile/sign stage token.

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
profile are separate requests. Optional `expectations` (`teamId`, `bundleId`,
`distribution`, `certificateSha256`) are checked against derived facts. A
caller-supplied distribution never overrides the derived one.

Android `purpose` is `direct_distribution` or `play_upload`. `play_upload`
records upload-key metadata only. It does not claim Play app-signing identity.

## Result

Public JSON only: status, reason codes, selected alias, certificate SHA-256,
validity, algorithm, derived Apple distribution, tool versions, and evidence
flags. Passwords, private keys, PKCS#12 bytes, profiles, tokens, and URLs are
rejected if they appear in the result. `installable` and `trustedByPlatform`
stay false. OpenSSL CMS decode uses `-noverify` and is not Apple trust.

`evidence.notExecuted` lists macOS checks this host did not run:
`security_cms_anchor_verify`, `keychain_import`, `codesign_identity_check`.
Those belong to the pinned `validate-signing-material.yml` job.

## Reason codes

`ok`, `scope_mismatch`, `unsupported_input`, `malformed_material`,
`size_limit`, `path_rejected`, `wrong_password`, `wrong_key_password`,
`private_key_mismatch`, `alias_not_found`, `ambiguous_alias`,
`unsupported_algorithm`, `certificate_not_yet_valid`, `certificate_expired`,
`chain_invalid`, `cms_invalid`, `profile_tampered`, `team_mismatch`,
`bundle_mismatch`, `certificate_mismatch`, `entitlements_mismatch`,
`distribution_mismatch`, `profile_not_yet_valid`, `profile_expired`,
`macos_capability_unavailable`, `tool_failed`, `idempotent_terminal_failure`.

A failure exits 2 and still prints one terminal JSON object. The validator
does not retry or upload.

## Workflow boundary

`validate-signing-material.yml` is `workflow_call` plus `workflow_dispatch`
restricted to the repository owner. The only material input is
`validation_id`. The job refuses `pull_request`, public repositories, and any
stage other than `validate`. Hawk (AVIARY-88) owns the fetch/report API. Until
that contract is released, the workflow stops after the scope gate and does
not call a guessed endpoint.
