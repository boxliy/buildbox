# Aviary buildbox

Buildbox executes immutable Build Spec v1 attempts dispatched by Hawk. The only
workflow input is `build_run_id`. A GitHub success alone never authorizes a download.

## Execution and trust

The caller workflow pins prepare, sign and finalize reusable workflows to full
commit SHAs. Each reusable workflow checks out its own trusted script SHA. Update
Hawk's approved caller and reusable workflow SHA allowlists before dispatching a
new revision. GitHub's repository and owner **numeric IDs**, workflow path, ref,
approved SHA, dispatch event, run ID and first run attempt must all match.
Direct GitHub reruns cannot claim a fresh attempt; retry from Release instead.

| Stage | Authority | Work |
| --- | --- | --- |
| prepare | OIDC → short prepare credential | Read the frozen Spec; obtain exact source with a repository-scoped GitHub App token |
| compile | No OIDC, Hawk, storage or signing credential | Validate inputs, generate Swan assets, compile unsigned APK/AAB or device app |
| sign | OIDC → short sign credential | Retrieve the fixed signing version; verify identity/version; sign and attest exact bytes |
| finalize | OIDC → short finalize credential | Request target-specific PUT authorization, upload, report receipt |

Runners and workspaces are separate; compile caches are not shared with signing.
Source checkout uses `persist-credentials: false`. No application-provided script
runs in the signing job. Credentials, keystores, profiles and presigned URLs are
never job artifacts. Prepare refuses **public repository artifact transport** before
source retrieval. This repository's public visibility therefore requires an
approved private execution/transport configuration before real builds can run;
private runners alone do not make public Actions artifacts private.

Required operator configuration (do not add secret values to this repository):

- Secrets `HAWK_BASE_URL`, `HAWK_OIDC_AUDIENCE`.
- Variable `AVIARY_SOURCE_REPOSITORY`, variable `AVIARY_SOURCE_APP_ID`, secret
  `AVIARY_SOURCE_APP_PRIVATE_KEY`: a GitHub App restricted to read-only contents
  of the approved source repository and any explicitly authorized dependencies.
- Hawk dispatch credentials, numeric repository identity and approved workflow
  SHA configuration; OIDC stage signing secret and fixed GitHub issuer/JWKS trust.
- App packaging inputs, an active fixed signing version and published storage
  binding in Hawk. Missing configuration fails closed.

## Immutable inputs

Targets are exactly `apk`, `aab`, `ipa`; aliases are rejected. Android supports APK
and AAB together; iOS supports IPA only. The hash is the shared v1 canonical JSON
SHA-256 of `config`, excluding `artifactPrefix`. Duplicate keys, floating point
numbers in the outer Spec, unknown schema versions and noncanonical targets fail.
The Rust/script identity vector is `tests/fixtures/build_spec_v1_identity.json`.
Release payloads are canonical JSON strings inside the Spec to preserve their
signed bytes, including UI numeric values.

The Swan adapter validates exact source SHA, `.fvmrc`, lockfile, resource digests,
App/tenant scope and signed bundled Release before writing generated assets.
Compile enforces the Flutter version and workspace lockfile. Brand inputs require
`icon.png` (square PNG, at least 1024 pixels) and `launch.png`, with fixed digests
and an App background color. The adapter installs signed App-scoped manifest,
theme and FTL resources; the branding tool generates native icons/launch images.
Android permissions and iOS usage descriptions derive from the fixed capabilities;
unsupported capabilities fail rather than silently using default Swan branding.

## Material validation

`scripts/signing_validation` checks one authorized keystore, Apple certificate,
or provisioning profile. It does not compile or sign an app. The offline
contract is `signing-material-validation/v1`. The controlled job translates
Hawk schema version 1. Android `status: valid` requires the private-key
challenge. Apple `status: valid` also requires chain trust that actually ran,
and a profile requires a CMS signature check. Finding macOS tools does not
count as running them. A Linux parse is not Apple trust.
See `scripts/signing_validation/README.md`.

## Signing and artifacts

APK uses `zipalign` and `apksigner`, verifies certificate, package and version.
AAB uses the checksum-pinned bundletool to inspect identity, then JAR signing and
strict verification. An upload key is not a claim of Play app-signing identity or
store readiness. iOS requires the frozen Xcode build on macOS, a device product,
matching team/bundle/certificate/profile and unexpired development, ad-hoc,
enterprise or App Store provisioning. Distribution is derived from the verified
profile flags, not a caller label. App Store output is for the store distribution
path, not arbitrary device installation. Wildcard profiles are rejected. Every
nested app/extension requires its own frozen identity/profile/entitlement mapping. Sign runs codesign on native code and packages the IPA without
running source build phases. Entitlements are restricted to frozen capabilities,
not copied wholesale from the provisioning profile. No store upload is performed.

The sign stage records proof bound to attempt, target, signing version, certificate,
size and SHA-256. Finalize cannot invent that proof. Hawk creates the upload key
and independently copies/hashes the object under a lease-specific protected key.
Only verified, still-authorized artifacts receive an authenticated download URL.
Signing revocation/cancellation prevents new signing, uploads and downloads.

Finalize exchanges its credential before restoring artifacts, so prepare failure,
cancellation and missing output can still report failure. A terminal finalize
refresh permits identical receipts only, not another upload. Hard cancellation
can prevent `always()` execution; Hawk's leased reconciliation handles lost
callbacks and external run outcomes. Successful Actions without trusted artifacts
never become downloadable.

## Signing material validation

`scripts/signing_validation/` validates one authorized Android keystore or Apple
certificate/profile. It does not compile or sign an app. The JSON contract is
`signing-material-validation/v1`; see `scripts/signing_validation/README.md`.
`validate-signing-material.yml` accepts only a platform `validation_id` on a
private repository. The material fetch uses Hawk's authorized validation API. OpenSSL CMS decode is not Apple trust. macOS
`security`/`codesign` checks stay in Apple `evidence.notExecuted` until they
run. A proven Android private-key challenge does not carry those checks.

## Checks and acceptance limits

```sh
bash tests/contract.sh
python3 -m unittest discover -s tests -p 'test_*.py'
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.7 -shellcheck= -pyflakes= .github/workflows/{build,prepare,sign,finalize}.yml
```

Contract tests use isolated HTTP/tool fixtures. Python tests cover real JAR
signature verification, archive rejection, iOS policy, canonical hashes and
cross-job failure/cancellation branches. They do not prove an Android SDK or
macOS signing run. Real Actions execution, signing material, storage, devices,
installation and upgrade acceptance are deferred until business configuration
is supplied. Unsigned, fixture and simulator results are not signed delivery.


### Frozen tenant signing integration (Spec v1)

Hawk freezes tenant asset/version IDs, alias, purpose and certificate fingerprint,
plus each iOS component's profile version/UUID and minimal requested entitlements.
The sign stage receives only the current run/attempt/platform's exact material
versions. Child components do not inherit all host or profile privileges.
`configure_ios.py` applies fixed bundle/team/name/version and no-sign settings to
Runner and the source-approved `iosComponentTargets` before credential-free device
archive compilation. Sign executes no application scripts. Frameworks/dylibs and
child apps are signed inside out and individually verified before the host.

The proof includes the exact component manifest. Missing, extra or changed
components cannot authorize upload. Hawk binds each target's size/hash proof to
its exact presigned PUT and independently verifies stored bytes before download.
Execution success alone never grants download. Revocation blocks future material,
upload, retry and download authorization; already issued plaintext or presigned
URLs cannot be remotely erased and remain bounded by their original lifetime.

`spec_identity.py` validates current-v1 semantics before computing the canonical
hash. The shared vector in `tests/fixtures/build_spec_v1_identity.json` is also
owned by Hawk. Inline `brandResources` are immutable nonsecret PNG snapshots,
with resource ID/revision, bytes and SHA-256. They are materialized only at their
fixed brand paths before the Swan adapter verifies frozen resource digests.

Linux fixture checks cover policy, transport and signing orchestration; they do
not establish real Apple trust, macOS archive/export, device installation,
upgrade continuity, TestFlight or store acceptance. No test submits to a store.
