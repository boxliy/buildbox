# Private executor deployment contract

`boxliy/buildbox` is public code hosting, not an authorized product execution
repository. All reusable jobs and the caller reject public execution. Do not
remove these guards. No private executor has been provisioned by this change.
An operator must designate an authorized **private** repository before packaging
can become ready. This task does not create repositories, change visibility,
install secrets, or execute a product build.

## Configuration owner and activation order

The platform/GitHub operator owns these prerequisites:

1. In an authorized private repository, install `.github/workflows/build.yml`
   from this delivery without changing its immutable reusable/script pins. Keep
   the workflow filename and `run-name` contract. Do not copy product secrets to
   the public repository. The caller must exist on its default branch for
   `workflow_dispatch` and the selected branch must resolve to the approved SHA.
2. Configure the private caller's existing `HAWK_BASE_URL`,
   `HAWK_OIDC_AUDIENCE`, and `AVIARY_SOURCE_APP_PRIVATE_KEY` secret references;
   variables `AVIARY_SOURCE_APP_ID` and `AVIARY_SOURCE_REPOSITORY` must identify
   the authorized source read application and exact `boxliy/aviary` source.
   The source application needs contents:read only on the frozen source and its
   authorized private submodules. Use the existing secret-management process.
   These values are not supplied or installed by this delivery.
3. In Hawk configure `HAWK_BUILDBOX_REPOSITORY`, workflow, ref, numeric repository ID, approved **private caller**
   commit SHA and the existing minimum Actions dispatch credential. Configure
   `HAWK_BUILDBOX_OIDC_TRUST_JSON` with the private caller's numeric owner/repo IDs,
   exact repository, `.github/workflows/build.yml`, branch ref and caller SHA;
   set `workflowRepository` to `boxliy/buildbox`, and set each reusable workflow
   SHA to the exact pin in the caller. Keep the existing audience and stage-secret
   configuration. Never use a public caller's identity as a substitute.
4. Apply the additive Hawk dispatch-proof migration through the normal migration
   pipeline and release matching platform/workflow code. Readiness requires
   authenticated GitHub metadata confirming the exact repository is private.
   Missing/mismatched trust disables dispatch; missing access, public metadata or
   a repository mismatch produce blocked reasons before a new batch is prepared.
   Missing private topology is an environment prerequisite, not successful delivery.
5. Authorize a real test App, signing materials, OSS profile and devices separately.
   Those business checks remain deferred. Offline/fake-service tests do not prove
   Actions signing, OSS delivery, installation or upgrade acceptance.

The exact Hawk environment names and approved pin values are documented in
Aviary's `openwiki/development/buildbox-private-executor.md`. Deploy both halves
together. A caller/script/reusable change requires updating the corresponding
approved SHA, not relaxing OIDC trust or switching to a mutable pin.

## Data flow and access boundaries

| Hop | Writer / reader | Authorization and object scope | Lifetime / retention |
| --- | --- | --- | --- |
| Frozen source tar | Trusted prepare / compile | Source GitHub App token is repository read-only and revoked by its action; tar is a private caller Actions artifact `source-<github.run_id>`, downloaded only from the current run | Artifact retention 1 day; source credential at most GitHub App token lifetime and post-job revocation |
| Compile inputs | Trusted prepare / compile | `export-job-inputs compile` allowlists fixed Spec inputs; private artifact `compile-input-<github.run_id>`; no stage token, signing material or upload grant | 1 day |
| Sign inputs | Trusted prepare / sign and finalize | Allowlisted immutable inputs in private `sign-input-<github.run_id>`; no capability URL or bearer | 1 day |
| Unsigned product | Compile / isolated sign | Private `unsigned-output-<github.run_id>`; signer validates archive, frozen package/version, actual certificate and declared capabilities | 1 day |
| Signed product | Isolated sign / finalize | Private `signed-output-<github.run_id>`; signing material remains only in signer temporary files, never artifacts | 1 day |
| Final object | Finalize / Hawk verifier / authenticated user | Existing attempt+target-specific OSS upload grant; Hawk validates actual size/SHA, current attempt and signing proof before authorized download | Existing storage retention policy; grants short-lived, cancellation/revocation and attempt gates preserved |

Private Actions artifacts use GitHub's repository/run authorization, **not** an
invented per-object OSS capability. Authorized repository readers can read retained
artifacts; repository membership must therefore be restricted to the authorized
product-build audience. Each transfer uses a fixed artifact name and the current
run only (no external repository/run override), with immutable v4 artifacts.
An expired/deleted artifact fails restore; a rerun is rejected by Hawk OIDC
`run_attempt == 1`. No public Actions artifact or public download URL is used.
Compile has contents:read only, no OIDC write permission, platform bearer,
source credential or signing material. It never receives a stage credential.

## Dispatch correlation and recovery

Hawk commits a random 256-bit proof hash and a 15-minute deadline before the
single dispatch POST. The raw proof is a workflow input in the private caller,
never a run title, output, artifact or platform log. The trusted exchange script
reads the event file as data and masks the value before any later log use.
First binding requires both this proof and fully verified GitHub OIDC identity;
the proof is consumed in the same locked transaction as the unique run binding.
Subsequent stage exchanges refresh only that exact signed run/attempt identity.

A GitHub 204 is acceptance, not an external run receipt. Unknown network results
are never blindly redispatched. Reconcile cannot claim a run by title or platform
ID: it waits for proof-backed OIDC binding, then polls the bound run. If no proof
arrives before its deadline, the attempt fails with `DISPATCH_NOT_OBSERVED`; an
explicit retry creates a new attempt/proof. Old callbacks and proofs cannot
claim a new attempt. A crash between the commit and POST can therefore produce
a failed attempt, never a second ambiguous dispatch.


## AVIARY-91 integration pins

The example caller pins prepare/sign/finalize to
`ea5a3b9c3cc48071a660b8ea0f7e06612d9d427c`; those workflows and compile check out
scripts at `6eefd9071b6cbf2a20c761eeb98d959880dcd3a6`. The independent material
validator's existing approval/pin contract is unchanged. These public reusable
SHAs are not an approved private caller SHA. The private caller's operator must
record its resulting exact commit in Hawk before authorized product execution.
No real product workflow is dispatched as part of fixture acceptance.
