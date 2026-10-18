"""Offline signing-material validation contract.

Hawk (AVIARY-88) accepted this offline shape. The controlled job translates
it to and from the Hawk HTTP envelope. Passwords and private material never
appear in the result object. This module does not fetch credentials, compile
an app, or sign a product.
"""

CONTRACT_VERSION = "signing-material-validation/v1"
VALIDATOR_VERSION = "1.1.0"

MAX_MATERIAL_BYTES = 2 * 1024 * 1024
MAX_PASSWORD_BYTES = 256
MAX_ALIASES = 32
MAX_CHAIN = 8
MAX_DEVICES = 200
MAX_PLIST_BYTES = 256 * 1024
MAX_ZIP_ENTRIES = 64
MAX_EXPANDED_BYTES = 4 * 1024 * 1024
TOOL_TIMEOUT_SECONDS = 20

PLATFORMS = ("android", "ios")
ANDROID_PURPOSES = ("direct_distribution", "play_upload")
ANDROID_FORMATS = ("JKS", "PKCS12")
APPLE_KINDS = ("certificate", "provisioning_profile")
APPLE_DISTRIBUTIONS = ("development", "ad_hoc", "enterprise", "app_store")
PUBLIC_KEY_ALGORITHMS = ("RSA", "EC")

# Stable machine codes. Messages stay generic so tool stderr never leaks.
REASON_OK = "ok"
REASON_SCOPE_MISMATCH = "scope_mismatch"
REASON_UNSUPPORTED_INPUT = "unsupported_input"
REASON_MALFORMED_MATERIAL = "malformed_material"
REASON_UNKNOWN_FORMAT = "unknown_format"
REASON_SIZE_LIMIT = "size_limit"
REASON_PATH_REJECTED = "path_rejected"
REASON_WRONG_PASSWORD = "wrong_password"
REASON_WRONG_KEY_PASSWORD = "wrong_key_password"
REASON_PRIVATE_KEY_MISMATCH = "private_key_mismatch"
REASON_ALIAS_NOT_FOUND = "alias_not_found"
REASON_AMBIGUOUS_ALIAS = "ambiguous_alias"
REASON_UNSUPPORTED_ALGORITHM = "unsupported_algorithm"
REASON_CERTIFICATE_NOT_YET_VALID = "certificate_not_yet_valid"
REASON_CERTIFICATE_EXPIRED = "certificate_expired"
REASON_CHAIN_INVALID = "chain_invalid"
REASON_CMS_INVALID = "cms_invalid"
REASON_PROFILE_TAMPERED = "profile_tampered"
REASON_TEAM_MISMATCH = "team_mismatch"
REASON_BUNDLE_MISMATCH = "bundle_mismatch"
REASON_CERTIFICATE_MISMATCH = "certificate_mismatch"
REASON_ENTITLEMENTS_MISMATCH = "entitlements_mismatch"
REASON_DISTRIBUTION_MISMATCH = "distribution_mismatch"
REASON_PROFILE_NOT_YET_VALID = "profile_not_yet_valid"
REASON_PROFILE_EXPIRED = "profile_expired"
REASON_MACOS_REQUIRED = "macos_capability_unavailable"
REASON_TOOL_FAILED = "tool_failed"
REASON_IDEMPOTENT_FAILURE = "idempotent_terminal_failure"

# Material validation never grants compile, sign, publish, or asset management.
STAGE = "validate"

# Trust checks this Linux parser does not perform. Their presence forbids status=valid.
TRUST_CHECKS = (
    "security_cms_anchor_verify",
    "keychain_import",
    "codesign_identity_check",
)

# Result document keys that may carry secret-shaped values. Tests scan output.
FORBIDDEN_RESULT_KEYS = frozenset({
    "password", "storePassword", "keyPassword", "privateKey", "privateKeyPem",
    "keystore", "container", "containerBase64", "material", "pkcs12",
    "provisioningProfile", "profileBytes", "signedUrl", "presignedUrl",
    "authorization", "token", "secret",
})
