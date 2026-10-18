"""Offline signing-material validation contract.

Hawk (AVIARY-88) accepted this offline shape. The controlled job translates
it to and from the Hawk HTTP envelope. Passwords and private material never
appear in the result object. This module does not fetch credentials, compile
an app, or sign a product.
"""

CONTRACT_VERSION = "signing-material-validation/v1"
VALIDATOR_VERSION = "1.2.0"

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
ANDROID_FORMATS = ("JKS", "PKCS12")
APPLE_KINDS = ("certificate", "provisioning_profile")
# Offline names stay snake_case. Hawk distributionMethod uses hyphens.
APPLE_DISTRIBUTIONS = ("development", "ad_hoc", "enterprise", "app_store")
HAWK_DISTRIBUTIONS = {
    "development": "development",
    "ad_hoc": "ad-hoc",
    "enterprise": "enterprise",
    "app_store": "app-store",
}
PUBLIC_KEY_ALGORITHMS = ("RSA", "EC")

# Offline machine codes. Messages stay generic so tool stderr never leaks.
# Hawk's published allowlist is HAWK_REASON_CODES; the job translates.
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

# Published Hawk reason allowlist. A valid result uses an empty list.
HAWK_REASON_CODES = frozenset({
    "wrong_password",
    "invalid_material",
    "unsupported_format",
    "unsupported_algorithm",
    "expired",
    "not_yet_valid",
    "private_key_mismatch",
    "signature_invalid",
    "untrusted_chain",
    "scope_mismatch",
    "tool_unavailable",
    "resource_limit",
    "validation_failed",
    "macos_capability_unavailable",
    "path_rejected",
    "entitlement_mismatch",
})

# Offline codes that are not in the Hawk list. Unmapped codes fail closed.
HAWK_REASON_MAP = {
    "malformed_material": "invalid_material",
    "unknown_format": "unsupported_format",
    "size_limit": "resource_limit",
    "wrong_key_password": "wrong_password",
    "alias_not_found": "invalid_material",
    "ambiguous_alias": "invalid_material",
    "certificate_not_yet_valid": "not_yet_valid",
    "certificate_expired": "expired",
    "chain_invalid": "untrusted_chain",
    "cms_invalid": "signature_invalid",
    "profile_tampered": "signature_invalid",
    "team_mismatch": "scope_mismatch",
    "bundle_mismatch": "scope_mismatch",
    "certificate_mismatch": "scope_mismatch",
    "entitlements_mismatch": "entitlement_mismatch",
    "distribution_mismatch": "scope_mismatch",
    "profile_not_yet_valid": "not_yet_valid",
    "profile_expired": "expired",
    "tool_failed": "validation_failed",
    "unsupported_input": "invalid_material",
    "idempotent_terminal_failure": "validation_failed",
    "result_rejected": "validation_failed",
}

# Material validation never grants compile, sign, publish, or asset management.
STAGE = "validate"

# Apple trust checks this parser does not perform. They stay on Apple results
# until the commands run. They are not Android notExecuted entries.
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
