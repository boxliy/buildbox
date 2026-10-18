"""Isolated signing-material validation. Not a product signer."""

from .contract import SCHEMA_VERSION, VALIDATOR_VERSION
from .validate import validate_document

__all__ = ["SCHEMA_VERSION", "VALIDATOR_VERSION", "validate_document"]
