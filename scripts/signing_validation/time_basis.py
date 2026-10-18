"""Fixed evaluation time. Validity is never taken from the process clock alone."""

import datetime
from zoneinfo import ZoneInfo

from .outcome import ValidationFailure
from .contract import REASON_MALFORMED_MATERIAL


UTC = datetime.timezone.utc
TAIPEI = ZoneInfo("Asia/Taipei")


def parse_instant(value):
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValidationFailure(REASON_MALFORMED_MATERIAL, "evaluatedAt must be an explicit UTC instant")
    try:
        parsed = datetime.datetime.fromisoformat(value[:-1]).replace(tzinfo=UTC)
    except ValueError as error:
        raise ValidationFailure(REASON_MALFORMED_MATERIAL, "evaluatedAt is not a timestamp") from error
    if parsed.year < 2000 or parsed.year > 2100:
        raise ValidationFailure(REASON_MALFORMED_MATERIAL, "evaluatedAt is outside the supported range")
    return parsed


def as_utc(value):
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def instant(value):
    return as_utc(value).strftime("%Y-%m-%dT%H:%M:%SZ")


def taipei_date(value):
    return as_utc(value).astimezone(TAIPEI).date().isoformat()


def validity(not_before, not_after, evaluated_at, early_code, late_code):
    start, end, now = as_utc(not_before), as_utc(not_after), as_utc(evaluated_at)
    if now < start:
        return early_code
    if now >= end:
        return late_code
    return None
