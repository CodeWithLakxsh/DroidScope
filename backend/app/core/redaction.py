"""Secret redaction helpers.

Evidence captured by the secret detector may contain live credentials.  The
database stores both a masked preview and a salted fingerprint; the raw value is
only retained when ``store_raw`` is explicitly enabled for a deployment.
"""

from __future__ import annotations

import hashlib
import re

_MASK = "•"

# Patterns applied to free-form text (log lines, runtime events, report prose).
_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)\b(AIza[0-9A-Za-z_\-]{35})\b"), "google-api-key"),
    (re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b"), "github-token"),
    (re.compile(r"\b(sk-[A-Za-z0-9]{20,})\b"), "generic-sk-token"),
    (re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), "aws-access-key-id"),
    (re.compile(r"\b(xox[baprs]-[0-9A-Za-z\-]{10,})\b"), "slack-token"),
    (
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        "private-key-block",
    ),
    (
        re.compile(r"(?i)\b(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,})\b"),
        "jwt",
    ),
)


def mask_value(value: str, *, keep_prefix: int = 4, keep_suffix: int = 2) -> str:
    """Return a masked preview of a sensitive value.

    Short values are fully masked because a prefix/suffix of a short secret can
    leak most of its entropy.
    """
    if not value:
        return ""
    if len(value) <= keep_prefix + keep_suffix + 4:
        return _MASK * min(len(value), 12)
    body = max(len(value) - keep_prefix - keep_suffix, 4)
    return f"{value[:keep_prefix]}{_MASK * min(body, 16)}{value[-keep_suffix:]}"


def fingerprint_value(value: str, *, salt: str = "droidscope-evidence") -> str:
    """Stable, non-reversible identity for a secret value.

    Used to correlate the same secret across scans and APK versions without
    persisting the plaintext.
    """
    digest = hashlib.sha256(f"{salt}:{value}".encode())
    return digest.hexdigest()[:32]


def redact_text(text: str) -> str:
    """Replace recognised credential shapes inside free-form text."""
    if not text:
        return text
    result = text
    for pattern, label in _PATTERNS:
        result = pattern.sub(lambda m, _label=label: f"[redacted:{_label}]", result)
    return result
