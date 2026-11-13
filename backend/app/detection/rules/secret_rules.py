"""Hardcoded secret detection.

Secret detection is where naive scanners generate the most noise, so this
detector refuses to report on a single signal.  A candidate must either match a
*provider-specific* pattern whose shape is unambiguous (an AWS access key id has
a fixed prefix and length), or combine several weaker signals: an identifier that
names a credential, sufficient Shannon entropy, a plausible character set, and
the absence of a known benign shape (a resource id, a class name, a hash, a
public constant).

Every reported value is masked.  The database keeps the mask plus a salted
fingerprint so the same secret can be correlated across scans without the
plaintext being persisted.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from app.core.enums import Confidence, FindingCategory, Severity
from app.detection.base import Rule, RuleMetadata
from app.detection.context import SourceContext, SourceFile
from app.detection.model import Evidence, RawFinding
from app.detection.registry import register

ENGINE = "secret-analyzer"

MASTG_SECRETS = "https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0013/"
MAX_FINDINGS = 80
MIN_GENERIC_LENGTH = 20
MIN_GENERIC_ENTROPY = 3.6


@dataclass(frozen=True, slots=True)
class ProviderPattern:
    """A credential shape specific enough to report on its own."""

    name: str
    pattern: re.Pattern[str]
    severity: Severity
    confidence: Confidence
    # Whether the matched value is a secret, or merely an identifier that is
    # designed to be public (e.g. a Firebase API key).
    is_sensitive: bool = True
    note: str | None = None
    group: int = 0


PROVIDER_PATTERNS: tuple[ProviderPattern, ...] = (
    ProviderPattern(
        "AWS access key id",
        re.compile(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"),
        Severity.critical,
        Confidence.high,
        note=(
            "An AWS access key id is paired with a secret access key; search the "
            "application for the matching secret and rotate both."
        ),
    ),
    ProviderPattern(
        "AWS secret access key",
        re.compile(
            r"(?i)aws(?:.{0,20})?(?:secret|private)(?:.{0,20})?[\"'\s:=]+([A-Za-z0-9/+=]{40})\b"
        ),
        Severity.critical,
        Confidence.high,
        group=1,
    ),
    ProviderPattern(
        "GitHub token",
        re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b"),
        Severity.critical,
        Confidence.high,
    ),
    ProviderPattern(
        "Slack token",
        re.compile(r"\b(xox[baprs]-[0-9A-Za-z\-]{10,})\b"),
        Severity.high,
        Confidence.high,
    ),
    ProviderPattern(
        "Stripe secret key",
        re.compile(r"\b((?:sk|rk)_(?:live|test)_[0-9A-Za-z]{10,})\b"),
        Severity.critical,
        Confidence.high,
        note="A Stripe live secret key permits charges and refunds on the account.",
    ),
    ProviderPattern(
        "Private key block",
        re.compile(
            r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----)"
        ),
        Severity.critical,
        Confidence.high,
        note="A private key embedded in the APK is available to every installation.",
    ),
    ProviderPattern(
        "Google OAuth client secret",
        re.compile(r"\b(GOCSPX-[A-Za-z0-9_\-]{20,})\b"),
        Severity.critical,
        Confidence.high,
    ),
    ProviderPattern(
        "Twilio API key",
        re.compile(r"\b(SK[0-9a-fA-F]{32})\b"),
        Severity.high,
        Confidence.medium,
    ),
    ProviderPattern(
        "SendGrid API key",
        re.compile(r"\b(SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,})\b"),
        Severity.critical,
        Confidence.high,
    ),
    ProviderPattern(
        "Mailgun API key",
        re.compile(r"\b(key-[0-9a-f]{32})\b"),
        Severity.high,
        Confidence.medium,
    ),
    ProviderPattern(
        "JSON Web Token",
        re.compile(
            r"\b(eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{5,})\b"
        ),
        Severity.medium,
        Confidence.medium,
        note=(
            "A JWT compiled into the application is a static credential. Check its "
            "claims and expiry: a long-lived service token is a serious exposure, "
            "while an expired example token is not."
        ),
    ),
    ProviderPattern(
        "Google API key",
        re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b"),
        Severity.low,
        Confidence.high,
        is_sensitive=False,
        note=(
            "A Google API key is a client identifier, not a secret: it is designed to "
            "ship inside client applications. It becomes a finding only when it is "
            "unrestricted, because an unrestricted key can be used by anyone against "
            "your quota and billing. Verify the key's application and API "
            "restrictions in the Google Cloud console."
        ),
    ),
    ProviderPattern(
        "Firebase Cloud Messaging legacy server key",
        re.compile(r"\b(AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140,})\b"),
        Severity.critical,
        Confidence.high,
        note=(
            "Unlike a Firebase client API key, an FCM server key authorises sending "
            "push notifications to every installation of the application."
        ),
    ),
)

# Identifier fragments that indicate the value is a credential.
#
# These are matched against a *normalised* identifier -- lowercased with "_"
# and "-" removed -- because a word boundary cannot sit between "_" and a
# letter, so r"\bsecret_key\b" never matches "API_SECRET_KEY", which is exactly
# how such constants are written in practice.
SECRET_NAME_FRAGMENTS: tuple[str, ...] = (
    "apikey", "secretkey", "clientsecret", "accesstoken", "authtoken",
    "refreshtoken", "bearertoken", "privatekey", "encryptionkey", "signingkey",
    "masterkey", "password", "passwd", "credential", "sessionsecret",
    "appsecret", "consumersecret", "webhooksecret", "sharedsecret", "apisecret",
    "authkey", "secrettoken", "accesskey", "clientkey", "apitoken",
)
# Identifier fragments that mean the constant describes a credential field
# rather than holding one (a label, a preferences key, an error message).
NON_SECRET_NAME_FRAGMENTS: tuple[str, ...] = (
    "hint", "label", "placeholder", "field", "error", "message", "title",
    "prompt", "regex", "pattern", "header", "paramname", "keyname", "prefkey",
    "extra", "action", "column", "tag", "format", "url", "endpoint", "path",
)


def normalise_identifier(name: str) -> str:
    return name.lower().replace("_", "").replace("-", "").replace(" ", "")


def identifier_names_secret(name: str) -> bool:
    normalised = normalise_identifier(name)
    if any(fragment in normalised for fragment in NON_SECRET_NAME_FRAGMENTS):
        return False
    return any(fragment in normalised for fragment in SECRET_NAME_FRAGMENTS)

# Assignment of a literal to an identifier.  Covers Java, Kotlin and smali.
ASSIGNMENT = re.compile(
    r"""(?P<name>[A-Za-z_][A-Za-z0-9_]{2,60})\s*(?::\s*String\s*)?[=:]\s*"(?P<value>[^"\n]{8,512})\"""",
)
# Smali constant loads: const-string v0, "value"
SMALI_CONST = re.compile(r'const-string(?:/jumbo)?\s+[vp]\d+,\s*"(?P<value>[^"\n]{8,512})"')

# Shapes that look random but carry no secret.
BENIGN_VALUE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^[a-f0-9]{32}$"),  # bare md5-shaped digest
    re.compile(r"^[a-f0-9]{40}$"),  # sha1-shaped digest
    re.compile(r"^[a-f0-9]{64}$"),  # sha256-shaped digest
    re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"),  # uuid
    re.compile(r"^(?:[A-Za-z]+\.){2,}[A-Za-z0-9_$]+$"),  # fully qualified class name
    re.compile(r"^(?:https?|content|file|android\.resource)://"),  # url
    re.compile(r"^[A-Za-z0-9_\-/]+\.(?:png|jpg|webp|xml|json|so|dex|ttf|otf|js|css|html)$"),
    re.compile(r"^#[0-9A-Fa-f]{3,8}$"),  # colour
    re.compile(r"^(?:[0-9]+[.,]?)+$"),  # numeric
    re.compile(r"^[A-Z][A-Z0-9_]{6,}$"),  # SCREAMING_CASE identifier
    re.compile(r"^(?:[A-Za-z]+[ _\-]){2,}[A-Za-z]+$"),  # human sentence
    re.compile(r"^L[a-zA-Z0-9/$_]+;$"),  # smali type descriptor
    re.compile(r"^\.?[A-Za-z0-9_]+(?:/[A-Za-z0-9_.$]+)+$"),  # smali path
    re.compile(r"(?i)^(?:true|false|null|none|undefined|changeme|your[_-]?key|xxx+|test|example|placeholder|dummy|sample|todo|fixme|lorem)"),
    re.compile(r"^[\x00-\x1f]+$"),
)

# Values containing format placeholders are templates, not secrets.
TEMPLATE_MARKERS = ("%s", "%d", "{0}", "{}", "${", "<", "@string/", "@+id/")

PLACEHOLDER_WORDS = (
    "your", "example", "sample", "placeholder", "dummy", "changeme", "insert",
    "replace", "xxxx", "aaaa", "0000", "1234", "test_key", "fake", "mock", "redacted",
)


def shannon_entropy(value: str) -> float:
    """Bits of entropy per character."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def character_classes(value: str) -> int:
    classes = 0
    if any(c.islower() for c in value):
        classes += 1
    if any(c.isupper() for c in value):
        classes += 1
    if any(c.isdigit() for c in value):
        classes += 1
    if any(not c.isalnum() for c in value):
        classes += 1
    return classes


def is_placeholder(value: str) -> bool:
    """Is the value an obvious stand-in rather than a credential?"""
    return any(word in value.strip().lower() for word in PLACEHOLDER_WORDS)


def looks_benign(value: str) -> bool:
    stripped = value.strip()
    if len(stripped) < 8:
        return True
    if is_placeholder(stripped):
        return True
    if any(marker in stripped for marker in TEMPLATE_MARKERS):
        return True
    if " " in stripped and len(stripped.split()) > 2:
        return True
    return any(pattern.match(stripped) for pattern in BENIGN_VALUE_PATTERNS)


class ProviderSecretRule(Rule):
    """Credentials whose format identifies the issuing service."""

    meta = RuleMetadata(
        id="DS-SECRET-001",
        name="Hardcoded credential for a known service",
        description=(
            "A string matching the documented format of a third-party service "
            "credential is embedded in the application."
        ),
        category=FindingCategory.secrets,
        severity=Severity.critical,
        confidence=Confidence.high,
        engine=ENGINE,
        impact=(
            "Any value compiled into an APK is readable by anyone who can install the "
            "application. A credential exposed this way can be used directly against "
            "the issuing service, with the privileges of whatever account it belongs "
            "to, and it cannot be revoked without shipping a new build."
        ),
        remediation=(
            "Treat the credential as compromised and rotate it now. Move the operation "
            "that requires it behind a server you control, so the client holds only a "
            "short-lived, user-scoped token. Where a key must ship in the client, "
            "restrict it by application signature, package name and API surface, and "
            "monitor its usage."
        ),
        cwe_ids=["CWE-798", "CWE-312"],
        masvs_controls=["MASVS-CRYPTO-2", "MASVS-CODE-4"],
        references=[
            MASTG_SECRETS,
            "https://cwe.mitre.org/data/definitions/798.html",
        ],
        verification=(
            "Authenticate against the issuing service with the extracted value in an "
            "authorised test. Do not use a credential you are not authorised to test."
        ),
        limitations=(
            "A value with the right shape may be a revoked, example or test credential. "
            "Confirm it is live before treating it as a confirmed compromise. Reported "
            "values are masked; raw evidence retention is disabled by default."
        ),
    )

    def evaluate(self, context: SourceContext) -> Iterator[RawFinding]:
        emitted = 0
        seen: set[tuple[str, str]] = set()
        for source in context.index.iter_files(
            languages={"java", "kotlin", "smali", "resource", "other"}
        ):
            if emitted >= MAX_FINDINGS:
                return
            for finding in self.evaluate_file(source, third_party=context.is_third_party(source.relative_path)):
                key = (
                    finding.metadata.get("provider", ""),
                    finding.evidence[0].value_fingerprint() or "",
                )
                if key in seen:
                    continue
                seen.add(key)
                emitted += 1
                yield finding
                if emitted >= MAX_FINDINGS:
                    return

    def evaluate_file(self, source: SourceFile, *, third_party: bool = False) -> Iterator[RawFinding]:
        for provider in PROVIDER_PATTERNS:
            for match in provider.pattern.finditer(source.text):
                value = match.group(provider.group)
                # A provider pattern is already shape-specific, so only the
                # placeholder check applies: the structural heuristics in
                # looks_benign() would discard a real AWS key as a
                # SCREAMING_CASE identifier.
                if not value or is_placeholder(value):
                    continue
                line_number = source.line_of_offset(match.start())
                line_text = source.line_text(line_number).strip()

                severity = provider.severity
                confidence = provider.confidence
                if third_party:
                    # A key inside a bundled SDK is usually the SDK vendor's own
                    # sample or a public identifier.
                    confidence = Confidence.low
                    severity = Severity.low if severity == Severity.low else Severity.medium

                evidence = [
                    Evidence(
                        description=f"{provider.name} found in {source.relative_path}",
                        snippet=line_text[:300],
                        file_path=source.relative_path,
                        line_number=line_number,
                        kind="code" if source.language != "resource" else "resource",
                        sensitive=provider.is_sensitive,
                        raw_value=value if provider.is_sensitive else None,
                        metadata={
                            "provider": provider.name,
                            "value_length": len(value),
                            "public_identifier": not provider.is_sensitive,
                        },
                    )
                ]
                if provider.note:
                    evidence.append(Evidence(description=provider.note, kind="metadata"))
                if third_party:
                    evidence.append(
                        Evidence(
                            description=(
                                "The value is located in a bundled third-party library "
                                "path, so it may belong to the SDK vendor rather than to "
                                "this application"
                            ),
                            kind="metadata",
                        )
                    )

                title = (
                    f"Hardcoded {provider.name}"
                    if provider.is_sensitive
                    else f"Client identifier embedded in the application: {provider.name}"
                )
                description = (
                    self.meta.description
                    if provider.is_sensitive
                    else (
                        f"A {provider.name} is embedded in the application. This class of "
                        "key is intended to be distributed in clients and is not a secret "
                        "by itself; the security question is whether the key is restricted."
                    )
                )
                yield self.finding(
                    title=title,
                    description=description,
                    severity=severity,
                    confidence=confidence,
                    affected_component=source.relative_path,
                    file_path=source.relative_path,
                    line_number=line_number,
                    evidence=evidence,
                    impact=(
                        self.meta.impact
                        if provider.is_sensitive
                        else (
                            "If the key is not restricted by package name and signing "
                            "certificate, a third party can extract it and consume your "
                            "quota or incur billing against your project."
                        )
                    ),
                    remediation=(
                        self.meta.remediation
                        if provider.is_sensitive
                        else (
                            "Restrict the key in the provider console to this "
                            "application's package name and signing certificate "
                            "fingerprint, and limit it to the specific APIs it needs."
                        )
                    ),
                    metadata={
                        "provider": provider.name,
                        "public_identifier": not provider.is_sensitive,
                        "third_party_path": third_party,
                    },
                )


register(ProviderSecretRule())


class GenericSecretRule(Rule):
    """High-entropy literals assigned to credential-named identifiers."""

    meta = RuleMetadata(
        id="DS-SECRET-002",
        name="Possible hardcoded credential",
        description=(
            "A high-entropy string literal is assigned to an identifier whose name "
            "indicates it holds a credential. The combination of a credential-shaped "
            "name and a random-looking value suggests an embedded secret."
        ),
        category=FindingCategory.secrets,
        severity=Severity.high,
        confidence=Confidence.medium,
        engine=ENGINE,
        impact=(
            "If the value is a live credential, anyone who extracts the APK can use it "
            "against the service it authenticates to. Because every installation ships "
            "the same value, one extraction affects all users and the credential cannot "
            "be rotated without a new release."
        ),
        remediation=(
            "Confirm what the value authenticates to. If it is live, rotate it and move "
            "the privileged operation to a server component so the application holds no "
            "long-lived secret. If the value is not a credential, rename the identifier "
            "so the intent is clear."
        ),
        cwe_ids=["CWE-798", "CWE-312"],
        masvs_controls=["MASVS-CRYPTO-2"],
        references=[MASTG_SECRETS],
        verification=(
            "Locate the use site of the constant to determine which service it "
            "authenticates to, then confirm whether the value is accepted."
        ),
        limitations=(
            "This is a heuristic. Opaque non-secret values such as public keys, "
            "resource identifiers and vendor application ids can match. Values are "
            "masked in all output; review the call site before treating the finding as "
            "confirmed."
        ),
    )

    def evaluate(self, context: SourceContext) -> Iterator[RawFinding]:
        emitted = 0
        seen_fingerprints: set[str] = set()
        for source in context.index.iter_files(languages={"java", "kotlin", "smali"}):
            if emitted >= MAX_FINDINGS:
                return
            third_party = context.is_third_party(source.relative_path)
            for finding in self.evaluate_file(source, third_party=third_party):
                fingerprint = finding.evidence[0].value_fingerprint() or ""
                if fingerprint in seen_fingerprints:
                    continue
                seen_fingerprints.add(fingerprint)
                emitted += 1
                yield finding
                if emitted >= MAX_FINDINGS:
                    return

    def evaluate_file(self, source: SourceFile, *, third_party: bool = False) -> Iterator[RawFinding]:
        for candidate in self._candidates(source):
            name, value, line_number = candidate
            if looks_benign(value):
                continue
            entropy = shannon_entropy(value)
            classes = character_classes(value)

            name_is_secret = identifier_names_secret(name)
            # Smali constants have no identifier, so require the surrounding line
            # to name a credential.
            if not name_is_secret:
                continue
            if len(value) < MIN_GENERIC_LENGTH:
                continue
            if entropy < MIN_GENERIC_ENTROPY:
                continue

            confidence = Confidence.medium
            severity = Severity.high
            notes: list[str] = []
            if entropy >= 4.2 and classes >= 3 and len(value) >= 32:
                confidence = Confidence.high
                notes.append(
                    f"value is {len(value)} characters with {entropy:.2f} bits of entropy "
                    f"per character across {classes} character classes"
                )
            else:
                notes.append(
                    f"value is {len(value)} characters with {entropy:.2f} bits of entropy "
                    "per character"
                )
            if third_party:
                confidence = Confidence.low
                severity = Severity.medium
                notes.append(
                    "the constant is in a bundled third-party library path, so it may be "
                    "an SDK default rather than this application's credential"
                )

            line_text = source.line_text(line_number).strip()
            evidence = [
                Evidence(
                    description=f"Constant {name!r} assigned a high-entropy literal",
                    snippet=line_text[:300],
                    file_path=source.relative_path,
                    line_number=line_number,
                    kind="code",
                    sensitive=True,
                    raw_value=value,
                    metadata={
                        "identifier": name,
                        "entropy": round(entropy, 3),
                        "length": len(value),
                        "character_classes": classes,
                    },
                )
            ]
            evidence.extend(Evidence(description=note, kind="metadata") for note in notes)

            yield self.finding(
                title=f"Possible hardcoded credential in {name}",
                severity=severity,
                confidence=confidence,
                affected_component=source.relative_path,
                file_path=source.relative_path,
                line_number=line_number,
                evidence=evidence,
                metadata={
                    "identifier": name,
                    "entropy": round(entropy, 3),
                    "third_party_path": third_party,
                },
            )

    @staticmethod
    def _candidates(source: SourceFile) -> Iterable[tuple[str, str, int]]:
        if source.language == "smali":
            for match in SMALI_CONST.finditer(source.text):
                line_number = source.line_of_offset(match.start())
                # Use nearby field/method context as the identifier.
                context_line = source.line_text(max(line_number - 1, 1))
                name = context_line.strip()[:80] or "const-string"
                yield name, match.group("value"), line_number
            return
        for match in ASSIGNMENT.finditer(source.text):
            yield (
                match.group("name"),
                match.group("value"),
                source.line_of_offset(match.start()),
            )


register(GenericSecretRule())
