"""Secret detection: provider formats, entropy heuristics and masking."""

from __future__ import annotations

import pytest

from app.core.enums import Confidence, Severity
from app.detection.context import SourceFile
from app.detection.rules.secret_rules import (
    GenericSecretRule,
    ProviderSecretRule,
    identifier_names_secret,
    is_placeholder,
    looks_benign,
    shannon_entropy,
)


def java_file(body: str, path: str = "com/example/app/Config.java") -> SourceFile:
    return SourceFile(relative_path=path, language="java", text=body)


class TestHelpers:
    def test_entropy_increases_with_randomness(self) -> None:
        assert shannon_entropy("aaaaaaaaaa") < shannon_entropy("x9K2mQ7vLp4wR8tN")

    @pytest.mark.parametrize(
        "value",
        [
            "550e8400-e29b-41d4-a716-446655440000",  # uuid
            "com.example.app.MainActivity",  # class name
            "https://example.com/path",  # url
            "#ff00aa",  # colour
            "YOUR_API_KEY_HERE",  # placeholder
            "d41d8cd98f00b204e9800998ecf8427e",  # md5-shaped digest
        ],
    )
    def test_benign_shapes_are_rejected(self, value: str) -> None:
        assert looks_benign(value)

    def test_ordinary_identifiers_are_gated_by_entropy_not_shape(self) -> None:
        """A value like "image_cache" has no benign *shape*.

        It is excluded by the length and entropy thresholds instead, which is
        the correct layer: shape matching should reject only values that are
        structurally something else (a UUID, a class name, a URL).
        """
        value = "image_cache"
        assert shannon_entropy(value) < 3.6
        assert len(value) < 20

    def test_a_real_looking_secret_is_not_benign(self) -> None:
        assert not looks_benign("x9K2mQ7vLp4wR8tN3bY6cZ1jH5sD0aF7gU4eI2oP")

    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("API_SECRET_KEY", True),
            ("apiSecretKey", True),
            ("AWS_ACCESS_KEY_ID", True),
            ("userPassword", True),
            ("passwordHint", False),  # names a field, not a value
            ("PASSWORD_FIELD_LABEL", False),
            ("tokenUrl", False),  # a URL, not a token
            ("CACHE_DIR_NAME", False),
        ],
    )
    def test_identifier_classification(self, name: str, expected: bool) -> None:
        assert identifier_names_secret(name) is expected

    def test_placeholder_detection(self) -> None:
        assert is_placeholder("AKIAYOUR_KEY_HERE")
        assert not is_placeholder("AKIA_REDACTED_IN_HISTORY")


class TestProviderSecrets:
    @pytest.mark.parametrize(
        ("snippet", "provider"),
        [
            ('String k = "AKIA_REDACTED_IN_HISTORY";', "AWS access key id"),
            ('String k = "ghp_REDACTED_IN_HISTORY";', "GitHub token"),
            ('String k = "xoxb-REDACTED_IN_HISTORY";', "Slack token"),
            ('String k = "sk_live_REDACTED";', "Stripe secret key"),
            ('String k = "-----BEGIN RSA PRIVATE KEY-----";', "Private key block"),
        ],
    )
    def test_detects_known_formats(self, snippet: str, provider: str) -> None:
        findings = list(ProviderSecretRule().evaluate_file(java_file(snippet)))
        assert any(f.metadata["provider"] == provider for f in findings)

    def test_google_api_key_is_reported_as_a_public_identifier(self) -> None:
        """A Google API key ships in clients by design; it is not a secret."""
        snippet = 'String k = "AIza_REDACTED_IN_HISTORY";'
        findings = list(ProviderSecretRule().evaluate_file(java_file(snippet)))
        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.low
        assert finding.metadata["public_identifier"] is True
        assert "not a secret" in finding.description
        assert finding.evidence[0].sensitive is False

    def test_a_placeholder_is_not_reported(self) -> None:
        snippet = 'String k = "AKIA_REDACTED_IN_HISTORY";'
        assert list(ProviderSecretRule().evaluate_file(java_file(snippet))) == []

    def test_third_party_path_lowers_confidence(self) -> None:
        snippet = 'String k = "ghp_REDACTED_IN_HISTORY";'
        findings = list(
            ProviderSecretRule().evaluate_file(
                java_file(snippet, "com/google/android/gms/Internal.java"), third_party=True
            )
        )
        assert findings[0].confidence == Confidence.low

    def test_evidence_is_masked_and_fingerprinted(self) -> None:
        secret = "ghp_REDACTED_IN_HISTORY"
        findings = list(ProviderSecretRule().evaluate_file(java_file(f'String k = "{secret}";')))
        evidence = findings[0].evidence[0]
        assert evidence.sensitive is True
        masked = evidence.masked_snippet()
        assert secret not in masked
        assert "•" in masked
        assert evidence.value_fingerprint()

    def test_fingerprint_is_stable_and_distinct(self) -> None:
        from app.core.redaction import fingerprint_value

        assert fingerprint_value("abc") == fingerprint_value("abc")
        assert fingerprint_value("abc") != fingerprint_value("abd")


class TestGenericSecrets:
    def test_detects_a_high_entropy_credential_constant(self) -> None:
        snippet = 'public static final String API_SECRET_KEY = "x9K2mQ7vLp4wR8tN3bY6cZ1jH5sD0aF7gU4eI2oP";'
        findings = list(GenericSecretRule().evaluate_file(java_file(snippet)))
        assert len(findings) == 1
        assert findings[0].severity == Severity.high

    def test_ignores_a_low_entropy_value(self) -> None:
        snippet = 'public static final String API_SECRET_KEY = "aaaaaaaaaaaaaaaaaaaaaaaa";'
        assert list(GenericSecretRule().evaluate_file(java_file(snippet))) == []

    def test_ignores_a_short_value(self) -> None:
        snippet = 'public static final String API_SECRET_KEY = "x9K2mQ7v";'
        assert list(GenericSecretRule().evaluate_file(java_file(snippet))) == []

    def test_ignores_a_high_entropy_value_with_a_benign_name(self) -> None:
        snippet = (
            'public static final String CACHE_BUCKET = "x9K2mQ7vLp4wR8tN3bY6cZ1jH5sD0aF7gU4eI2oP";'
        )
        assert list(GenericSecretRule().evaluate_file(java_file(snippet))) == []

    def test_ignores_a_descriptive_field_name(self) -> None:
        snippet = (
            'public static final String PASSWORD_FIELD_LABEL = "x9K2mQ7vLp4wR8tN3bY6cZ1jH5sD0aF";'
        )
        assert list(GenericSecretRule().evaluate_file(java_file(snippet))) == []
