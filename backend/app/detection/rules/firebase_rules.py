"""Firebase configuration observations.

Important: a Firebase API key or project id is **not** a secret.  Google
documents these as client identifiers that are expected to ship inside
applications; security depends on Firebase Security Rules, not on the key being
hidden.  This module therefore records *observations* about the configuration
and states plainly what cannot be determined offline.

DroidScope never contacts a Firebase project, never attempts to read a database,
and never enumerates data.  Verifying whether a database or bucket is readable
requires authorisation from the project owner and is out of scope for static
analysis.
"""

from __future__ import annotations

from collections.abc import Iterator

from app.core.enums import Confidence, FindingCategory, Severity
from app.detection.base import Rule, RuleMetadata
from app.detection.context import SourceContext
from app.detection.model import Evidence, RawFinding
from app.detection.registry import register

ENGINE = "firebase-analyzer"

FIREBASE_RESOURCE_KEYS = {
    "google_app_id": "Firebase application id",
    "gcm_defaultSenderId": "Cloud Messaging sender id",
    "default_web_client_id": "OAuth web client id",
    "firebase_database_url": "Realtime Database URL",
    "google_storage_bucket": "Cloud Storage bucket",
    "project_id": "Firebase project id",
    "google_api_key": "Firebase API key",
    "google_crash_reporting_api_key": "Crash reporting API key",
}

FIREBASE_REFERENCE = (
    "https://firebase.google.com/docs/projects/api-keys"
)
RULES_REFERENCE = "https://firebase.google.com/docs/rules"


class FirebaseConfigurationRule(Rule):
    """Report the Firebase configuration found in the APK, as an observation."""

    meta = RuleMetadata(
        id="DS-FIREBASE-001",
        name="Firebase configuration present in the application",
        description=(
            "Firebase client configuration was found in the application's resources. "
            "These values are client identifiers, not secrets: Google documents them "
            "as safe to include in client applications. They are recorded here because "
            "they identify the backend services the application uses, which is the "
            "starting point for an authorised review of the project's security rules."
        ),
        category=FindingCategory.firebase,
        severity=Severity.info,
        confidence=Confidence.high,
        engine=ENGINE,
        impact=(
            "No impact follows from the presence of these identifiers alone. The "
            "security of a Firebase backend is determined by its Security Rules and by "
            "whether the API key is restricted, neither of which can be observed from "
            "the APK. If the rules permit unauthenticated access, the identifiers below "
            "are sufficient to reach the data; that must be confirmed by someone "
            "authorised to inspect the project."
        ),
        remediation=(
            "Review the project's Firebase Security Rules so that every read and write "
            "requires an authenticated, authorised principal, and never rely on the "
            "client identifiers being secret. Restrict the API key in the Google Cloud "
            "console to this application's package name and signing certificate, and "
            "limit it to the APIs actually in use. Enable App Check to reject requests "
            "from clients other than your own application."
        ),
        cwe_ids=[],
        masvs_controls=["MASVS-AUTH-2"],
        references=[FIREBASE_REFERENCE, RULES_REFERENCE],
        verification=(
            "Access-control verification requires the project owner's authorisation. "
            "With authorisation, review the Security Rules in the Firebase console, or "
            "use the Firebase Emulator Suite against a copy of the rules. DroidScope "
            "does not contact the project."
        ),
        limitations=(
            "Offline observation only. DroidScope does not determine whether the "
            "database, storage bucket or any other service is actually readable, and "
            "does not treat the presence of these identifiers as a vulnerability."
        ),
    )

    def evaluate(self, context: SourceContext) -> Iterator[RawFinding]:
        discovered: dict[str, tuple[str, str, int | None]] = {}

        for source in context.index.iter_files(languages={"resource", "other"}):
            name = source.relative_path.replace("\\", "/")
            if not (
                name.endswith("strings.xml")
                or name.endswith("google-services.json")
                or "values" in name
            ):
                continue
            for key, label in FIREBASE_RESOURCE_KEYS.items():
                if key in discovered:
                    continue
                value, line = self._extract(source.text, key)
                if value:
                    discovered[key] = (label, value, line)
                    if line is None:
                        continue

        if not discovered:
            return

        evidence: list[Evidence] = []
        for key, (label, value, line) in sorted(discovered.items()):
            evidence.append(
                Evidence(
                    description=f"{label} ({key})",
                    snippet=f"{key} = {value}",
                    line_number=line,
                    kind="resource",
                    metadata={"resource_key": key, "label": label},
                )
            )

        database_url = discovered.get("firebase_database_url", (None, None, None))[1]
        bucket = discovered.get("google_storage_bucket", (None, None, None))[1]
        if database_url:
            evidence.append(
                Evidence(
                    description=(
                        "A Realtime Database URL is configured. Whether its contents are "
                        "readable without authentication is governed by the project's "
                        "Security Rules and was not tested."
                    ),
                    kind="metadata",
                )
            )
        if bucket:
            evidence.append(
                Evidence(
                    description=(
                        "A Cloud Storage bucket is configured. Object-level access is "
                        "governed by Storage Security Rules and was not tested."
                    ),
                    kind="metadata",
                )
            )

        yield self.finding(
            title=(
                f"Firebase configuration detected ({len(discovered)} identifier"
                f"{'s' if len(discovered) != 1 else ''})"
            ),
            affected_component=discovered.get("project_id", (None, None, None))[1]
            or context.metadata.package_name,
            file_path="res/values/strings.xml",
            evidence=evidence,
            metadata={
                "services": sorted(discovered),
                "has_realtime_database": bool(database_url),
                "has_storage_bucket": bool(bucket),
            },
        )

    @staticmethod
    def _extract(text: str, key: str) -> tuple[str | None, int | None]:
        import re

        patterns = (
            re.compile(rf'<string name="{re.escape(key)}"[^>]*>([^<]+)</string>'),
            re.compile(rf'"{re.escape(key)}"\s*:\s*"([^"]+)"'),
        )
        for pattern in patterns:
            match = pattern.search(text)
            if match:
                line = text.count("\n", 0, match.start()) + 1
                return match.group(1).strip(), line
        return None, None


register(FirebaseConfigurationRule())
