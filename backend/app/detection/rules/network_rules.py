"""Rules over extracted network indicators.

The indicator extractor classifies every URL, host and address it finds.  These
rules turn a *classification* into a finding only where the classification
itself is the security observation -- an internal hostname shipped in a release
build, or an endpoint addressed by raw IP.  Indicators are never treated as
malicious merely because they exist, and DroidScope never contacts them.
"""

from __future__ import annotations

from collections.abc import Iterator

from app.core.enums import Confidence, FindingCategory, Severity
from app.detection.base import Rule, RuleMetadata
from app.detection.context import IndicatorContext
from app.detection.model import Evidence, RawFinding
from app.detection.registry import register

ENGINE = "network-indicator-analyzer"


class InternalEndpointRule(Rule):
    meta = RuleMetadata(
        id="DS-INDICATOR-001",
        name="Internal or private network endpoint embedded in the application",
        description=(
            "The application contains a URL or address pointing at a private network "
            "range, an internal hostname, or a development host. Such endpoints are "
            "normally expected only in debug builds."
        ),
        category=FindingCategory.network_security,
        severity=Severity.low,
        confidence=Confidence.medium,
        engine=ENGINE,
        impact=(
            "Internal endpoints disclose details of the operator's infrastructure, "
            "including naming conventions and internal address ranges, which assists "
            "an attacker who gains a foothold on the same network. If the application "
            "actually contacts the endpoint, users on other networks will see failed "
            "connections, and a staging endpoint may enforce weaker controls than "
            "production."
        ),
        remediation=(
            "Remove development and staging endpoints from release builds by selecting "
            "them from build configuration rather than embedding them in shared code. "
            "Verify the release artifact contains only production endpoints."
        ),
        cwe_ids=["CWE-200"],
        masvs_controls=["MASVS-CODE-4"],
        references=[
            "https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0026/"
        ],
        limitations=(
            "An embedded address is not evidence that the application connects to it. "
            "DroidScope does not contact extracted endpoints and performs no scanning."
        ),
    )

    INTERNAL_SCOPES = {"private", "loopback", "link-local"}
    DEV_HOST_MARKERS = ("staging", "dev.", "test.", "qa.", "uat", "internal", "intranet", "localhost", ".local")

    def evaluate(self, context: IndicatorContext) -> Iterator[RawFinding]:
        grouped: dict[str, list[dict]] = {}
        for indicator in context.indicators:
            host = (indicator.get("host") or indicator.get("value") or "").lower()
            scope = indicator.get("scope", "unknown")
            is_internal = scope in self.INTERNAL_SCOPES
            is_dev = any(marker in host for marker in self.DEV_HOST_MARKERS)
            if not (is_internal or is_dev):
                continue
            # Loopback alone is routine (emulator host, local test server).
            key = "development" if is_dev and not is_internal else scope
            grouped.setdefault(key, []).append(indicator)

        for key, indicators in grouped.items():
            severity = Severity.low
            if key == "private":
                severity = Severity.low
            elif key == "development":
                severity = Severity.medium

            evidence = [
                Evidence(
                    description=(
                        f"{indicator.get('indicator_type', 'indicator')} "
                        f"{indicator.get('value', '')} "
                        f"(scope: {indicator.get('scope', 'unknown')})"
                    ),
                    file_path=indicator.get("source_file"),
                    snippet=indicator.get("context"),
                    kind="metadata",
                    metadata={
                        "scope": indicator.get("scope"),
                        "occurrences": indicator.get("occurrences", 1),
                    },
                )
                for indicator in indicators[:12]
            ]
            if len(indicators) > 12:
                evidence.append(
                    Evidence(
                        description=f"{len(indicators) - 12} further indicators of the same class",
                        kind="metadata",
                    )
                )

            label = {
                "private": "private network address",
                "loopback": "loopback address",
                "link-local": "link-local address",
                "development": "development or staging hostname",
            }.get(key, key)

            yield self.finding(
                title=f"Embedded {label} ({len(indicators)} indicator{'s' if len(indicators) != 1 else ''})",
                severity=severity,
                affected_component=context.metadata.package_name if context.metadata else None,
                evidence=evidence,
                metadata={"scope": key, "count": len(indicators)},
            )


register(InternalEndpointRule())


class RawIpEndpointRule(Rule):
    meta = RuleMetadata(
        id="DS-INDICATOR-002",
        name="Endpoint addressed by raw IP address",
        description=(
            "The application references a public endpoint by IP address rather than by "
            "hostname."
        ),
        category=FindingCategory.network_security,
        severity=Severity.low,
        confidence=Confidence.medium,
        engine=ENGINE,
        impact=(
            "A certificate cannot normally be issued for an IP address, so TLS to an "
            "IP endpoint is often accompanied by disabled certificate validation. "
            "Hardcoded addresses also break when infrastructure moves, which pushes "
            "developers toward disabling verification to keep the client working."
        ),
        remediation=(
            "Address services by hostname so that DNS and certificate validation work "
            "normally, and confirm that no certificate or hostname verification has "
            "been relaxed to accommodate an IP endpoint."
        ),
        cwe_ids=["CWE-295"],
        masvs_controls=["MASVS-NETWORK-1"],
        references=[
            "https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0020/"
        ],
        limitations=(
            "Some IP references are legitimate (STUN servers, DNS resolvers, or "
            "fallback addresses). DroidScope does not contact the address."
        ),
    )

    def evaluate(self, context: IndicatorContext) -> Iterator[RawFinding]:
        candidates = [
            indicator
            for indicator in context.indicators
            if indicator.get("indicator_type") == "ip"
            and indicator.get("scope") == "public"
        ]
        if not candidates:
            return
        yield self.finding(
            title=f"{len(candidates)} public IP address endpoint(s) referenced",
            affected_component=context.metadata.package_name if context.metadata else None,
            evidence=[
                Evidence(
                    description=f"IP address {indicator.get('value')}",
                    file_path=indicator.get("source_file"),
                    snippet=indicator.get("context"),
                    kind="metadata",
                    metadata={"occurrences": indicator.get("occurrences", 1)},
                )
                for indicator in candidates[:15]
            ],
            metadata={"count": len(candidates)},
        )


register(RawIpEndpointRule())
