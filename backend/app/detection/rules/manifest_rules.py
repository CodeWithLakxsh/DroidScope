"""Manifest and application-configuration detection rules.

These rules are deliberately *not* keyword matchers.  Each one models the
platform behaviour that makes a configuration dangerous, and refuses to report
when the preconditions for exploitation are absent.  The most common source of
noise in Android scanners -- "every exported component is a vulnerability" -- is
handled in :class:`ExportedComponentRule`, which weighs component kind, target
SDK, permission protection level and intent filters before deciding.
"""

from __future__ import annotations

from collections.abc import Iterable

from app.core.enums import Confidence, FindingCategory, Severity
from app.detection.base import Rule, RuleMetadata
from app.detection.context import ManifestContext
from app.detection.model import Evidence, RawFinding
from app.detection.registry import register
from app.schemas.apk import Component

ENGINE = "manifest-analyzer"

# Protection levels that actually restrict which apps may invoke a component.
RESTRICTIVE_PROTECTION_PREFIXES = ("signature", "signatureOrSystem", "privileged")

MASTG_COMPONENT = "https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0029/"
MASTG_BACKUP = "https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0009/"
MASTG_DEBUG = "https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0046/"
MASTG_CLEARTEXT = "https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0019/"
ANDROID_EXPORTED_DOC = (
    "https://developer.android.com/guide/topics/manifest/activity-element#exported"
)
ANDROID_NSC_DOC = "https://developer.android.com/privacy-and-security/security-config"


def _protection_is_restrictive(level: str | None) -> bool:
    if not level:
        return False
    return any(level.startswith(prefix) for prefix in RESTRICTIVE_PROTECTION_PREFIXES)


def _component_guard(component: Component, context: ManifestContext) -> tuple[bool, str | None]:
    """Is the component access-controlled?  Returns (guarded, protection level)."""
    permissions = [component.permission, component.read_permission, component.write_permission]
    for permission in permissions:
        if not permission:
            continue
        declaration = context.metadata.declared_permission(permission)
        level = (
            declaration.protection_level if declaration else component.permission_protection_level
        )
        if _protection_is_restrictive(level):
            return True, level
        # A normal/dangerous custom permission is a weak guard: any app can
        # request a normal permission and it is granted at install time.
        return False, level or "normal (assumed)"
    return False, None


class ExportedComponentRule(Rule):
    """Exported components reachable by any installed application.

    Reported only when the component is genuinely reachable:

    * ``android:exported`` is true, or defaulted to true by an intent filter;
    * it is not guarded by a signature-level permission;
    * it is enabled.

    Severity reflects the component kind, because the consequence differs: an
    exported provider can leak stored data, an exported receiver can be driven
    by a broadcast, an exported activity is usually a UI entry point.  Launcher
    activities are reported as informational, since being launchable is their
    purpose.
    """

    meta = RuleMetadata(
        id="DS-MANIFEST-001",
        name="Exported component without access control",
        description=(
            "The component is exported and is not protected by a signature-level "
            "permission, so any application installed on the device can start or "
            "bind to it."
        ),
        category=FindingCategory.component_security,
        severity=Severity.medium,
        confidence=Confidence.high,
        engine=ENGINE,
        impact=(
            "Any third-party application can interact with this component. Depending "
            "on what the component does with the supplied Intent this may allow "
            "unauthorised actions, information disclosure, or state changes that the "
            "application assumes only its own code can trigger."
        ),
        remediation=(
            'Set android:exported="false" if the component is only used inside the '
            "application. If it must be reachable by other applications, protect it "
            "with android:permission using a signature-level custom permission, and "
            "validate every field of the incoming Intent."
        ),
        cwe_ids=["CWE-926"],
        masvs_controls=["MASVS-PLATFORM-1"],
        references=[MASTG_COMPONENT, ANDROID_EXPORTED_DOC],
        verification=(
            "Confirm reachability from an unprivileged app, e.g. "
            "adb shell am start -n <package>/<component> for an activity, or "
            "adb shell am broadcast -n <package>/<component> for a receiver."
        ),
        limitations=(
            "Static analysis cannot tell whether the component performs a security "
            "relevant action with the Intent it receives; a reviewer must confirm the "
            "impact by inspecting the component implementation."
        ),
    )

    SEVERITY_BY_KIND = {
        "provider": Severity.high,
        "service": Severity.medium,
        "receiver": Severity.medium,
        "activity": Severity.low,
        "activity-alias": Severity.low,
    }

    def evaluate(self, context: ManifestContext) -> Iterable[RawFinding]:
        metadata = context.metadata
        target_sdk = metadata.effective_target_sdk()

        for component in metadata.exported_components():
            if not component.enabled:
                continue

            guarded, level = _component_guard(component, context)
            if guarded:
                continue

            # A launcher activity is exported by design.
            if component.is_launcher:
                yield self._launcher_finding(component, context)
                continue

            severity = self.SEVERITY_BY_KIND.get(component.kind, Severity.low)
            confidence = Confidence.high

            notes: list[str] = []
            if component.exported_implied:
                notes.append(
                    "android:exported is absent; the platform defaults this component to "
                    "exported because it declares an intent filter"
                )
                if target_sdk >= 31:
                    notes.append(
                        "targetSdkVersion is 31 or above, where the attribute is mandatory "
                        "for components with intent filters -- the package as built would be "
                        "rejected at install time, so verify the manifest that actually ships"
                    )
                    confidence = Confidence.medium
            if level:
                notes.append(
                    f"a permission is declared but its protection level is {level!r}, which "
                    "does not restrict which applications may be granted it"
                )

            evidence = [
                Evidence(
                    description=f"{component.kind} declared in the manifest",
                    snippet=self._component_snippet(component),
                    file_path=context.manifest_path,
                    line_number=context.manifest_line_of(component.name),
                    kind="manifest",
                    metadata={
                        "exported_attribute": component.exported_attribute,
                        "intent_filters": len(component.intent_filters),
                        "target_sdk": target_sdk,
                    },
                )
            ]
            for note in notes:
                evidence.append(Evidence(description=note, kind="manifest"))

            if component.kind == "provider" and component.grant_uri_permissions:
                severity = Severity.high
                evidence.append(
                    Evidence(
                        description=(
                            "android:grantUriPermissions is enabled, so URI permissions can "
                            "be delegated to other applications"
                        ),
                        kind="manifest",
                    )
                )

            yield self.finding(
                title=f"Exported {component.kind} without access control: {component.name}",
                severity=severity,
                confidence=confidence,
                affected_component=component.name,
                file_path=context.manifest_path,
                line_number=context.manifest_line_of(component.name),
                evidence=evidence,
                metadata={
                    "component_kind": component.kind,
                    "exported_implied": component.exported_implied,
                    "authorities": component.authorities,
                },
            )

    def _launcher_finding(self, component: Component, context: ManifestContext) -> RawFinding:
        return self.finding(
            title=f"Launcher activity is exported by design: {component.name}",
            description=(
                "The activity is exported because it is the application launcher entry "
                "point. This is required for the application to be started from the home "
                "screen and is not a vulnerability on its own."
            ),
            severity=Severity.info,
            confidence=Confidence.high,
            affected_component=component.name,
            file_path=context.manifest_path,
            line_number=context.manifest_line_of(component.name),
            impact=(
                "No direct impact. Recorded so that the exported surface of the "
                "application is completely documented."
            ),
            remediation="No change required for a launcher activity.",
            evidence=[
                Evidence(
                    description="Activity declares MAIN/LAUNCHER intent filter",
                    snippet=self._component_snippet(component),
                    file_path=context.manifest_path,
                    kind="manifest",
                )
            ],
            metadata={"component_kind": component.kind, "launcher": True},
        )

    @staticmethod
    def _component_snippet(component: Component) -> str:
        attributes = [f'android:name="{component.name}"']
        if component.exported_attribute is not None:
            attributes.append(f'android:exported="{str(component.exported_attribute).lower()}"')
        if component.permission:
            attributes.append(f'android:permission="{component.permission}"')
        if component.authorities:
            attributes.append(f'android:authorities="{";".join(component.authorities)}"')
        tag = component.kind
        snippet = f"<{tag} {' '.join(attributes)}>"
        for flt in component.intent_filters[:3]:
            actions = "".join(f'\n    <action android:name="{a}" />' for a in flt.actions[:4])
            categories = "".join(
                f'\n    <category android:name="{c}" />' for c in flt.categories[:4]
            )
            snippet += f"\n  <intent-filter>{actions}{categories}\n  </intent-filter>"
        return snippet + f"\n</{tag}>"


register(ExportedComponentRule())


class ExportedProviderDataRule(Rule):
    """An exported content provider is a direct path to the app's stored data."""

    meta = RuleMetadata(
        id="DS-MANIFEST-002",
        name="Exported content provider exposes application data",
        description=(
            "A content provider is exported without a signature-level permission on "
            "both read and write access. Content providers front application data "
            "stores, so an unprotected provider is a direct data exposure path."
        ),
        category=FindingCategory.data_storage,
        severity=Severity.high,
        confidence=Confidence.high,
        engine=ENGINE,
        impact=(
            "Another application can query or modify the data served by this provider "
            "without holding any privileged permission, by addressing its content:// "
            "authority."
        ),
        remediation=(
            'Set android:exported="false" unless cross-application access is a '
            "requirement. Where it is required, declare separate android:readPermission "
            "and android:writePermission with signature protection level, add "
            "<path-permission> entries for sensitive paths, and validate selection "
            "arguments to prevent SQL injection through the provider interface."
        ),
        cwe_ids=["CWE-926", "CWE-200"],
        masvs_controls=["MASVS-PLATFORM-1", "MASVS-STORAGE-1"],
        references=[
            "https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0024/",
            "https://developer.android.com/guide/topics/providers/content-provider-creating#Permissions",
        ],
        verification=(
            "Enumerate the authority from an unprivileged app or adb: "
            "adb shell content query --uri content://<authority>/<path>"
        ),
        limitations=(
            "Whether sensitive data is actually reachable depends on the provider "
            "implementation and its URI matcher, which static manifest analysis cannot "
            "determine."
        ),
    )

    def evaluate(self, context: ManifestContext) -> Iterable[RawFinding]:
        for provider in context.metadata.components_of("provider"):
            if not provider.exported or not provider.enabled:
                continue

            read_guarded = _protection_is_restrictive(
                self._level(context, provider.read_permission or provider.permission)
            )
            write_guarded = _protection_is_restrictive(
                self._level(context, provider.write_permission or provider.permission)
            )
            if read_guarded and write_guarded:
                continue

            unguarded = []
            if not read_guarded:
                unguarded.append("read")
            if not write_guarded:
                unguarded.append("write")

            evidence = [
                Evidence(
                    description=(
                        f"Provider authorities: {', '.join(provider.authorities) or 'not declared'}"
                    ),
                    snippet=ExportedComponentRule._component_snippet(provider),
                    file_path=context.manifest_path,
                    line_number=context.manifest_line_of(provider.name),
                    kind="manifest",
                    metadata={"unprotected_operations": unguarded},
                ),
                Evidence(
                    description=(
                        f"Unprotected operations: {', '.join(unguarded)}; "
                        f"readPermission={provider.read_permission or 'none'}, "
                        f"writePermission={provider.write_permission or 'none'}, "
                        f"permission={provider.permission or 'none'}"
                    ),
                    kind="manifest",
                ),
            ]
            if provider.path_permissions:
                evidence.append(
                    Evidence(
                        description=(
                            f"{len(provider.path_permissions)} <path-permission> entries are "
                            "declared; paths they cover may be protected even though the "
                            "provider itself is not"
                        ),
                        kind="manifest",
                    )
                )

            severity = Severity.high if not write_guarded else Severity.medium
            yield self.finding(
                title=f"Exported content provider: {provider.name}",
                severity=severity,
                affected_component=provider.name,
                file_path=context.manifest_path,
                line_number=context.manifest_line_of(provider.name),
                evidence=evidence,
                metadata={
                    "authorities": provider.authorities,
                    "unprotected_operations": unguarded,
                    "grant_uri_permissions": provider.grant_uri_permissions,
                },
            )

    @staticmethod
    def _level(context: ManifestContext, permission: str | None) -> str | None:
        if not permission:
            return None
        declaration = context.metadata.declared_permission(permission)
        return declaration.protection_level if declaration else None


register(ExportedProviderDataRule())


class DebuggableRule(Rule):
    meta = RuleMetadata(
        id="DS-MANIFEST-003",
        name="Application is debuggable",
        description=(
            "android:debuggable is set to true. A debuggable application allows any "
            "user with ADB access to attach a debugger, read and modify process memory, "
            "and execute code in the application's security context."
        ),
        category=FindingCategory.manifest_configuration,
        severity=Severity.high,
        confidence=Confidence.high,
        engine=ENGINE,
        impact=(
            "An attacker with physical or ADB access can run arbitrary code as the "
            "application, read its private files and extract secrets held in memory. "
            "On a rooted device any application holding appropriate access can do the "
            "same. Debuggable builds also permit run-as access to the private data "
            "directory."
        ),
        remediation=(
            "Remove android:debuggable from the manifest and let the build system set "
            "it per build type. Release builds must never ship with it enabled."
        ),
        cwe_ids=["CWE-489"],
        masvs_controls=["MASVS-RESILIENCE-4"],
        references=[MASTG_DEBUG],
        verification="adb shell run-as <package> ls should fail on a non-debuggable release build.",
    )

    def evaluate(self, context: ManifestContext) -> Iterable[RawFinding]:
        flags = context.metadata.application_flags
        if flags.debuggable is not True:
            return
        yield self.finding(
            affected_component=context.metadata.package_name,
            file_path=context.manifest_path,
            line_number=context.manifest_line_of("debuggable"),
            evidence=[
                Evidence(
                    description="Application element sets android:debuggable",
                    snippet='<application android:debuggable="true" ... >',
                    file_path=context.manifest_path,
                    line_number=context.manifest_line_of("debuggable"),
                    kind="manifest",
                )
            ],
        )


register(DebuggableRule())


class BackupEnabledRule(Rule):
    """Backup exposure, differentiated by SDK level and by configuration.

    ``allowBackup`` defaults to true, so this rule reports the default too, but
    at a lower severity than an explicit opt-in, and it accounts for
    ``fullBackupContent`` / ``dataExtractionRules`` which can exclude sensitive
    files from the backup set.
    """

    meta = RuleMetadata(
        id="DS-MANIFEST-004",
        name="Application data can be backed up",
        description=(
            "Backup is enabled for the application, so its private data directory can "
            "be copied off the device through the Android backup mechanism."
        ),
        category=FindingCategory.data_storage,
        severity=Severity.medium,
        confidence=Confidence.high,
        engine=ENGINE,
        impact=(
            "On a device with USB debugging enabled, 'adb backup' (API < 31) or a "
            "device-to-device transfer can extract the application's private files, "
            "including databases, shared preferences and cached tokens."
        ),
        remediation=(
            'Set android:allowBackup="false" if the application stores credentials or '
            "other sensitive data. If backup is required, exclude sensitive paths using "
            "android:dataExtractionRules (API 31+) and android:fullBackupContent "
            "(API 23-30), and never place long-lived tokens in backed-up storage."
        ),
        cwe_ids=["CWE-530"],
        masvs_controls=["MASVS-STORAGE-2"],
        references=[
            MASTG_BACKUP,
            "https://developer.android.com/guide/topics/data/autobackup",
        ],
        verification=(
            "On API < 31 with USB debugging: adb backup -f out.ab <package>, then "
            "inspect the archive. On API 31+ verify the declared dataExtractionRules."
        ),
    )

    def evaluate(self, context: ManifestContext) -> Iterable[RawFinding]:
        flags = context.metadata.application_flags
        if flags.allow_backup is False:
            return

        explicit = flags.allow_backup is True
        min_sdk = context.metadata.min_sdk or 1
        has_rules = bool(flags.full_backup_content or flags.data_extraction_rules)

        severity = Severity.medium if explicit else Severity.low
        confidence = Confidence.high if explicit else Confidence.medium
        if has_rules:
            # Rules may already exclude everything sensitive.
            severity = Severity.low
            confidence = Confidence.low

        evidence = [
            Evidence(
                description=(
                    "android:allowBackup is explicitly true"
                    if explicit
                    else "android:allowBackup is not declared and therefore defaults to true"
                ),
                snippet=(
                    f'<application android:allowBackup="'
                    f'{str(flags.allow_backup).lower()}" ... >'
                )
                if explicit
                else (
                    "<application ... >  "
                    "<!-- allowBackup attribute absent, platform default is true -->"
                ),
                file_path=context.manifest_path,
                line_number=context.manifest_line_of("allowBackup"),
                kind="manifest",
            ),
            Evidence(
                description=(
                    f"minSdkVersion is {min_sdk}; adb backup was removed for applications "
                    "targeting API 31 and above, which limits but does not eliminate the "
                    "exposure (device transfer and cloud backup still apply)"
                ),
                kind="manifest",
            ),
        ]
        if has_rules:
            evidence.append(
                Evidence(
                    description=(
                        "Backup content rules are declared "
                        f"(fullBackupContent={flags.full_backup_content or 'none'}, "
                        f"dataExtractionRules={flags.data_extraction_rules or 'none'}); "
                        "review them to confirm sensitive paths are excluded"
                    ),
                    kind="manifest",
                )
            )

        yield self.finding(
            title=(
                "Application backup is explicitly enabled"
                if explicit
                else "Application backup is enabled by platform default"
            ),
            severity=severity,
            confidence=confidence,
            affected_component=context.metadata.package_name,
            file_path=context.manifest_path,
            line_number=context.manifest_line_of("allowBackup"),
            evidence=evidence,
            limitations=(
                "Whether sensitive data is actually included depends on what the "
                "application writes to its private directory and on the declared backup "
                "rules. This finding records the exposure path, not confirmed data loss."
            ),
            metadata={"explicit": explicit, "has_backup_rules": has_rules, "min_sdk": min_sdk},
        )


register(BackupEnabledRule())


class CleartextTrafficRule(Rule):
    """Cleartext HTTP exposure, resolved against the network security config."""

    meta = RuleMetadata(
        id="DS-MANIFEST-005",
        name="Cleartext network traffic is permitted",
        description=(
            "The application permits unencrypted HTTP traffic, either through "
            "android:usesCleartextTraffic or through its network security "
            "configuration."
        ),
        category=FindingCategory.network_security,
        severity=Severity.medium,
        confidence=Confidence.high,
        engine=ENGINE,
        impact=(
            "Traffic sent over cleartext HTTP can be read and modified by anyone on the "
            "network path, including other devices on the same Wi-Fi network. This "
            "allows credential interception and response tampering."
        ),
        remediation=(
            "Remove android:usesCleartextTraffic and set cleartextTrafficPermitted="
            '"false" in the base-config of the network security configuration. Where a '
            "specific host genuinely requires HTTP, scope the exception to that domain "
            "only, and move the exception into debug-overrides when it is for testing."
        ),
        cwe_ids=["CWE-319"],
        masvs_controls=["MASVS-NETWORK-1"],
        references=[MASTG_CLEARTEXT, ANDROID_NSC_DOC],
        verification=(
            "Observe traffic from an instrumented device, or attempt an HTTP request to "
            "a permitted host from within the application."
        ),
    )

    def evaluate(self, context: ManifestContext) -> Iterable[RawFinding]:
        flags = context.metadata.application_flags
        nsc = context.network_security_config
        min_sdk = context.metadata.min_sdk or 1
        target_sdk = context.metadata.effective_target_sdk()

        attribute_permits = flags.uses_cleartext_traffic is True
        config_permits_globally = bool(nsc and nsc.present and nsc.base_cleartext_permitted is True)
        config_blocks_globally = bool(nsc and nsc.present and nsc.base_cleartext_permitted is False)
        domain_exceptions = list(nsc.cleartext_domains) if nsc and nsc.present else []

        # Platform default: cleartext allowed below API 28, blocked from 28 up.
        default_permits = target_sdk < 28 and flags.uses_cleartext_traffic is None and not nsc

        if config_blocks_globally and not domain_exceptions and not attribute_permits:
            return  # Properly configured: nothing to report.

        if not (
            attribute_permits or config_permits_globally or domain_exceptions or default_permits
        ):
            return

        evidence: list[Evidence] = []
        severity = Severity.medium
        confidence = Confidence.high
        scope = "application-wide"

        if attribute_permits:
            evidence.append(
                Evidence(
                    description="android:usesCleartextTraffic is set to true",
                    snippet='<application android:usesCleartextTraffic="true" ... >',
                    file_path=context.manifest_path,
                    line_number=context.manifest_line_of("usesCleartextTraffic"),
                    kind="manifest",
                )
            )
        if config_permits_globally:
            evidence.append(
                Evidence(
                    description=(
                        "The network security configuration sets "
                        'cleartextTrafficPermitted="true" in base-config, which applies to '
                        "every destination"
                    ),
                    file_path=nsc.source_file if nsc else None,
                    kind="resource",
                )
            )
        if domain_exceptions:
            scope = "specific domains"
            evidence.append(
                Evidence(
                    description=(
                        "Cleartext is permitted for specific domains: "
                        + ", ".join(domain_exceptions[:12])
                    ),
                    file_path=nsc.source_file if nsc else None,
                    kind="resource",
                    metadata={"domains": domain_exceptions[:50]},
                )
            )
            if not attribute_permits and not config_permits_globally:
                # A scoped exception is far less serious than a blanket one, and
                # localhost exceptions are routine for development tooling.
                only_local = all(
                    domain in {"localhost", "127.0.0.1", "10.0.2.2", "::1"}
                    for domain in domain_exceptions
                )
                severity = Severity.low if only_local else Severity.medium
                confidence = Confidence.medium if only_local else Confidence.high
                if only_local:
                    evidence.append(
                        Evidence(
                            description=(
                                "Every cleartext exception targets a loopback or emulator "
                                "host address, which is the normal pattern for local "
                                "development endpoints"
                            ),
                            kind="resource",
                        )
                    )
        if default_permits:
            evidence.append(
                Evidence(
                    description=(
                        f"targetSdkVersion is {target_sdk}, below API 28, so the platform "
                        "permits cleartext traffic by default and no network security "
                        "configuration overrides it"
                    ),
                    kind="manifest",
                )
            )
            confidence = Confidence.medium

        if target_sdk >= 28 and not (
            attribute_permits or config_permits_globally or domain_exceptions
        ):
            return

        evidence.append(
            Evidence(
                description=(
                    f"minSdkVersion={min_sdk}, targetSdkVersion={target_sdk}; the platform "
                    "blocks cleartext by default from API 28 onwards unless overridden"
                ),
                kind="manifest",
            )
        )

        yield self.finding(
            title=f"Cleartext HTTP traffic permitted ({scope})",
            severity=severity,
            confidence=confidence,
            affected_component=context.metadata.package_name,
            file_path=(
                nsc.source_file
                if (nsc and nsc.source_file and not attribute_permits)
                else context.manifest_path
            ),
            evidence=evidence,
            limitations=(
                "This finding reports that cleartext is permitted, not that the "
                "application actually sends cleartext traffic. Confirm with a network "
                "capture from an authorised test environment."
            ),
            metadata={
                "attribute": flags.uses_cleartext_traffic,
                "base_config_permits": nsc.base_cleartext_permitted if nsc else None,
                "cleartext_domains": domain_exceptions[:50],
                "target_sdk": target_sdk,
            },
        )


register(CleartextTrafficRule())


class UserCertificateTrustRule(Rule):
    meta = RuleMetadata(
        id="DS-MANIFEST-006",
        name="Application trusts user-installed certificate authorities",
        description=(
            "The network security configuration adds the user certificate store as a "
            "trust anchor outside of debug-overrides, so certificates installed by the "
            "device user or by an MDM profile are trusted for TLS validation."
        ),
        category=FindingCategory.network_security,
        severity=Severity.medium,
        confidence=Confidence.high,
        engine=ENGINE,
        impact=(
            "A certificate installed on the device, whether by the user or by malware "
            "with the necessary access, becomes trusted for the application's TLS "
            "connections. This makes transparent interception of the application's "
            "traffic possible on a device the attacker controls."
        ),
        remediation=(
            'Remove <certificates src="user" /> from base-config and domain-config. If '
            "it is needed for testing, move it into <debug-overrides>, which the "
            "platform only honours for debuggable builds."
        ),
        cwe_ids=["CWE-295"],
        masvs_controls=["MASVS-NETWORK-1"],
        references=[
            ANDROID_NSC_DOC,
            "https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0020/",
        ],
    )

    def evaluate(self, context: ManifestContext) -> Iterable[RawFinding]:
        nsc = context.network_security_config
        if not nsc or not nsc.present:
            return

        trusting_domains = [rule for rule in nsc.domain_rules if rule.trust_user_cas]
        if not nsc.base_trust_user_cas and not trusting_domains:
            return

        evidence: list[Evidence] = []
        if nsc.base_trust_user_cas:
            evidence.append(
                Evidence(
                    description=(
                        'base-config trust-anchors include <certificates src="user" />, '
                        "applying to every destination"
                    ),
                    file_path=nsc.source_file,
                    kind="resource",
                )
            )
        for rule in trusting_domains:
            evidence.append(
                Evidence(
                    description=(
                        "domain-config trusts user CAs for: " + ", ".join(rule.domains[:10])
                    ),
                    file_path=nsc.source_file,
                    kind="resource",
                )
            )
        if nsc.debug_overrides_present:
            evidence.append(
                Evidence(
                    description=(
                        "A debug-overrides section also exists; trust anchors declared "
                        "there apply only to debuggable builds and are not part of this "
                        "finding"
                    ),
                    kind="resource",
                )
            )

        yield self.finding(
            affected_component=context.metadata.package_name,
            file_path=nsc.source_file,
            evidence=evidence,
            metadata={
                "base": nsc.base_trust_user_cas,
                "domains": [d.domains for d in trusting_domains],
            },
        )


register(UserCertificateTrustRule())


class CustomPermissionProtectionRule(Rule):
    meta = RuleMetadata(
        id="DS-MANIFEST-007",
        name="Custom permission uses a weak protection level",
        description=(
            "The application declares a custom permission with protectionLevel normal "
            "or dangerous and uses it to guard a component. Any application can hold "
            "such a permission, so it does not restrict access."
        ),
        category=FindingCategory.permissions,
        severity=Severity.medium,
        confidence=Confidence.high,
        engine=ENGINE,
        impact=(
            "A normal permission is granted automatically at install time to any "
            "application that requests it, and a dangerous permission only requires a "
            "user prompt. Guarding a component with either provides no meaningful "
            "protection against a malicious application on the same device."
        ),
        remediation=(
            'Declare the permission with android:protectionLevel="signature" so that '
            "only applications signed with the same key can obtain it."
        ),
        cwe_ids=["CWE-732", "CWE-280"],
        masvs_controls=["MASVS-PLATFORM-1"],
        references=[
            "https://developer.android.com/guide/topics/manifest/permission-element#plevel",
            "https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0027/",
        ],
    )

    def evaluate(self, context: ManifestContext) -> Iterable[RawFinding]:
        metadata = context.metadata
        guarded_by: dict[str, list[str]] = {}
        for component in metadata.components:
            for permission in (
                component.permission,
                component.read_permission,
                component.write_permission,
            ):
                if permission:
                    guarded_by.setdefault(permission, []).append(component.name)

        for declaration in metadata.declared_permissions:
            level = (declaration.protection_level or "normal").strip()
            if _protection_is_restrictive(level):
                continue
            users = guarded_by.get(declaration.name, [])
            if not users:
                # An unused weak custom permission is informational only.
                continue

            yield self.finding(
                title=f"Custom permission with weak protection level: {declaration.name}",
                severity=Severity.medium if level.startswith("normal") else Severity.low,
                affected_component=declaration.name,
                file_path=context.manifest_path,
                line_number=context.manifest_line_of(declaration.name),
                evidence=[
                    Evidence(
                        description=f"Permission declared with protectionLevel={level!r}",
                        snippet=(
                            f'<permission android:name="{declaration.name}" '
                            f'android:protectionLevel="{level}" />'
                        ),
                        file_path=context.manifest_path,
                        line_number=context.manifest_line_of(declaration.name),
                        kind="manifest",
                    ),
                    Evidence(
                        description=(
                            "Used to protect: "
                            + ", ".join(users[:8])
                            + (f" (+{len(users) - 8} more)" if len(users) > 8 else "")
                        ),
                        kind="manifest",
                    ),
                ],
                metadata={"protection_level": level, "guarded_components": users[:50]},
            )


register(CustomPermissionProtectionRule())


class DangerousPermissionCombinationRule(Rule):
    """Combinations of permissions that together enable a surveillance capability.

    A single dangerous permission is normal in most applications, so this rule
    only reports *combinations* that are rarely justified together.
    """

    meta = RuleMetadata(
        id="DS-MANIFEST-008",
        name="Permission combination enables broad data collection",
        description=(
            "The application requests a combination of permissions that together grant "
            "a capability well beyond what either permission provides alone."
        ),
        category=FindingCategory.permissions,
        severity=Severity.low,
        confidence=Confidence.low,
        engine=ENGINE,
        impact=(
            "The requested combination allows collection of personal data at a scope "
            "users are unlikely to expect. Whether this is appropriate depends entirely "
            "on the application's purpose."
        ),
        remediation=(
            "Review whether every permission in the combination is required. Request "
            "permissions at the point of use, prefer scoped alternatives (for example "
            "the photo picker instead of READ_MEDIA_IMAGES), and document the purpose "
            "for each one."
        ),
        cwe_ids=["CWE-250"],
        masvs_controls=["MASVS-PRIVACY-1"],
        references=[
            "https://developer.android.com/training/permissions/usage-notes",
        ],
        limitations=(
            "This is a privacy review prompt, not a vulnerability. A legitimate "
            "application may require every permission in the combination."
        ),
    )

    COMBINATIONS: tuple[tuple[str, tuple[str, ...], str], ...] = (
        (
            "Audio recording combined with background location",
            (
                "android.permission.RECORD_AUDIO",
                "android.permission.ACCESS_BACKGROUND_LOCATION",
            ),
            "allows recording audio while tracking the device location in the background",
        ),
        (
            "SMS access combined with network access",
            ("android.permission.READ_SMS", "android.permission.INTERNET"),
            "allows reading one-time passcodes from SMS and transmitting them off device",
        ),
        (
            "Contacts and call log access",
            ("android.permission.READ_CONTACTS", "android.permission.READ_CALL_LOG"),
            "allows reconstructing the user's social graph",
        ),
        (
            "Package installation with broad package visibility",
            (
                "android.permission.REQUEST_INSTALL_PACKAGES",
                "android.permission.QUERY_ALL_PACKAGES",
            ),
            "allows enumerating installed applications and prompting to install further packages",
        ),
        (
            "Accessibility-adjacent overlay and package visibility",
            (
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.QUERY_ALL_PACKAGES",
            ),
            "allows drawing over other applications while detecting which one is in "
            "the foreground, "
            "the pattern used by overlay phishing",
        ),
    )

    def evaluate(self, context: ManifestContext) -> Iterable[RawFinding]:
        held = context.metadata.permission_names()
        for title, required, explanation in self.COMBINATIONS:
            if not set(required).issubset(held):
                continue
            yield self.finding(
                title=f"Permission combination to review: {title}",
                description=(
                    f"The application requests {' and '.join(required)}, which together "
                    f"{explanation}."
                ),
                affected_component=context.metadata.package_name,
                file_path=context.manifest_path,
                evidence=[
                    Evidence(
                        description=f"Requested permission: {permission}",
                        snippet=f'<uses-permission android:name="{permission}" />',
                        file_path=context.manifest_path,
                        line_number=context.manifest_line_of(permission),
                        kind="manifest",
                    )
                    for permission in required
                ],
                metadata={"permissions": list(required)},
            )


register(DangerousPermissionCombinationRule())


class DeepLinkHandlingRule(Rule):
    meta = RuleMetadata(
        id="DS-MANIFEST-009",
        name="Browsable deep link without app link verification",
        description=(
            "An activity declares a browsable intent filter for an http or https "
            "scheme without android:autoVerify, so the link is not verified as an "
            "Android App Link."
        ),
        category=FindingCategory.component_security,
        severity=Severity.low,
        confidence=Confidence.medium,
        engine=ENGINE,
        impact=(
            "Without verification, any other application can register the same host "
            "and scheme and will be offered to the user in the disambiguation dialog. "
            "A malicious application can use this to capture links intended for this "
            "application, including links carrying authentication codes."
        ),
        remediation=(
            'Add android:autoVerify="true" to the intent filter and publish a '
            "matching assetlinks.json at https://<host>/.well-known/assetlinks.json. "
            "Treat all data arriving through a deep link as untrusted input and never "
            "use it to authenticate the user or to decide authorisation."
        ),
        cwe_ids=["CWE-939"],
        masvs_controls=["MASVS-PLATFORM-1"],
        references=[
            "https://developer.android.com/training/app-links/verify-android-applinks",
            "https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0031/",
        ],
        verification=(
            'adb shell am start -a android.intent.action.VIEW -d "<scheme>://<host>/<path>" '
            "and observe which activity receives the Intent."
        ),
    )

    WEB_SCHEMES = {"http", "https"}

    def evaluate(self, context: ManifestContext) -> Iterable[RawFinding]:
        for component in context.metadata.components:
            if component.kind not in {"activity", "activity-alias"} or not component.exported:
                continue
            for flt in component.intent_filters:
                if not flt.is_browsable:
                    continue
                schemes = set(flt.schemes())
                if not schemes:
                    continue
                web_schemes = schemes & self.WEB_SCHEMES
                custom_schemes = schemes - self.WEB_SCHEMES

                if web_schemes and not flt.auto_verify:
                    hosts = [d.get("host", "") for d in flt.data if d.get("host")]
                    yield self.finding(
                        title=f"Unverified web deep link on {component.name}",
                        severity=Severity.low,
                        affected_component=component.name,
                        file_path=context.manifest_path,
                        line_number=context.manifest_line_of(component.name),
                        evidence=[
                            Evidence(
                                description=(
                                    f"Browsable intent filter for scheme(s) "
                                    f"{', '.join(sorted(web_schemes))} "
                                    f"host(s) {', '.join(hosts[:6]) or 'any'} without autoVerify"
                                ),
                                snippet=ExportedComponentRule._component_snippet(component),
                                file_path=context.manifest_path,
                                kind="manifest",
                            )
                        ],
                        metadata={"schemes": sorted(web_schemes), "hosts": hosts[:20]},
                    )
                if custom_schemes:
                    yield self.finding(
                        title=f"Custom URL scheme deep link on {component.name}",
                        description=(
                            "The activity handles a custom URL scheme from the browser. "
                            "Custom schemes cannot be verified by the platform, so any "
                            "application may claim the same scheme."
                        ),
                        severity=Severity.low,
                        confidence=Confidence.medium,
                        affected_component=component.name,
                        file_path=context.manifest_path,
                        line_number=context.manifest_line_of(component.name),
                        impact=(
                            "Another application can register the same custom scheme and "
                            "intercept links, which matters when the scheme carries OAuth "
                            "redirects or other authentication material."
                        ),
                        remediation=(
                            "Prefer verified App Links over custom schemes for anything "
                            "security relevant. For OAuth, use PKCE and validate the "
                            "redirect, assuming the scheme may be hijacked."
                        ),
                        evidence=[
                            Evidence(
                                description=(
                                    "Custom scheme(s): " + ", ".join(sorted(custom_schemes))
                                ),
                                snippet=ExportedComponentRule._component_snippet(component),
                                file_path=context.manifest_path,
                                kind="manifest",
                            )
                        ],
                        metadata={"schemes": sorted(custom_schemes)},
                    )


register(DeepLinkHandlingRule())


class TaskHijackingRule(Rule):
    meta = RuleMetadata(
        id="DS-MANIFEST-010",
        name="Activity configuration permits task hijacking",
        description=(
            "An exported activity uses singleTask launch mode or declares a custom "
            "taskAffinity on an application with minSdkVersion below 28, a "
            "configuration that allows StrandHogg-style task hijacking."
        ),
        category=FindingCategory.component_security,
        severity=Severity.medium,
        confidence=Confidence.medium,
        engine=ENGINE,
        impact=(
            "A malicious application can place its own activity into this "
            "application's task, so that the user sees attacker-controlled UI while "
            "believing they are interacting with this application. This enables "
            "credential phishing."
        ),
        remediation=(
            'Set android:taskAffinity="" on the activity (or at application level) and '
            "avoid singleTask launch mode for exported activities. Raising "
            "minSdkVersion to 28 or above mitigates the original attack, as the "
            "platform no longer allows a new task to be reparented in this way."
        ),
        cwe_ids=["CWE-940"],
        masvs_controls=["MASVS-PLATFORM-1"],
        references=[
            "https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0030/",
        ],
        limitations=(
            "Exploitability depends on the Android version of the target device. The "
            "configuration is reported because it is the precondition for the attack."
        ),
    )

    def evaluate(self, context: ManifestContext) -> Iterable[RawFinding]:
        min_sdk = context.metadata.min_sdk or 1
        if min_sdk >= 28:
            return
        for component in context.metadata.components:
            if component.kind not in {"activity", "activity-alias"} or not component.exported:
                continue
            reasons: list[str] = []
            if (component.launch_mode or "").lower() in {"singletask", "2", "0x2"}:
                reasons.append("launchMode is singleTask")
            if component.task_affinity:
                reasons.append(f"taskAffinity is set to {component.task_affinity!r}")
            if not reasons:
                continue
            yield self.finding(
                title=f"Task hijacking precondition on {component.name}",
                affected_component=component.name,
                file_path=context.manifest_path,
                line_number=context.manifest_line_of(component.name),
                evidence=[
                    Evidence(description=reason, kind="manifest", file_path=context.manifest_path)
                    for reason in reasons
                ]
                + [
                    Evidence(
                        description=f"minSdkVersion is {min_sdk}, below the API 28 mitigation",
                        kind="manifest",
                    )
                ],
                metadata={"min_sdk": min_sdk, "launch_mode": component.launch_mode},
            )


register(TaskHijackingRule())


class SharedUserIdRule(Rule):
    meta = RuleMetadata(
        id="DS-MANIFEST-011",
        name="Application declares a shared user ID",
        description=(
            "android:sharedUserId places the application in the same Linux UID as other "
            "applications signed with the same key, so they share a sandbox and can "
            "read each other's private files."
        ),
        category=FindingCategory.manifest_configuration,
        severity=Severity.low,
        confidence=Confidence.high,
        engine=ENGINE,
        impact=(
            "The application's private data directory is reachable by every other "
            "application sharing the UID. A weakness in any one of them becomes a "
            "weakness in all of them. The attribute is deprecated from API 29."
        ),
        remediation=(
            "Remove android:sharedUserId and share data through an explicit interface "
            "such as a signature-permission-protected content provider. Migrating away "
            "requires care: changing the UID of an installed application is not "
            "possible without a reinstall."
        ),
        cwe_ids=["CWE-668"],
        masvs_controls=["MASVS-STORAGE-2"],
        references=["https://developer.android.com/guide/topics/manifest/manifest-element#uid"],
    )

    def evaluate(self, context: ManifestContext) -> Iterable[RawFinding]:
        shared = context.metadata.shared_user_id
        if not shared:
            return
        yield self.finding(
            affected_component=context.metadata.package_name,
            file_path=context.manifest_path,
            line_number=context.manifest_line_of("sharedUserId"),
            evidence=[
                Evidence(
                    description=f"Manifest declares sharedUserId={shared!r}",
                    snippet=f'<manifest android:sharedUserId="{shared}" ... >',
                    file_path=context.manifest_path,
                    kind="manifest",
                )
            ],
            metadata={"shared_user_id": shared},
        )


register(SharedUserIdRule())


class OutdatedSdkRule(Rule):
    meta = RuleMetadata(
        id="DS-MANIFEST-012",
        name="Application supports an outdated Android platform",
        description=(
            "minSdkVersion permits installation on Android releases that no longer "
            "receive security updates, and which lack platform hardening that newer "
            "releases apply by default."
        ),
        category=FindingCategory.manifest_configuration,
        severity=Severity.low,
        confidence=Confidence.high,
        engine=ENGINE,
        impact=(
            "On old platform versions the application runs without protections it "
            "would otherwise get for free, such as cleartext traffic being blocked by "
            "default (API 28), scoped storage (API 29), and the mandatory exported "
            "attribute (API 31). Known platform vulnerabilities on those releases are "
            "also unpatched."
        ),
        remediation=(
            "Raise minSdkVersion to a maintained release. Where support for older "
            "devices is a business requirement, compensate in the application: disable "
            "cleartext explicitly, avoid legacy external storage, and set exported "
            "explicitly on every component."
        ),
        cwe_ids=["CWE-1104"],
        masvs_controls=["MASVS-PLATFORM-3"],
        references=["https://developer.android.com/google/play/requirements/target-sdk"],
    )

    # API 26 (Android 8.0) and below receive no security patches.
    UNSUPPORTED_MAX_API = 26

    def evaluate(self, context: ManifestContext) -> Iterable[RawFinding]:
        min_sdk = context.metadata.min_sdk
        target_sdk = context.metadata.target_sdk
        findings_metadata = {"min_sdk": min_sdk, "target_sdk": target_sdk}

        if min_sdk is not None and min_sdk <= self.UNSUPPORTED_MAX_API:
            yield self.finding(
                title=(
                    f"minSdkVersion {min_sdk} allows installation on unsupported "
                    "Android releases"
                ),
                severity=Severity.low,
                affected_component=context.metadata.package_name,
                file_path=context.manifest_path,
                line_number=context.manifest_line_of("minSdkVersion"),
                evidence=[
                    Evidence(
                        description=(
                            f"uses-sdk declares minSdkVersion={min_sdk}; Android releases up to "
                            "API 26 no longer receive security updates"
                        ),
                        snippet=f'<uses-sdk android:minSdkVersion="{min_sdk}" '
                        f'android:targetSdkVersion="{target_sdk}" />',
                        file_path=context.manifest_path,
                        kind="manifest",
                    )
                ],
                metadata=findings_metadata,
            )

        if target_sdk is None:
            yield self.finding(
                title="targetSdkVersion is not declared",
                description=(
                    "No targetSdkVersion is declared, so the platform treats the target as "
                    "equal to minSdkVersion and applies legacy compatibility behaviour for "
                    "every API."
                ),
                severity=Severity.medium,
                affected_component=context.metadata.package_name,
                file_path=context.manifest_path,
                impact=(
                    "The application opts out of every platform security default "
                    "introduced after its minSdkVersion, including the cleartext traffic "
                    "block and scoped storage."
                ),
                remediation=(
                    "Declare targetSdkVersion explicitly and set it to a current API level."
                ),
                evidence=[
                    Evidence(
                        description="uses-sdk has no targetSdkVersion attribute",
                        file_path=context.manifest_path,
                        kind="manifest",
                    )
                ],
                metadata=findings_metadata,
            )
        elif target_sdk < 30:
            yield self.finding(
                title=f"targetSdkVersion {target_sdk} opts out of modern platform protections",
                severity=Severity.low,
                affected_component=context.metadata.package_name,
                file_path=context.manifest_path,
                line_number=context.manifest_line_of("targetSdkVersion"),
                evidence=[
                    Evidence(
                        description=(
                            f"targetSdkVersion={target_sdk}; scoped storage (API 29), the "
                            "mandatory exported attribute (API 31) and package visibility "
                            "filtering (API 30) are not enforced for this application"
                        ),
                        file_path=context.manifest_path,
                        kind="manifest",
                    )
                ],
                metadata=findings_metadata,
            )


register(OutdatedSdkRule())


class CertificateQualityRule(Rule):
    meta = RuleMetadata(
        id="DS-MANIFEST-013",
        name="Signing certificate uses a weak algorithm or key",
        description=(
            "The APK signing certificate uses a signature algorithm or key size that is "
            "no longer considered sound."
        ),
        category=FindingCategory.cryptography,
        severity=Severity.medium,
        confidence=Confidence.high,
        engine=ENGINE,
        impact=(
            "A weak signing key undermines the identity guarantee that Android's update "
            "mechanism relies on. Signature-level permissions and update authenticity "
            "both depend on the strength of this key."
        ),
        remediation=(
            "Sign releases with an RSA key of at least 2048 bits (or an EC key of at "
            "least 256 bits) using a SHA-256 or stronger signature algorithm, and enable "
            "APK signature scheme v2 or later. Use Play App Signing or key rotation "
            "(v3) to migrate away from a weak key."
        ),
        cwe_ids=["CWE-327", "CWE-326"],
        masvs_controls=["MASVS-CRYPTO-1", "MASVS-RESILIENCE-1"],
        references=[
            "https://source.android.com/docs/security/features/apksigning",
            "https://developer.android.com/studio/publish/app-signing",
        ],
    )

    WEAK_SIGNATURE_ALGOS = ("md5", "sha1", "md2")

    def evaluate(self, context: ManifestContext) -> Iterable[RawFinding]:
        for cert in context.metadata.certificates:
            problems: list[str] = []
            algo = (cert.signature_algorithm or "").lower()
            if any(weak in algo for weak in self.WEAK_SIGNATURE_ALGOS):
                problems.append(
                    f"signature algorithm is {cert.signature_algorithm!r}, which uses a "
                    "broken or deprecated hash"
                )
            key_algo = (cert.public_key_algorithm or "").lower()
            if cert.key_size_bits:
                if key_algo.startswith("rsa") and cert.key_size_bits < 2048:
                    problems.append(f"RSA key size is {cert.key_size_bits} bits, below 2048")
                elif key_algo in {"ec", "ecdsa"} and cert.key_size_bits < 256:
                    problems.append(f"EC key size is {cert.key_size_bits} bits, below 256")
                elif key_algo.startswith("dsa") and cert.key_size_bits <= 1024:
                    problems.append(f"DSA key size is {cert.key_size_bits} bits")
            if not problems:
                continue

            yield self.finding(
                title="Weak APK signing certificate",
                severity=Severity.medium,
                affected_component=cert.subject or "signing certificate",
                evidence=[
                    Evidence(
                        description=problem,
                        kind="metadata",
                        metadata={"sha256_fingerprint": cert.sha256_fingerprint},
                    )
                    for problem in problems
                ]
                + [
                    Evidence(
                        description=(
                            f"Certificate subject: {cert.subject or 'unknown'}; "
                            f"SHA-256 fingerprint: {cert.sha256_fingerprint}"
                        ),
                        kind="metadata",
                    )
                ],
                metadata={
                    "signature_algorithm": cert.signature_algorithm,
                    "key_size_bits": cert.key_size_bits,
                    "sha256_fingerprint": cert.sha256_fingerprint,
                },
            )

        if context.metadata.signature_schemes and context.metadata.signature_schemes == ["v1"]:
            yield self.finding(
                title="APK is signed only with signature scheme v1",
                description=(
                    "The APK carries only a v1 (JAR) signature. Scheme v1 does not "
                    "protect the whole archive and is vulnerable to the Janus "
                    "modification technique on older platforms."
                ),
                severity=Severity.medium,
                affected_component=context.metadata.package_name,
                impact=(
                    "On Android 5.0-8.0 an attacker can prepend a DEX file to a v1-only "
                    "APK and keep the signature valid (Janus, CVE-2017-13156), allowing "
                    "a modified application to be installed as an update."
                ),
                remediation=(
                    "Re-sign the release with APK signature scheme v2 or later using "
                    "apksigner, keeping v1 only if minSdkVersion is below 24."
                ),
                evidence=[
                    Evidence(
                        description="Only a v1 JAR signature was detected in the archive",
                        kind="metadata",
                    )
                ],
                metadata={"signature_schemes": context.metadata.signature_schemes},
            )


register(CertificateQualityRule())


class TestOnlyRule(Rule):
    meta = RuleMetadata(
        id="DS-MANIFEST-014",
        name="Application is marked test only",
        description=(
            "android:testOnly is set, which marks the build as one that may only be "
            "installed through adb with the -t flag."
        ),
        category=FindingCategory.manifest_configuration,
        severity=Severity.low,
        confidence=Confidence.high,
        engine=ENGINE,
        impact=(
            "A testOnly build is not a release artifact. Such builds commonly carry "
            "debug configuration, test endpoints and relaxed security settings, and "
            "cannot be distributed through the Play Store."
        ),
        remediation="Remove android:testOnly before producing a release build.",
        cwe_ids=["CWE-489"],
        masvs_controls=["MASVS-RESILIENCE-4"],
        references=[
            "https://developer.android.com/guide/topics/manifest/application-element#testOnly"
        ],
    )

    def evaluate(self, context: ManifestContext) -> Iterable[RawFinding]:
        if context.metadata.application_flags.test_only is not True:
            return
        yield self.finding(
            affected_component=context.metadata.package_name,
            file_path=context.manifest_path,
            line_number=context.manifest_line_of("testOnly"),
            evidence=[
                Evidence(
                    description='Application element sets android:testOnly="true"',
                    file_path=context.manifest_path,
                    kind="manifest",
                )
            ],
        )


register(TestOnlyRule())
