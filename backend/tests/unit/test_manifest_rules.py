"""Manifest rule behaviour.

These tests assert the *nuance* that separates a usable scanner from a noisy
one: a signature-protected exported component is not reported, a launcher
activity is informational, and cleartext findings respect the network security
configuration.
"""

from __future__ import annotations

import pytest

from app.analyzers.manifest.network_security_config import parse_network_security_config
from app.analyzers.manifest.parser import ParsedManifest, decode_protection_level
from app.core.enums import Confidence, Severity
from app.detection.context import ManifestContext
from app.detection.registry import load_builtin_rules, registry
from app.schemas.apk import ApkMetadata

ANDROID_NS = 'xmlns:android="http://schemas.android.com/apk/res/android"'


def build_manifest(application_attributes: str = "", body: str = "", sdk: str = "") -> str:
    uses_sdk = sdk or '<uses-sdk android:minSdkVersion="24" android:targetSdkVersion="33" />'
    return f"""<?xml version="1.0" encoding="utf-8"?>
<manifest {ANDROID_NS} package="com.example.app" android:versionName="1.0" android:versionCode="1">
  {uses_sdk}
  <application android:label="Example" {application_attributes}>
    {body}
  </application>
</manifest>"""


def context_for(manifest_xml: str, *, nsc_xml: str | None = None) -> ManifestContext:
    parsed = ParsedManifest(manifest_xml)
    min_sdk, target_sdk, max_sdk = parsed.sdk_versions()
    metadata = ApkMetadata(
        package_name=parsed.package,
        version_name=parsed.version_name(),
        version_code=parsed.version_code(),
        min_sdk=min_sdk,
        target_sdk=target_sdk,
        max_sdk=max_sdk,
        application_flags=parsed.application_flags(),
        requested_permissions=parsed.requested_permissions(),
        declared_permissions=parsed.declared_permissions(),
        components=parsed.components(),
    )
    nsc = parse_network_security_config(nsc_xml) if nsc_xml else None
    return ManifestContext(
        metadata=metadata, manifest_xml=manifest_xml, network_security_config=nsc
    )


def run_rule(rule_id: str, context: ManifestContext) -> list:
    load_builtin_rules()
    rule = registry.get(rule_id)
    assert rule is not None, f"{rule_id} is not registered"
    return list(rule.evaluate(context))


class TestProtectionLevelDecoding:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("0x00000000", "normal"),
            ("0x00000001", "dangerous"),
            ("0x00000002", "signature"),
            ("0x00000012", "signature|privileged"),
            ("signature", "signature"),
            (None, None),
        ],
    )
    def test_decodes_numeric_and_textual(self, raw, expected) -> None:
        assert decode_protection_level(raw) == expected


class TestExportedComponents:
    def test_reports_an_unprotected_exported_activity(self) -> None:
        context = context_for(
            build_manifest(body='<activity android:name=".Open" android:exported="true" />')
        )
        findings = run_rule("DS-MANIFEST-001", context)
        assert len(findings) == 1
        assert "Open" in findings[0].affected_component

    def test_ignores_a_signature_protected_component(self) -> None:
        """A signature-level permission genuinely restricts access."""
        manifest = f"""<?xml version="1.0" encoding="utf-8"?>
<manifest {ANDROID_NS} package="com.example.app">
  <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="33" />
  <permission android:name="com.example.app.permission.PRIVATE"
              android:protectionLevel="signature" />
  <application android:label="Example">
    <service android:name=".Guarded" android:exported="true"
             android:permission="com.example.app.permission.PRIVATE" />
  </application>
</manifest>"""
        assert run_rule("DS-MANIFEST-001", context_for(manifest)) == []

    def test_reports_a_component_guarded_by_a_normal_permission(self) -> None:
        """A normal permission is granted to anyone who asks, so it is no guard."""
        manifest = f"""<?xml version="1.0" encoding="utf-8"?>
<manifest {ANDROID_NS} package="com.example.app">
  <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="33" />
  <permission android:name="com.example.app.permission.WEAK"
              android:protectionLevel="normal" />
  <application android:label="Example">
    <receiver android:name=".Weak" android:exported="true"
              android:permission="com.example.app.permission.WEAK" />
  </application>
</manifest>"""
        findings = run_rule("DS-MANIFEST-001", context_for(manifest))
        assert len(findings) == 1
        assert any("does not restrict" in item.description for item in findings[0].evidence)

    def test_launcher_activity_is_informational(self) -> None:
        body = """<activity android:name=".Main" android:exported="true">
            <intent-filter>
              <action android:name="android.intent.action.MAIN" />
              <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
          </activity>"""
        findings = run_rule("DS-MANIFEST-001", context_for(build_manifest(body=body)))
        assert len(findings) == 1
        assert findings[0].severity == Severity.info

    def test_non_exported_component_is_not_reported(self) -> None:
        context = context_for(
            build_manifest(body='<activity android:name=".Closed" android:exported="false" />')
        )
        assert run_rule("DS-MANIFEST-001", context) == []

    def test_component_without_filters_defaults_to_not_exported(self) -> None:
        context = context_for(build_manifest(body='<service android:name=".Internal" />'))
        assert run_rule("DS-MANIFEST-001", context) == []

    def test_implied_export_lowers_confidence_on_modern_targets(self) -> None:
        """From API 31 the attribute is mandatory, so an implied export is suspect."""
        body = """<receiver android:name=".Implied">
            <intent-filter><action android:name="com.example.ACTION" /></intent-filter>
          </receiver>"""
        context = context_for(
            build_manifest(
                body=body,
                sdk='<uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34" />',
            )
        )
        findings = run_rule("DS-MANIFEST-001", context)
        assert len(findings) == 1
        assert findings[0].confidence == Confidence.medium


class TestProviderRule:
    def test_reports_an_unprotected_provider(self) -> None:
        body = (
            '<provider android:name=".Data" android:authorities="com.example.app.data" '
            'android:exported="true" />'
        )
        findings = run_rule("DS-MANIFEST-002", context_for(build_manifest(body=body)))
        assert len(findings) == 1
        assert findings[0].severity == Severity.high

    def test_ignores_a_fully_protected_provider(self) -> None:
        manifest = f"""<?xml version="1.0" encoding="utf-8"?>
<manifest {ANDROID_NS} package="com.example.app">
  <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="33" />
  <permission android:name="com.example.app.permission.DATA"
              android:protectionLevel="signature" />
  <application android:label="Example">
    <provider android:name=".Data" android:authorities="com.example.app.data"
              android:exported="true"
              android:readPermission="com.example.app.permission.DATA"
              android:writePermission="com.example.app.permission.DATA" />
  </application>
</manifest>"""
        assert run_rule("DS-MANIFEST-002", context_for(manifest)) == []


class TestDebuggable:
    def test_reports_debuggable(self) -> None:
        context = context_for(build_manifest(application_attributes='android:debuggable="true"'))
        findings = run_rule("DS-MANIFEST-003", context)
        assert len(findings) == 1
        assert findings[0].severity == Severity.high

    def test_silent_when_not_debuggable(self) -> None:
        context = context_for(build_manifest(application_attributes='android:debuggable="false"'))
        assert run_rule("DS-MANIFEST-003", context) == []


class TestBackup:
    def test_explicit_backup_outranks_the_default(self) -> None:
        explicit = run_rule(
            "DS-MANIFEST-004",
            context_for(build_manifest(application_attributes='android:allowBackup="true"')),
        )
        implicit = run_rule("DS-MANIFEST-004", context_for(build_manifest()))
        assert explicit[0].severity == Severity.medium
        assert implicit[0].severity == Severity.low

    def test_disabled_backup_is_not_reported(self) -> None:
        context = context_for(build_manifest(application_attributes='android:allowBackup="false"'))
        assert run_rule("DS-MANIFEST-004", context) == []

    def test_backup_rules_lower_confidence(self) -> None:
        context = context_for(
            build_manifest(
                application_attributes='android:allowBackup="true" android:dataExtractionRules="@xml/rules"'
            )
        )
        findings = run_rule("DS-MANIFEST-004", context)
        assert findings[0].confidence == Confidence.low


class TestCleartext:
    def test_reports_explicit_cleartext_attribute(self) -> None:
        context = context_for(
            build_manifest(application_attributes='android:usesCleartextTraffic="true"')
        )
        findings = run_rule("DS-MANIFEST-005", context)
        assert len(findings) == 1

    def test_silent_when_config_blocks_cleartext(self) -> None:
        nsc = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
  <base-config cleartextTrafficPermitted="false" />
</network-security-config>"""
        assert run_rule("DS-MANIFEST-005", context_for(build_manifest(), nsc_xml=nsc)) == []

    def test_localhost_only_exception_is_low_severity(self) -> None:
        """A loopback exception is the normal local-development pattern."""
        nsc = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
  <base-config cleartextTrafficPermitted="false" />
  <domain-config cleartextTrafficPermitted="true">
    <domain>localhost</domain>
    <domain>10.0.2.2</domain>
  </domain-config>
</network-security-config>"""
        findings = run_rule("DS-MANIFEST-005", context_for(build_manifest(), nsc_xml=nsc))
        assert len(findings) == 1
        assert findings[0].severity == Severity.low

    def test_real_domain_exception_is_medium(self) -> None:
        nsc = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
  <base-config cleartextTrafficPermitted="false" />
  <domain-config cleartextTrafficPermitted="true">
    <domain>api.production.example</domain>
  </domain-config>
</network-security-config>"""
        findings = run_rule("DS-MANIFEST-005", context_for(build_manifest(), nsc_xml=nsc))
        assert findings[0].severity == Severity.medium

    def test_modern_target_without_overrides_is_silent(self) -> None:
        context = context_for(
            build_manifest(
                sdk='<uses-sdk android:minSdkVersion="28" android:targetSdkVersion="34" />'
            )
        )
        assert run_rule("DS-MANIFEST-005", context) == []


class TestUserCertificateTrust:
    def test_reports_user_ca_trust_in_base_config(self) -> None:
        nsc = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
  <base-config>
    <trust-anchors>
      <certificates src="system" />
      <certificates src="user" />
    </trust-anchors>
  </base-config>
</network-security-config>"""
        assert len(run_rule("DS-MANIFEST-006", context_for(build_manifest(), nsc_xml=nsc))) == 1

    def test_debug_overrides_are_not_reported(self) -> None:
        """Trust declared in debug-overrides only applies to debuggable builds."""
        nsc = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
  <base-config><trust-anchors><certificates src="system" /></trust-anchors></base-config>
  <debug-overrides>
    <trust-anchors><certificates src="user" /></trust-anchors>
  </debug-overrides>
</network-security-config>"""
        assert run_rule("DS-MANIFEST-006", context_for(build_manifest(), nsc_xml=nsc)) == []


class TestDeepLinks:
    def test_reports_unverified_web_link(self) -> None:
        body = """<activity android:name=".Deep" android:exported="true">
            <intent-filter>
              <action android:name="android.intent.action.VIEW" />
              <category android:name="android.intent.category.BROWSABLE" />
              <data android:scheme="https" android:host="example.com" />
            </intent-filter>
          </activity>"""
        findings = run_rule("DS-MANIFEST-009", context_for(build_manifest(body=body)))
        assert any("Unverified web deep link" in finding.title for finding in findings)

    def test_autoverify_suppresses_the_web_link_finding(self) -> None:
        body = """<activity android:name=".Deep" android:exported="true">
            <intent-filter android:autoVerify="true">
              <action android:name="android.intent.action.VIEW" />
              <category android:name="android.intent.category.BROWSABLE" />
              <data android:scheme="https" android:host="example.com" />
            </intent-filter>
          </activity>"""
        findings = run_rule("DS-MANIFEST-009", context_for(build_manifest(body=body)))
        assert not any("Unverified web deep link" in finding.title for finding in findings)


class TestSdkRules:
    def test_reports_missing_target_sdk(self) -> None:
        context = context_for(build_manifest(sdk='<uses-sdk android:minSdkVersion="21" />'))
        findings = run_rule("DS-MANIFEST-012", context)
        assert any("targetSdkVersion is not declared" in f.title for f in findings)

    def test_current_sdk_levels_are_silent(self) -> None:
        context = context_for(
            build_manifest(
                sdk='<uses-sdk android:minSdkVersion="28" android:targetSdkVersion="34" />'
            )
        )
        assert run_rule("DS-MANIFEST-012", context) == []
