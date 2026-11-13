"""Manifest analyzer: evaluates the structural manifest rules."""

from __future__ import annotations

from app.analyzers.base import AnalysisInput, Analyzer, AnalyzerResult, ArtifactRef
from app.analyzers.manifest.network_security_config import (
    NetworkSecurityConfig,
    parse_network_security_config,
    resolve_config_resource,
)
from app.core.enums import AnalyzerStatus
from app.core.logging import get_logger
from app.detection.context import ManifestContext
from app.detection.registry import registry

logger = get_logger(__name__)


class ManifestAnalyzer(Analyzer):
    name = "manifest-analyzer"
    version = "1"
    required_capabilities = ("androguard",)
    description = (
        "Evaluates the AndroidManifest and network security configuration against "
        "structural rules that account for component kind, target SDK and permission "
        "protection levels."
    )

    async def analyze(self, data: AnalysisInput) -> AnalyzerResult:
        result = AnalyzerResult(analyzer=self.name, status=AnalyzerStatus.completed)

        nsc = self._load_network_security_config(data, result)
        manifest_key: str | None = None

        if data.manifest_xml:
            stored = data.store.write_text(
                data.store.scan_key(data.scan_id, "manifest", "AndroidManifest.xml"),
                data.manifest_xml,
            )
            manifest_key = stored.storage_key
            result.artifacts.append(
                ArtifactRef(
                    kind="manifest",
                    storage_key=stored.storage_key,
                    size_bytes=stored.size_bytes,
                    entry_count=1,
                    detail={"format": "xml", "decoder": "androguard-axml"},
                )
            )
        else:
            result.limitations.append(
                "AndroidManifest.xml could not be decoded, so manifest rules ran "
                "against metadata recovered by other means and may be incomplete"
            )

        context = ManifestContext(
            metadata=data.metadata,
            manifest_xml=data.manifest_xml,
            network_security_config=nsc,
            source_available=bool(data.shared.get("source_root")),
        )

        rules = registry.for_engine(self.name)
        evaluated = 0
        rule_errors: list[str] = []
        for rule in rules:
            try:
                result.findings.extend(rule.evaluate(context))
                evaluated += 1
            except Exception as exc:  # noqa: BLE001 - one bad rule must not stop the rest
                logger.exception("manifest_rule.failed", rule=rule.meta.id)
                rule_errors.append(f"{rule.meta.id}: {type(exc).__name__}: {exc}")

        if nsc and nsc.parse_error:
            result.limitations.append(nsc.parse_error)

        result.detail = {
            "rules_evaluated": evaluated,
            "rules_available": len(rules),
            "rule_errors": rule_errors,
            "components_examined": len(data.metadata.components),
            "exported_components": len(data.metadata.exported_components()),
            "permissions_requested": len(data.metadata.requested_permissions),
            "network_security_config": nsc.to_dict() if nsc else {"present": False},
            "manifest_storage_key": manifest_key,
        }
        result.shared = {"network_security_config": nsc.to_dict() if nsc else None}
        if rule_errors:
            result.error = f"{len(rule_errors)} rule(s) raised an error"
        return result

    def _load_network_security_config(
        self, data: AnalysisInput, result: AnalyzerResult
    ) -> NetworkSecurityConfig | None:
        reference = data.metadata.application_flags.network_security_config
        if not reference:
            return NetworkSecurityConfig(present=False)

        apk = data.shared.get("androguard_apk")
        if apk is None:
            try:
                from app.analyzers.apk.metadata import load_androguard_apk

                apk = load_androguard_apk(data.apk_path)
                data.shared["androguard_apk"] = apk
            except Exception as exc:  # noqa: BLE001
                result.limitations.append(
                    f"network security configuration {reference!r} could not be read: {exc}"
                )
                return NetworkSecurityConfig(present=False, parse_error=str(exc))

        xml_text, resource_path = resolve_config_resource(apk, reference)
        if not xml_text:
            result.limitations.append(
                f"the manifest references the network security configuration "
                f"{reference!r} but the resource could not be decoded, so cleartext "
                "and trust-anchor rules were evaluated without it"
            )
            return NetworkSecurityConfig(
                present=False,
                parse_error=f"resource {reference!r} could not be resolved",
            )

        config = parse_network_security_config(xml_text, source_file=resource_path)
        stored = data.store.write_text(
            data.store.scan_key(data.scan_id, "manifest", "network_security_config.xml"),
            xml_text,
        )
        result.artifacts.append(
            ArtifactRef(
                kind="network-security-config",
                storage_key=stored.storage_key,
                size_bytes=stored.size_bytes,
                entry_count=1,
                detail={"resource": resource_path},
            )
        )
        return config
