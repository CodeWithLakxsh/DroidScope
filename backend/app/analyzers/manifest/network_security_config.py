"""Network Security Configuration parsing.

Android's ``networkSecurityConfig`` resource decides whether cleartext traffic
is permitted and which trust anchors apply.  Reading it is what separates a real
finding ("cleartext permitted for every domain") from a false one ("cleartext
globally disabled, permitted only for 127.0.0.1 in the debug config").
"""

from __future__ import annotations

from dataclasses import dataclass, field
from xml.etree.ElementTree import Element, ParseError

from defusedxml.ElementTree import fromstring as safe_fromstring

from app.core.logging import get_logger

logger = get_logger(__name__)


@dataclass(slots=True)
class DomainRule:
    domains: list[str] = field(default_factory=list)
    include_subdomains: bool = False
    cleartext_permitted: bool | None = None
    trust_user_cas: bool = False
    trust_anchors: list[str] = field(default_factory=list)
    pin_set_expiry: str | None = None
    has_pins: bool = False

    def to_dict(self) -> dict:
        return {
            "domains": self.domains,
            "include_subdomains": self.include_subdomains,
            "cleartext_permitted": self.cleartext_permitted,
            "trust_user_cas": self.trust_user_cas,
            "trust_anchors": self.trust_anchors,
            "has_pins": self.has_pins,
            "pin_set_expiry": self.pin_set_expiry,
        }


@dataclass(slots=True)
class NetworkSecurityConfig:
    present: bool = False
    source_file: str | None = None
    base_cleartext_permitted: bool | None = None
    base_trust_user_cas: bool = False
    base_trust_anchors: list[str] = field(default_factory=list)
    debug_overrides_trust_user_cas: bool = False
    debug_overrides_present: bool = False
    domain_rules: list[DomainRule] = field(default_factory=list)
    parse_error: str | None = None

    @property
    def cleartext_domains(self) -> list[str]:
        """Domains explicitly allowed to use cleartext."""
        allowed: list[str] = []
        for rule in self.domain_rules:
            if rule.cleartext_permitted:
                allowed.extend(rule.domains)
        return allowed

    def to_dict(self) -> dict:
        return {
            "present": self.present,
            "source_file": self.source_file,
            "base_cleartext_permitted": self.base_cleartext_permitted,
            "base_trust_user_cas": self.base_trust_user_cas,
            "base_trust_anchors": self.base_trust_anchors,
            "debug_overrides_present": self.debug_overrides_present,
            "debug_overrides_trust_user_cas": self.debug_overrides_trust_user_cas,
            "domain_rules": [rule.to_dict() for rule in self.domain_rules],
            "cleartext_domains": self.cleartext_domains,
            "parse_error": self.parse_error,
        }


def _bool(value: str | None) -> bool | None:
    if value is None:
        return None
    return value.strip().lower() in {"true", "1"}


def _trust_anchor_sources(element: Element) -> tuple[list[str], bool]:
    sources: list[str] = []
    trust_user = False
    anchors = element.find("trust-anchors")
    if anchors is None:
        return sources, trust_user
    for cert in anchors.findall("certificates"):
        src = cert.get("src") or ""
        if src:
            sources.append(src)
        if src == "user":
            trust_user = True
    return sources, trust_user


def parse_network_security_config(xml_text: str, *, source_file: str | None = None) -> NetworkSecurityConfig:
    config = NetworkSecurityConfig(present=True, source_file=source_file)
    try:
        root = safe_fromstring(xml_text.encode("utf-8", errors="replace"))
    except (ParseError, ValueError) as exc:
        config.parse_error = f"network security config could not be parsed: {exc}"
        return config

    if root.tag != "network-security-config":
        config.parse_error = f"unexpected root element {root.tag!r}"
        return config

    base = root.find("base-config")
    if base is not None:
        config.base_cleartext_permitted = _bool(base.get("cleartextTrafficPermitted"))
        anchors, trust_user = _trust_anchor_sources(base)
        config.base_trust_anchors = anchors
        config.base_trust_user_cas = trust_user

    debug = root.find("debug-overrides")
    if debug is not None:
        config.debug_overrides_present = True
        _anchors, trust_user = _trust_anchor_sources(debug)
        config.debug_overrides_trust_user_cas = trust_user

    for domain_config in root.findall("domain-config"):
        rule = DomainRule(
            include_subdomains=False,
            cleartext_permitted=_bool(domain_config.get("cleartextTrafficPermitted")),
        )
        for domain in domain_config.findall("domain"):
            if domain.text:
                rule.domains.append(domain.text.strip())
            if _bool(domain.get("includeSubdomains")):
                rule.include_subdomains = True
        anchors, trust_user = _trust_anchor_sources(domain_config)
        rule.trust_anchors = anchors
        rule.trust_user_cas = trust_user
        pin_set = domain_config.find("pin-set")
        if pin_set is not None:
            rule.has_pins = bool(pin_set.findall("pin"))
            rule.pin_set_expiry = pin_set.get("expiration")
        config.domain_rules.append(rule)

    return config


def resolve_config_resource(apk, reference: str | None) -> tuple[str | None, str | None]:
    """Resolve ``@xml/network_security_config`` to decoded XML text.

    Returns ``(xml_text, resource_path)``.  The resource is AXML-encoded inside
    the APK, so androguard's AXML printer is used to decode it.
    """
    if apk is None or not reference:
        return None, None

    candidates: list[str] = []
    resolved = _resolve_reference_name(apk, reference)
    if resolved:
        # e.g. @xml/network_security_config -> res/xml/network_security_config.xml
        kind, name = resolved
        candidates.extend([f"res/{kind}/{name}.xml", f"res/{name}.xml"])
    elif not reference.startswith("@"):
        candidates.append(reference)

    try:
        files = set(apk.get_files())
    except Exception:  # noqa: BLE001
        files = set()

    # Resource shrinking can rename the file; fall back to a name search.
    if not any(candidate in files for candidate in candidates):
        candidates.extend(
            path
            for path in files
            if path.startswith("res/") and "network_security" in path.lower()
        )

    for candidate in candidates:
        if candidate not in files:
            continue
        try:
            raw = apk.get_file(candidate)
        except Exception:  # noqa: BLE001
            continue
        if not raw:
            continue
        text = _decode_resource_xml(raw)
        if text:
            return text, candidate
    return None, None


def _decode_resource_xml(raw: bytes) -> str | None:
    if raw[:2] == b"\x03\x00":  # binary AXML magic
        try:
            from androguard.core.axml import AXMLPrinter

            printer = AXMLPrinter(raw)
            decoded = printer.get_xml()
            return decoded.decode("utf-8", errors="replace") if isinstance(decoded, bytes) else str(decoded)
        except Exception as exc:  # noqa: BLE001
            logger.debug("nsc.axml_decode_failed", error=str(exc))
            return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _resolve_reference_name(apk, reference: str) -> tuple[str, str] | None:  # noqa: ANN001
    """Resolve a manifest resource reference to a (type, name) pair.

    aapt2 compiles ``android:networkSecurityConfig="@xml/foo"`` down to a
    numeric resource id such as ``@7F020000``, so the literal name is only
    recoverable through the resource table.
    """
    if not reference.startswith("@"):
        return None
    body = reference[1:]

    # Textual form: @xml/network_security_config (possibly package qualified).
    if "/" in body:
        kind, _, name = body.rpartition("/")
        kind = kind.split(":")[-1] or "xml"
        return kind, name

    # Numeric form: a hexadecimal or decimal resource id.
    try:
        resource_id = int(body, 16) if not body.isdigit() else int(body)
    except ValueError:
        return None

    try:
        resources = apk.get_android_resources()
        if resources is None:
            return None
        entry = resources.get_id(apk.get_package(), resource_id)
        if entry and entry[0] and entry[1]:
            return str(entry[0]), str(entry[1])
        xml_name = resources.get_resource_xml_name(resource_id)
        if xml_name:
            # Form: @package:type/name
            _, _, tail = xml_name.partition(":")
            kind, _, name = tail.partition("/")
            if kind and name:
                return kind, name
    except Exception as exc:  # noqa: BLE001 - resource table may be absent
        logger.debug("nsc.resource_id_unresolved", reference=reference, error=str(exc))
    return None
