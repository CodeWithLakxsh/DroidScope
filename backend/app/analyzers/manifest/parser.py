"""AndroidManifest parsing.

Androguard decodes the binary AXML into XML text; this module turns that text
into the :mod:`app.schemas.apk` model.  Parsing the XML ourselves (rather than
relying on androguard's convenience getters) is deliberate: the detection rules
need attributes androguard does not surface, in particular the *absence* of
``android:exported`` and the full intent-filter data entries.
"""

from __future__ import annotations

from typing import Any

from defusedxml.ElementTree import fromstring as safe_fromstring
from xml.etree.ElementTree import Element, ParseError

from app.core.logging import get_logger
from app.schemas.apk import (
    ApplicationFlags,
    Component,
    ComponentKind,
    IntentFilter,
    PermissionDeclaration,
    RequestedPermission,
)

logger = get_logger(__name__)

ANDROID_NS = "http://schemas.android.com/apk/res/android"
_A = f"{{{ANDROID_NS}}}"

COMPONENT_TAGS: dict[str, ComponentKind] = {
    "activity": "activity",
    "activity-alias": "activity-alias",
    "service": "service",
    "receiver": "receiver",
    "provider": "provider",
}

# Permissions flagged "dangerous" (runtime) by the platform.  Kept as a local
# catalogue so analysis works offline; sourced from the Android SDK docs.
DANGEROUS_PERMISSIONS: frozenset[str] = frozenset(
    {
        "android.permission.READ_CALENDAR",
        "android.permission.WRITE_CALENDAR",
        "android.permission.CAMERA",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.GET_ACCOUNTS",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_PHONE_STATE",
        "android.permission.READ_PHONE_NUMBERS",
        "android.permission.CALL_PHONE",
        "android.permission.ANSWER_PHONE_CALLS",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.ADD_VOICEMAIL",
        "android.permission.USE_SIP",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.BODY_SENSORS",
        "android.permission.ACTIVITY_RECOGNITION",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_WAP_PUSH",
        "android.permission.RECEIVE_MMS",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.ACCESS_MEDIA_LOCATION",
        "android.permission.READ_MEDIA_IMAGES",
        "android.permission.READ_MEDIA_VIDEO",
        "android.permission.READ_MEDIA_AUDIO",
        "android.permission.POST_NOTIFICATIONS",
        "android.permission.BLUETOOTH_SCAN",
        "android.permission.BLUETOOTH_CONNECT",
        "android.permission.BLUETOOTH_ADVERTISE",
        "android.permission.NEARBY_WIFI_DEVICES",
        "android.permission.UWB_RANGING",
        "android.permission.READ_MEDIA_VISUAL_USER_SELECTED",
    }
)

# Permissions that are signature/privileged only, or otherwise notable.
SPECIAL_PERMISSIONS: dict[str, str] = {
    "android.permission.SYSTEM_ALERT_WINDOW": "special (user grant via settings)",
    "android.permission.WRITE_SETTINGS": "special (user grant via settings)",
    "android.permission.REQUEST_INSTALL_PACKAGES": "special (user grant via settings)",
    "android.permission.MANAGE_EXTERNAL_STORAGE": "special (user grant via settings)",
    "android.permission.SCHEDULE_EXACT_ALARM": "special",
    "android.permission.QUERY_ALL_PACKAGES": "special",
    "android.permission.INSTALL_PACKAGES": "signature|privileged",
    "android.permission.MOUNT_UNMOUNT_FILESYSTEMS": "signature|privileged",
    "android.permission.READ_LOGS": "signature|privileged",
    "android.permission.WRITE_SECURE_SETTINGS": "signature|privileged",
}


def _attr(element: Element, name: str, *, namespaced: bool = True) -> str | None:
    key = f"{_A}{name}" if namespaced else name
    value = element.get(key)
    if value is None and namespaced:
        # apktool-decoded manifests sometimes carry un-namespaced attributes.
        value = element.get(name)
    return value


def _bool_attr(element: Element, name: str) -> bool | None:
    value = _attr(element, name)
    if value is None:
        return None
    lowered = value.strip().lower()
    if lowered in {"true", "1"}:
        return True
    if lowered in {"false", "0"}:
        return False
    return None


def _int_attr(element: Element, name: str) -> int | None:
    value = _attr(element, name)
    if value is None:
        return None
    text = value.strip()
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        return int(text)
    except ValueError:
        return None


def _normalise_class_name(name: str | None, package: str | None) -> str:
    if not name:
        return ""
    if name.startswith("."):
        return f"{package}{name}" if package else name
    if "." not in name and package:
        return f"{package}.{name}"
    return name


class ManifestParseError(Exception):
    pass


class ParsedManifest:
    """Structured view over a decoded AndroidManifest.xml."""

    def __init__(self, xml_text: str) -> None:
        self.xml_text = xml_text
        try:
            self.root: Element = safe_fromstring(xml_text.encode("utf-8", errors="replace"))
        except (ParseError, ValueError) as exc:
            raise ManifestParseError(f"manifest XML could not be parsed: {exc}") from exc
        if self.root.tag != "manifest":
            raise ManifestParseError(
                f"unexpected manifest root element {self.root.tag!r}"
            )
        self.package = self.root.get("package") or _attr(self.root, "package")
        self.application = self.root.find("application")

    # -- top level ---------------------------------------------------------
    def version_name(self) -> str | None:
        return _attr(self.root, "versionName")

    def version_code(self) -> int | None:
        return _int_attr(self.root, "versionCode")

    def compile_sdk(self) -> int | None:
        return _int_attr(self.root, "compileSdkVersion")

    def install_location(self) -> str | None:
        return _attr(self.root, "installLocation")

    def shared_user_id(self) -> str | None:
        return _attr(self.root, "sharedUserId")

    def sdk_versions(self) -> tuple[int | None, int | None, int | None]:
        uses_sdk = self.root.find("uses-sdk")
        if uses_sdk is None:
            return None, None, None
        return (
            _int_attr(uses_sdk, "minSdkVersion"),
            _int_attr(uses_sdk, "targetSdkVersion"),
            _int_attr(uses_sdk, "maxSdkVersion"),
        )

    def application_label(self) -> str | None:
        if self.application is None:
            return None
        label = _attr(self.application, "label")
        # Unresolved resource references are not a usable label.
        if label and label.startswith("@"):
            return None
        return label

    def icon_reference(self) -> str | None:
        if self.application is None:
            return None
        return _attr(self.application, "icon") or _attr(self.application, "roundIcon")

    def application_flags(self) -> ApplicationFlags:
        app = self.application
        if app is None:
            return ApplicationFlags()
        return ApplicationFlags(
            debuggable=_bool_attr(app, "debuggable"),
            allow_backup=_bool_attr(app, "allowBackup"),
            uses_cleartext_traffic=_bool_attr(app, "usesCleartextTraffic"),
            network_security_config=_attr(app, "networkSecurityConfig"),
            test_only=_bool_attr(app, "testOnly"),
            backup_agent=_attr(app, "backupAgent"),
            full_backup_content=_attr(app, "fullBackupContent"),
            data_extraction_rules=_attr(app, "dataExtractionRules"),
            has_fragile_user_data=_bool_attr(app, "hasFragileUserData"),
            request_legacy_external_storage=_bool_attr(app, "requestLegacyExternalStorage"),
            allow_task_reparenting=_bool_attr(app, "allowTaskReparenting"),
            custom_application_class=_normalise_class_name(_attr(app, "name"), self.package),
            extract_native_libs=_bool_attr(app, "extractNativeLibs"),
        )

    # -- permissions -------------------------------------------------------
    def requested_permissions(self) -> list[RequestedPermission]:
        results: list[RequestedPermission] = []
        seen: set[str] = set()
        for tag in ("uses-permission", "uses-permission-sdk-23"):
            for element in self.root.iter(tag):
                name = _attr(element, "name")
                if not name or name in seen:
                    continue
                seen.add(name)
                declared = self._declared_protection(name)
                results.append(
                    RequestedPermission(
                        name=name,
                        max_sdk_version=_int_attr(element, "maxSdkVersion"),
                        protection_level=declared
                        or SPECIAL_PERMISSIONS.get(name)
                        or ("dangerous" if name in DANGEROUS_PERMISSIONS else None),
                        is_dangerous=name in DANGEROUS_PERMISSIONS,
                    )
                )
        return sorted(results, key=lambda p: p.name)

    def _declared_protection(self, name: str) -> str | None:
        for element in self.root.iter("permission"):
            if _attr(element, "name") == name:
                return _attr(element, "protectionLevel")
        return None

    def declared_permissions(self) -> list[PermissionDeclaration]:
        results = []
        for element in self.root.iter("permission"):
            name = _attr(element, "name")
            if not name:
                continue
            results.append(
                PermissionDeclaration(
                    name=name,
                    protection_level=_attr(element, "protectionLevel"),
                    permission_group=_attr(element, "permissionGroup"),
                )
            )
        return results

    # -- components --------------------------------------------------------
    def components(self) -> list[Component]:
        if self.application is None:
            return []
        _min_sdk, target_sdk, _max_sdk = self.sdk_versions()
        effective_target = target_sdk or self.compile_sdk() or 0
        results: list[Component] = []
        for tag, kind in COMPONENT_TAGS.items():
            for element in self.application.iter(tag):
                results.append(self._component(element, kind, effective_target))
        return results

    def _component(self, element: Element, kind: ComponentKind, target_sdk: int) -> Component:
        name = _normalise_class_name(_attr(element, "name"), self.package)
        filters = [self._intent_filter(f) for f in element.findall("intent-filter")]
        exported_attr = _bool_attr(element, "exported")
        exported, implied = self._resolve_exported(kind, exported_attr, bool(filters), target_sdk)

        authorities: list[str] = []
        if kind == "provider":
            raw = _attr(element, "authorities") or ""
            authorities = [part for part in (p.strip() for p in raw.split(";")) if part]

        path_permissions = []
        for path_element in element.findall("path-permission"):
            entry = {
                key.replace(_A, ""): value for key, value in path_element.attrib.items()
            }
            path_permissions.append(entry)

        permission = _attr(element, "permission")
        return Component(
            kind=kind,
            name=name,
            exported=exported,
            exported_implied=implied,
            exported_attribute=exported_attr,
            enabled=_bool_attr(element, "enabled") if _bool_attr(element, "enabled") is not None else True,
            permission=permission,
            read_permission=_attr(element, "readPermission"),
            write_permission=_attr(element, "writePermission"),
            process=_attr(element, "process"),
            intent_filters=filters,
            authorities=authorities,
            grant_uri_permissions=bool(_bool_attr(element, "grantUriPermissions")),
            path_permissions=path_permissions,
            launch_mode=_attr(element, "launchMode"),
            task_affinity=_attr(element, "taskAffinity"),
            permission_protection_level=(
                self._declared_protection(permission) if permission else None
            ),
            attributes={
                key.replace(_A, "android:"): value
                for key, value in element.attrib.items()
                if key.replace(_A, "") not in {"name"}
            },
        )

    @staticmethod
    def _resolve_exported(
        kind: ComponentKind, exported_attr: bool | None, has_filters: bool, target_sdk: int
    ) -> tuple[bool, bool]:
        """Apply the platform's default-export rules.

        * If ``android:exported`` is set, that value wins.
        * Otherwise a component with an intent filter defaults to exported, and
          one without defaults to not exported.
        * Providers additionally defaulted to exported before API 17.
        * From API 31 the attribute is mandatory when an intent filter exists,
          so the installer rejects such an APK -- recorded as implied-exported
          because that configuration cannot ship.
        """
        if exported_attr is not None:
            return exported_attr, False
        if kind == "provider" and target_sdk and target_sdk < 17:
            return True, True
        return (True, True) if has_filters else (False, True)

    @staticmethod
    def _intent_filter(element: Element) -> IntentFilter:
        actions = [
            _attr(child, "name") or "" for child in element.findall("action")
        ]
        categories = [
            _attr(child, "name") or "" for child in element.findall("category")
        ]
        data_entries: list[dict[str, str]] = []
        for child in element.findall("data"):
            entry = {
                key.replace(_A, ""): value for key, value in child.attrib.items()
            }
            if entry:
                data_entries.append(entry)
        return IntentFilter(
            actions=[a for a in actions if a],
            categories=[c for c in categories if c],
            data=data_entries,
            priority=_int_attr(element, "priority"),
            auto_verify=bool(_bool_attr(element, "autoVerify")),
        )

    # -- misc --------------------------------------------------------------
    def metadata_entries(self) -> list[dict[str, str]]:
        entries: list[dict[str, str]] = []
        for element in self.root.iter("meta-data"):
            name = _attr(element, "name")
            if not name:
                continue
            entries.append(
                {
                    "name": name,
                    "value": _attr(element, "value") or "",
                    "resource": _attr(element, "resource") or "",
                }
            )
        return entries

    def features(self) -> list[dict[str, Any]]:
        features: list[dict[str, Any]] = []
        for element in self.root.iter("uses-feature"):
            name = _attr(element, "name") or _attr(element, "glEsVersion") or ""
            if not name:
                continue
            features.append({"name": name, "required": _bool_attr(element, "required") is not False})
        return features

    def queries(self) -> list[dict[str, str]]:
        """``<queries>`` entries, which reveal cross-app visibility intent."""
        results: list[dict[str, str]] = []
        for queries in self.root.iter("queries"):
            for child in queries:
                if child.tag == "package":
                    results.append({"type": "package", "value": _attr(child, "name") or ""})
                elif child.tag == "provider":
                    results.append(
                        {"type": "provider", "value": _attr(child, "authorities") or ""}
                    )
                elif child.tag == "intent":
                    actions = [_attr(a, "name") or "" for a in child.iter("action")]
                    results.append({"type": "intent", "value": ",".join(filter(None, actions))})
        return results
