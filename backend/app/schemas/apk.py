"""Normalised APK metadata schema.

This is the contract between the metadata extractor, the detection rules, the
API and the report engine.  Every field distinguishes three states: a parsed
value, an explicit *absent* value (``None`` / empty list), and a parse failure
recorded in :class:`ApkMetadata.parse_errors`.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

ComponentKind = Literal["activity", "activity-alias", "service", "receiver", "provider"]


class IntentFilter(BaseModel):
    model_config = ConfigDict(extra="forbid")

    actions: list[str] = Field(default_factory=list)
    categories: list[str] = Field(default_factory=list)
    # data elements, e.g. {"scheme": "https", "host": "example.com", "path": "/x"}
    data: list[dict[str, str]] = Field(default_factory=list)
    priority: int | None = None
    auto_verify: bool = False

    @property
    def is_launcher(self) -> bool:
        return (
            "android.intent.action.MAIN" in self.actions
            and "android.intent.category.LAUNCHER" in self.categories
        )

    @property
    def is_browsable(self) -> bool:
        return "android.intent.category.BROWSABLE" in self.categories

    def schemes(self) -> list[str]:
        return [d["scheme"] for d in self.data if d.get("scheme")]


class Component(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: ComponentKind
    name: str
    exported: bool
    # True when no android:exported attribute was present and the value was
    # inferred from the platform rules for this component kind and target SDK.
    exported_implied: bool = False
    exported_attribute: bool | None = None
    enabled: bool = True
    permission: str | None = None
    read_permission: str | None = None
    write_permission: str | None = None
    process: str | None = None
    intent_filters: list[IntentFilter] = Field(default_factory=list)
    # provider only
    authorities: list[str] = Field(default_factory=list)
    grant_uri_permissions: bool = False
    path_permissions: list[dict[str, str]] = Field(default_factory=list)
    # activity only
    launch_mode: str | None = None
    task_affinity: str | None = None
    permission_protection_level: str | None = None
    attributes: dict[str, str] = Field(default_factory=dict)

    @property
    def has_intent_filter(self) -> bool:
        return bool(self.intent_filters)

    @property
    def is_launcher(self) -> bool:
        return any(f.is_launcher for f in self.intent_filters)

    def deep_links(self) -> list[dict[str, str]]:
        """Browsable intent-filter data entries, i.e. web-reachable entry points."""
        links: list[dict[str, str]] = []
        for flt in self.intent_filters:
            if not flt.is_browsable:
                continue
            for data in flt.data:
                if data.get("scheme"):
                    links.append({**data, "auto_verify": str(flt.auto_verify).lower()})
        return links


class PermissionDeclaration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    protection_level: str | None = None
    permission_group: str | None = None


class RequestedPermission(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    max_sdk_version: int | None = None
    # Populated from the bundled Android permission catalogue when known.
    protection_level: str | None = None
    is_dangerous: bool = False
    description: str | None = None


class CertificateInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subject: str | None = None
    issuer: str | None = None
    serial_number: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    signature_algorithm: str | None = None
    public_key_algorithm: str | None = None
    key_size_bits: int | None = None
    sha256_fingerprint: str | None = None
    sha1_fingerprint: str | None = None
    is_self_signed: bool | None = None
    scheme: str | None = None


class NativeLibraryEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    abi: str
    size_bytes: int


class DexEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    size_bytes: int
    sha256: str | None = None


class ApplicationFlags(BaseModel):
    model_config = ConfigDict(extra="forbid")

    debuggable: bool | None = None
    allow_backup: bool | None = None
    uses_cleartext_traffic: bool | None = None
    network_security_config: str | None = None
    test_only: bool | None = None
    backup_agent: str | None = None
    full_backup_content: str | None = None
    data_extraction_rules: str | None = None
    has_fragile_user_data: bool | None = None
    request_legacy_external_storage: bool | None = None
    allow_task_reparenting: bool | None = None
    custom_application_class: str | None = None
    extract_native_libs: bool | None = None


class ApkMetadata(BaseModel):
    """Everything DroidScope knows about an APK after static parsing."""

    model_config = ConfigDict(extra="forbid")

    package_name: str | None = None
    app_label: str | None = None
    version_name: str | None = None
    version_code: int | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    compile_sdk: int | None = None
    max_sdk: int | None = None
    install_location: str | None = None
    shared_user_id: str | None = None

    application_flags: ApplicationFlags = Field(default_factory=ApplicationFlags)
    requested_permissions: list[RequestedPermission] = Field(default_factory=list)
    declared_permissions: list[PermissionDeclaration] = Field(default_factory=list)
    components: list[Component] = Field(default_factory=list)
    features: list[dict[str, Any]] = Field(default_factory=list)
    metadata_entries: list[dict[str, str]] = Field(default_factory=list)
    queries: list[dict[str, str]] = Field(default_factory=list)

    certificates: list[CertificateInfo] = Field(default_factory=list)
    signature_schemes: list[str] = Field(default_factory=list)

    dex_files: list[DexEntry] = Field(default_factory=list)
    native_libraries: list[NativeLibraryEntry] = Field(default_factory=list)
    abis: list[str] = Field(default_factory=list)
    asset_summary: dict[str, Any] = Field(default_factory=dict)
    entry_count: int = 0
    manifest_storage_key: str | None = None
    icon_entry: str | None = None

    parser: str = "androguard"
    parser_version: str | None = None
    parse_errors: list[str] = Field(default_factory=list)
    partial: bool = False

    # -- convenience accessors used by detection rules ---------------------
    def components_of(self, kind: ComponentKind) -> list[Component]:
        return [c for c in self.components if c.kind == kind]

    def exported_components(self) -> list[Component]:
        return [c for c in self.components if c.exported]

    def permission_names(self) -> set[str]:
        return {p.name for p in self.requested_permissions}

    def declared_permission(self, name: str) -> PermissionDeclaration | None:
        for decl in self.declared_permissions:
            if decl.name == name:
                return decl
        return None

    def effective_target_sdk(self) -> int:
        # Android treats a missing targetSdkVersion as equal to minSdkVersion.
        return self.target_sdk or self.min_sdk or 1
