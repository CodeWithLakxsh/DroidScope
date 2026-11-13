"""Analyzer registry and profile composition."""

from __future__ import annotations

from app.analyzers.base import Analyzer
from app.analyzers.manifest.analyzer import ManifestAnalyzer
from app.analyzers.native.analyzer import NativeAnalyzer
from app.analyzers.network.analyzer import IndicatorAnalyzer
from app.analyzers.source.analyzer import SourceAnalyzer
from app.analyzers.source.resources import ResourceAnalyzer
from app.analyzers.yara.analyzer import YaraAnalyzer
from app.core.enums import ScanProfile

# Order matters: analyzers that publish shared data run before their consumers.
# The source analyzer is placed after the cheap ones so a quick failure in
# decompilation does not delay manifest results.
ANALYZER_CLASSES: tuple[type[Analyzer], ...] = (
    ManifestAnalyzer,
    IndicatorAnalyzer,
    ResourceAnalyzer,
    SourceAnalyzer,
    NativeAnalyzer,
    YaraAnalyzer,
)


def build_analyzers(profile: ScanProfile) -> list[Analyzer]:
    """Instantiate the analyzers that belong to ``profile``."""
    analyzers: list[Analyzer] = []
    for analyzer_cls in ANALYZER_CLASSES:
        analyzer = analyzer_cls()
        if analyzer.applies_to(profile):
            analyzers.append(analyzer)
    return analyzers


def all_analyzers() -> list[Analyzer]:
    return [analyzer_cls() for analyzer_cls in ANALYZER_CLASSES]


PROFILE_DESCRIPTIONS: dict[ScanProfile, str] = {
    ScanProfile.quick: (
        "Validation, metadata, permissions, manifest rules and network indicators. "
        "No decompilation, so it completes in seconds."
    ),
    ScanProfile.standard: (
        "Everything in quick, plus JADX decompilation with source, secret and Firebase "
        "rules, apktool resource decoding, native ELF inspection and YARA scanning."
    ),
    ScanProfile.full: (
        "Everything in standard, plus Ghidra headless analysis of the largest native "
        "library where Ghidra is installed, and extended correlation in reporting."
    ),
}
