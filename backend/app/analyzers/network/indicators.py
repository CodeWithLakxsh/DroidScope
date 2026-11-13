"""Network indicator extraction.

Indicators are extracted from the APK's own contents -- DEX string pools,
resources, assets and native libraries -- and *classified*.  Classification is
the point: a loopback address, an RFC 1918 range, a documentation domain and a
public host each mean something different, and reporting them identically is how
scanners produce unusable output.

DroidScope never resolves, connects to, or scans an extracted indicator.
"""

from __future__ import annotations

import ipaddress
import re
import zipfile
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from app.core.logging import get_logger

logger = get_logger(__name__)

URL_PATTERN = re.compile(
    rb"(?:https?|ftp|ws|wss)://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,512}"
)
DOMAIN_PATTERN = re.compile(
    rb"(?<![A-Za-z0-9.\-])"
    rb"(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+"
    rb"(?:com|net|org|io|co|dev|app|cloud|ai|me|info|biz|xyz|site|online|tech|"
    rb"api|gov|edu|mil|int|eu|uk|us|de|fr|jp|cn|in|ru|br|au|ca|nl|se|no|ch|es|it)"
    rb"(?![A-Za-z0-9\-])"
)
IPV4_PATTERN = re.compile(rb"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])")

# Hosts that are definitionally not an operator endpoint.
RESERVED_DOMAINS = {
    "example.com", "example.org", "example.net", "localhost", "localhost.localdomain",
    "test.com", "invalid", "local",
}
# Infrastructure and documentation hosts that appear in every Android app.
NOISE_HOSTS = {
    "schemas.android.com", "www.w3.org", "w3.org", "java.sun.com", "xml.org",
    "apache.org", "www.apache.org", "github.com", "developer.android.com",
    "android.com", "xmlpull.org", "json.org", "slf4j.org", "jquery.com",
    "googleapis.com", "gstatic.com", "goo.gl", "bit.ly", "purl.org",
    "ns.adobe.com", "iptc.org", "npes.org", "aiim.org", "fonts.gstatic.com",
}
NOISE_SUFFIXES = (".w3.org", ".apache.org", ".android.com", ".sun.com", ".iana.org")

# RFC 5737 (IPv4) and RFC 3849 (IPv6) documentation ranges.
DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)

BINARY_SUFFIXES = {".so", ".dex", ".bin", ".dat", ".pak"}
TEXT_SUFFIXES = {".xml", ".json", ".txt", ".properties", ".js", ".html", ".css", ".csv"}
MAX_ENTRY_BYTES = 48 * 1024 * 1024
MAX_INDICATORS = 4000
CONTEXT_WINDOW = 60


@dataclass(slots=True)
class Indicator:
    indicator_type: str  # url | domain | ip | endpoint
    value: str
    scope: str = "unknown"
    scheme: str | None = None
    host: str | None = None
    port: int | None = None
    source_file: str | None = None
    context: str | None = None
    occurrences: int = 1
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "indicator_type": self.indicator_type,
            "value": self.value,
            "scope": self.scope,
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "source_file": self.source_file,
            "context": self.context,
            "occurrences": self.occurrences,
            "detail": self.detail,
        }


def classify_host(host: str) -> str:
    """Classify a host or address into a routing scope."""
    if not host:
        return "unknown"
    candidate = host.strip("[]").lower()

    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        if candidate in {"localhost", "localhost.localdomain"}:
            return "loopback"
        if candidate.startswith("example.") or candidate in {"test.com"}:
            return "documentation"
        if candidate in RESERVED_DOMAINS or candidate.endswith((".local", ".invalid", ".internal")):
            return "reserved"
        return "public"

    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link-local"
    if address.is_multicast:
        return "multicast"
    if address.is_unspecified:
        return "unspecified"
    # Checked before is_private: Python counts the RFC 5737 / RFC 3849
    # documentation ranges as private, but they mean something different --
    # they are placeholders, not an operator's internal infrastructure.
    if any(address in network for network in DOCUMENTATION_NETWORKS):
        return "documentation"
    if address.is_private:
        return "private"
    if address.is_reserved:
        return "reserved"
    return "public"


def is_noise_host(host: str) -> bool:
    lowered = host.lower()
    if lowered in NOISE_HOSTS:
        return True
    return lowered.endswith(NOISE_SUFFIXES)


class IndicatorExtractor:
    """Extract and classify network indicators from an APK."""

    def __init__(self, *, max_indicators: int = MAX_INDICATORS) -> None:
        self.max_indicators = max_indicators
        self.entries_scanned = 0
        self.entries_skipped = 0
        self.bytes_scanned = 0

    def extract_from_apk(self, apk_path: Path) -> list[Indicator]:
        aggregated: dict[tuple[str, str], Indicator] = {}
        try:
            with zipfile.ZipFile(apk_path) as archive:
                for info in archive.infolist():
                    if info.is_dir():
                        continue
                    if not self._should_scan(info.filename):
                        continue
                    if info.file_size > MAX_ENTRY_BYTES:
                        self.entries_skipped += 1
                        continue
                    try:
                        with archive.open(info) as handle:
                            data = handle.read()
                    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
                        logger.debug("indicators.entry_unreadable", entry=info.filename, error=str(exc))
                        self.entries_skipped += 1
                        continue
                    self.entries_scanned += 1
                    self.bytes_scanned += len(data)
                    self._merge(aggregated, self.extract_from_bytes(data, info.filename))
                    if len(aggregated) >= self.max_indicators:
                        break
        except (OSError, zipfile.BadZipFile) as exc:
            logger.warning("indicators.archive_unreadable", error=str(exc))
        return sorted(
            aggregated.values(),
            key=lambda ind: (-ind.occurrences, ind.indicator_type, ind.value),
        )

    def extract_from_directory(self, root: Path) -> list[Indicator]:
        """Extract indicators from a decompiled source tree."""
        aggregated: dict[tuple[str, str], Indicator] = {}
        if not root.is_dir():
            return []
        for path in root.rglob("*"):
            if not path.is_file() or path.is_symlink():
                continue
            if path.suffix.lower() not in TEXT_SUFFIXES | {".java", ".kt", ".smali"}:
                continue
            if path.stat().st_size > MAX_ENTRY_BYTES:
                continue
            try:
                data = path.read_bytes()
            except OSError:
                continue
            self.entries_scanned += 1
            self.bytes_scanned += len(data)
            relative = str(path.relative_to(root))
            self._merge(aggregated, self.extract_from_bytes(data, relative))
            if len(aggregated) >= self.max_indicators:
                break
        return sorted(
            aggregated.values(),
            key=lambda ind: (-ind.occurrences, ind.indicator_type, ind.value),
        )

    def extract_from_bytes(self, data: bytes, source_file: str) -> list[Indicator]:
        found: list[Indicator] = []
        seen_values: set[str] = set()

        for match in URL_PATTERN.finditer(data):
            raw = match.group(0).decode("utf-8", errors="replace").rstrip(".,;:'\")]}")
            if raw in seen_values:
                continue
            seen_values.add(raw)
            indicator = self._url_indicator(raw, source_file, data, match.start())
            if indicator:
                found.append(indicator)

        for match in IPV4_PATTERN.finditer(data):
            raw = match.group(1).decode("ascii", errors="replace")
            if raw in seen_values:
                continue
            try:
                ipaddress.ip_address(raw)
            except ValueError:
                continue
            # Version strings and resource ids look like addresses.
            if self._looks_like_version(data, match.start(), match.end()):
                continue
            seen_values.add(raw)
            found.append(
                Indicator(
                    indicator_type="ip",
                    value=raw,
                    host=raw,
                    scope=classify_host(raw),
                    source_file=source_file,
                    context=self._context(data, match.start(), match.end()),
                )
            )

        for match in DOMAIN_PATTERN.finditer(data):
            raw = match.group(0).decode("ascii", errors="replace").lower().rstrip(".")
            if raw in seen_values or is_noise_host(raw):
                continue
            # Skip a domain already captured as part of a URL.
            if any(raw in value for value in seen_values):
                continue
            seen_values.add(raw)
            found.append(
                Indicator(
                    indicator_type="domain",
                    value=raw,
                    host=raw,
                    scope=classify_host(raw),
                    source_file=source_file,
                    context=self._context(data, match.start(), match.end()),
                )
            )
        return found

    # -- internals ---------------------------------------------------------
    @staticmethod
    def _should_scan(name: str) -> bool:
        lowered = name.lower()
        suffix = Path(lowered).suffix
        if lowered.startswith("classes") and lowered.endswith(".dex"):
            return True
        if lowered.startswith("lib/") and suffix == ".so":
            return True
        if lowered == "androidmanifest.xml":
            return True
        if lowered.startswith(("res/", "assets/")):
            return suffix in TEXT_SUFFIXES or suffix in BINARY_SUFFIXES or suffix == ""
        if lowered == "resources.arsc":
            return True
        return suffix in TEXT_SUFFIXES

    def _url_indicator(
        self, raw: str, source_file: str, data: bytes, offset: int
    ) -> Indicator | None:
        try:
            parts = urlsplit(raw)
        except ValueError:
            return None
        host = (parts.hostname or "").lower()
        if not host or is_noise_host(host):
            return None
        port: int | None
        try:
            port = parts.port
        except ValueError:
            port = None
        return Indicator(
            indicator_type="url",
            value=raw[:2048],
            scheme=parts.scheme,
            host=host,
            port=port,
            scope=classify_host(host),
            source_file=source_file,
            context=self._context(data, offset, offset + len(raw)),
            detail={"path": parts.path[:256]} if parts.path not in {"", "/"} else {},
        )

    @staticmethod
    def _looks_like_version(data: bytes, start: int, end: int) -> bool:
        window = data[max(start - 24, 0) : end + 12].lower()
        return any(
            marker in window
            for marker in (b"version", b"sdk_int", b"build", b"v=", b"ver ", b"@dimen")
        )

    @staticmethod
    def _context(data: bytes, start: int, end: int) -> str:
        left = max(start - CONTEXT_WINDOW, 0)
        right = min(end + CONTEXT_WINDOW, len(data))
        window = data[left:right]
        text = window.decode("utf-8", errors="replace")
        printable = "".join(ch if ch.isprintable() or ch == " " else "." for ch in text)
        return printable.strip()[:200]

    @staticmethod
    def _merge(
        aggregated: dict[tuple[str, str], Indicator], indicators: list[Indicator]
    ) -> None:
        for indicator in indicators:
            key = (indicator.indicator_type, indicator.value)
            existing = aggregated.get(key)
            if existing is None:
                aggregated[key] = indicator
            else:
                existing.occurrences += 1
                if existing.source_file != indicator.source_file:
                    sources = existing.detail.setdefault("additional_sources", [])
                    if indicator.source_file and indicator.source_file not in sources and len(sources) < 10:
                        sources.append(indicator.source_file)


def summarise(indicators: list[Indicator]) -> dict[str, Any]:
    by_scope: dict[str, int] = defaultdict(int)
    by_type: dict[str, int] = defaultdict(int)
    for indicator in indicators:
        by_scope[indicator.scope] += 1
        by_type[indicator.indicator_type] += 1
    hosts = sorted({ind.host for ind in indicators if ind.host and ind.scope == "public"})
    return {
        "total": len(indicators),
        "by_scope": dict(by_scope),
        "by_type": dict(by_type),
        "distinct_public_hosts": len(hosts),
        "cleartext_urls": sum(1 for ind in indicators if ind.scheme == "http"),
    }
