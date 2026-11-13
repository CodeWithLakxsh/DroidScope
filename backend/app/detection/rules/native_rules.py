"""Native library hardening rules.

These rules consume the ELF inspection results produced by
:mod:`app.analyzers.native.elf`.  They describe compiler and linker hardening
that is missing, which is a weakness in depth rather than an exploitable bug on
its own -- the findings say so explicitly.
"""

from __future__ import annotations

from collections.abc import Iterator

from app.core.enums import Confidence, FindingCategory, Severity
from app.detection.base import Rule, RuleMetadata
from app.detection.context import NativeContext
from app.detection.model import Evidence, RawFinding
from app.detection.registry import register

ENGINE = "native-analyzer"
MASTG_BINARY = "https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0028/"


class NativeHardeningRule(Rule):
    meta = RuleMetadata(
        id="DS-NATIVE-001",
        name="Native library is missing exploit mitigations",
        description=(
            "A bundled native library was built without one or more standard "
            "mitigations. These do not create a vulnerability by themselves, but they "
            "remove the obstacles that make a memory-safety bug in the library harder "
            "to exploit."
        ),
        category=FindingCategory.native_code,
        severity=Severity.low,
        confidence=Confidence.high,
        engine=ENGINE,
        impact=(
            "Without full RELRO an attacker who can write to memory can target the GOT "
            "to redirect execution. Without stack canaries a stack buffer overflow can "
            "overwrite the return address undetected. An executable stack allows "
            "injected data to be run directly as code. Without PIE the library loads at "
            "a predictable address, which removes the benefit of ASLR."
        ),
        remediation=(
            "Rebuild with the NDK defaults, which enable these mitigations: "
            "-Wl,-z,relro,-z,now for full RELRO, -fstack-protector-strong for stack "
            "canaries, -Wl,-z,noexecstack for a non-executable stack, and -fPIE -pie "
            "(shared libraries are position independent by design). Confirm no build "
            "flag disables them, and prefer a current NDK."
        ),
        cwe_ids=["CWE-1419", "CWE-121"],
        masvs_controls=["MASVS-CODE-3"],
        references=[
            MASTG_BINARY,
            "https://developer.android.com/ndk/guides/cmake",
        ],
        limitations=(
            "Stack canary detection relies on the presence of __stack_chk_fail in the "
            "symbol table. A stripped library, or one where no function needed a "
            "canary, can be reported as missing it. Treat the canary signal as "
            "indicative rather than conclusive."
        ),
    )

    def evaluate(self, context: NativeContext) -> Iterator[RawFinding]:
        for library in context.libraries:
            if library.get("error"):
                continue
            hardening = library.get("hardening") or {}
            missing: list[tuple[str, str]] = []

            relro = hardening.get("relro")
            if relro == "none":
                missing.append(("RELRO", "the relocation table remains writable at runtime"))
            elif relro == "partial":
                missing.append(
                    ("Full RELRO", "only partial RELRO is enabled, so the GOT stays writable")
                )
            if hardening.get("stack_canary") is False:
                missing.append(
                    (
                        "Stack canaries",
                        "no __stack_chk_fail reference was found in the symbol table",
                    )
                )
            if hardening.get("nx") is False:
                missing.append(
                    ("Non-executable stack", "the PT_GNU_STACK segment is marked executable")
                )
            if hardening.get("pie") is False:
                missing.append(
                    ("Position independent code", "the ELF type is ET_EXEC rather than ET_DYN")
                )

            if not missing:
                continue

            severity = Severity.low
            if any(name == "Non-executable stack" for name, _ in missing):
                severity = Severity.medium

            path = library.get("path", "unknown")
            evidence = [
                Evidence(
                    description=f"{name} is not enabled: {detail}",
                    file_path=path,
                    kind="binary",
                    metadata={"mitigation": name},
                )
                for name, detail in missing
            ]
            evidence.append(
                Evidence(
                    description=(
                        f"Architecture {library.get('architecture', 'unknown')}, "
                        f"{library.get('size_bytes', 0)} bytes, "
                        f"{'stripped' if library.get('stripped') else 'not stripped'}"
                    ),
                    file_path=path,
                    kind="binary",
                    metadata={k: library.get(k) for k in ("architecture", "abi", "elf_type")},
                )
            )

            yield self.finding(
                title=(f"{path.split('/')[-1]} missing " + ", ".join(name for name, _ in missing)),
                severity=severity,
                affected_component=path,
                file_path=path,
                evidence=evidence,
                metadata={
                    "missing_mitigations": [name for name, _ in missing],
                    "hardening": hardening,
                    "abi": library.get("abi"),
                },
            )


register(NativeHardeningRule())


class NativeDangerousImportRule(Rule):
    meta = RuleMetadata(
        id="DS-NATIVE-002",
        name="Native library imports a memory-unsafe or process-control function",
        description=(
            "A native library imports functions that are either memory unsafe by "
            "design or that execute other programs. Their presence indicates where to "
            "focus a native code review."
        ),
        category=FindingCategory.native_code,
        severity=Severity.low,
        confidence=Confidence.medium,
        engine=ENGINE,
        impact=(
            "Functions such as strcpy, strcat, sprintf and gets perform no bounds "
            "checking, so a length assumption that does not hold becomes a buffer "
            "overflow. system, popen and the exec family run external programs, which "
            "turns any influence over their arguments into command execution within the "
            "application's sandbox."
        ),
        remediation=(
            "Replace unbounded string functions with bounded equivalents (strlcpy, "
            "snprintf) or with C++ string types, and compile with "
            "-D_FORTIFY_SOURCE=2. Remove process-execution calls, or build the argument "
            "vector from fixed values only. Fuzz the parsing entry points of the library."
        ),
        cwe_ids=["CWE-120", "CWE-676", "CWE-78"],
        masvs_controls=["MASVS-CODE-3"],
        references=[MASTG_BINARY],
        limitations=(
            "An import is not a vulnerability: these functions can be used safely. The "
            "finding marks attack surface for manual review, and cannot show whether "
            "any call site is reachable with attacker-controlled input."
        ),
    )

    UNSAFE_STRING = {
        "strcpy",
        "strcat",
        "sprintf",
        "vsprintf",
        "gets",
        "stpcpy",
        "wcscpy",
        "wcscat",
        "memcpy",
        "alloca",
    }
    PROCESS_CONTROL = {
        "system",
        "popen",
        "execl",
        "execle",
        "execlp",
        "execv",
        "execve",
        "execvp",
        "fork",
        "ptrace",
        "dlopen",
    }

    def evaluate(self, context: NativeContext) -> Iterator[RawFinding]:
        for library in context.libraries:
            if library.get("error"):
                continue
            imports = {str(name) for name in (library.get("imported_symbols") or [])}
            unsafe = sorted(imports & self.UNSAFE_STRING)
            process = sorted(imports & self.PROCESS_CONTROL)
            if not unsafe and not process:
                continue

            path = library.get("path", "unknown")
            evidence: list[Evidence] = []
            if unsafe:
                evidence.append(
                    Evidence(
                        description=(
                            "Unbounded or memory-unsafe string functions imported: "
                            + ", ".join(unsafe)
                        ),
                        file_path=path,
                        kind="binary",
                        metadata={"symbols": unsafe},
                    )
                )
            if process:
                evidence.append(
                    Evidence(
                        description=(
                            "Process control or dynamic loading functions imported: "
                            + ", ".join(process)
                        ),
                        file_path=path,
                        kind="binary",
                        metadata={"symbols": process},
                    )
                )

            severity = Severity.low
            if {"system", "popen", "execve", "ptrace"} & set(process):
                severity = Severity.medium

            yield self.finding(
                title=f"{path.split('/')[-1]} imports functions that warrant review",
                severity=severity,
                affected_component=path,
                file_path=path,
                evidence=evidence,
                metadata={"unsafe_string_functions": unsafe, "process_control": process},
            )


register(NativeDangerousImportRule())


class NativeSuspiciousStringRule(Rule):
    meta = RuleMetadata(
        id="DS-NATIVE-003",
        name="Native library contains notable embedded strings",
        description=(
            "Strings extracted from a native library reference root detection, shell "
            "paths, debugger checks or URLs. Native code is often where anti-analysis "
            "and hidden endpoints live, since it is harder to inspect than DEX."
        ),
        category=FindingCategory.native_code,
        severity=Severity.info,
        confidence=Confidence.medium,
        engine=ENGINE,
        impact=(
            "The strings themselves cause no harm. They indicate behaviour implemented "
            "in native code that a DEX-only review would miss: root or debugger "
            "detection affects how the application behaves under analysis, and an "
            "endpoint reachable only from native code may not appear anywhere in the "
            "Java sources."
        ),
        remediation=(
            "No action is required for this observation. Confirm that any endpoint "
            "found here is expected, and that root or emulator detection is a "
            "deliberate control rather than an attempt to hinder authorised review."
        ),
        cwe_ids=[],
        masvs_controls=["MASVS-RESILIENCE-1"],
        references=[MASTG_BINARY],
        limitations=(
            "String extraction has no context: a match does not prove the string is "
            "used, and obfuscated or encrypted strings will not appear at all."
        ),
    )

    def evaluate(self, context: NativeContext) -> Iterator[RawFinding]:
        for library in context.libraries:
            categories = library.get("suspicious_strings") or {}
            if not categories:
                continue
            path = library.get("path", "unknown")
            evidence = [
                Evidence(
                    description=f"{category}: {', '.join(values[:6])}",
                    file_path=path,
                    kind="binary",
                    metadata={"category": category, "values": values[:20]},
                )
                for category, values in sorted(categories.items())
                if values
            ]
            if not evidence:
                continue
            yield self.finding(
                title=f"Notable strings in {path.split('/')[-1]}",
                affected_component=path,
                file_path=path,
                evidence=evidence,
                metadata={"categories": sorted(categories)},
            )


register(NativeSuspiciousStringRule())
