"""SARIF 2.1.0 rendering.

SARIF lets DroidScope findings land in code-scanning tooling. Only findings with
a file location are given a physical location; manifest and binary findings
carry their component in the message and properties instead, rather than being
given a fabricated line number.
"""

from __future__ import annotations

from typing import Any

from app import __version__

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# SARIF levels are a fixed vocabulary; DroidScope severities map onto them and
# the original severity is preserved in properties.
LEVEL_BY_SEVERITY = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def render_sarif(document: dict[str, Any]) -> dict[str, Any]:
    findings = document.get("findings", [])
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in findings:
        rule_id = finding["rule_id"]
        if rule_id not in rules:
            rules[rule_id] = _rule_descriptor(finding)
        results.append(_result(finding))

    application = document.get("application", {})
    scan = document.get("scan", {})

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "DroidScope",
                        "version": __version__,
                        "informationUri": "https://github.com/CodeWithLakxsh/DroidScope",
                        "rules": list(rules.values()),
                    }
                },
                "automationDetails": {
                    "id": f"droidscope/{scan.get('profile', 'standard')}/{scan.get('id', '')}",
                    "description": {
                        "text": (
                            "DroidScope static analysis of "
                            f"{application.get('package_name') or application.get('file_name')}"
                        )
                    },
                },
                "invocations": [
                    {
                        "executionSuccessful": scan.get("status") == "completed",
                        "startTimeUtc": scan.get("started_at"),
                        "endTimeUtc": scan.get("finished_at"),
                        "toolExecutionNotifications": _notifications(document),
                    }
                ],
                "properties": {
                    "apkSha256": application.get("sha256"),
                    "packageName": application.get("package_name"),
                    "versionName": application.get("version_name"),
                    "riskScore": (document.get("risk") or {}).get("score"),
                    "riskBand": (document.get("risk") or {}).get("band"),
                    "limitations": (document.get("scope_and_limitations") or {}).get(
                        "statements", []
                    ),
                },
                "results": results,
            }
        ],
    }


def _rule_descriptor(finding: dict[str, Any]) -> dict[str, Any]:
    tags = ["security", finding.get("category", "")]
    tags.extend(finding.get("cwe_ids", []))
    tags.extend(finding.get("masvs_controls", []))
    return {
        "id": finding["rule_id"],
        "name": finding["rule_id"].replace("-", ""),
        "shortDescription": {"text": finding["title"][:200]},
        "fullDescription": {"text": finding["description"]},
        "help": {
            "text": f"{finding['impact']}\n\nRemediation: {finding['remediation']}",
            "markdown": (
                f"**Impact**\n\n{finding['impact']}\n\n"
                f"**Remediation**\n\n{finding['remediation']}"
                + (
                    f"\n\n**Verification**\n\n{finding['verification']}"
                    if finding.get("verification")
                    else ""
                )
                + (
                    f"\n\n**Limitations**\n\n{finding['limitations']}"
                    if finding.get("limitations")
                    else ""
                )
            ),
        },
        "defaultConfiguration": {
            "level": LEVEL_BY_SEVERITY.get(finding.get("severity", "info"), "note")
        },
        "properties": {
            "tags": [tag for tag in tags if tag],
            "security-severity": _security_severity(finding.get("severity", "info")),
            "precision": _precision(finding.get("confidence", "low")),
        },
        "helpUri": (finding.get("references") or [None])[0],
    }


def _result(finding: dict[str, Any]) -> dict[str, Any]:
    message = finding["title"]
    if finding.get("affected_component"):
        message = f"{message} (component: {finding['affected_component']})"

    result: dict[str, Any] = {
        "ruleId": finding["rule_id"],
        "level": LEVEL_BY_SEVERITY.get(finding.get("severity", "info"), "note"),
        "message": {"text": message},
        "partialFingerprints": {"droidscopeFingerprint/v1": finding.get("fingerprint", "")},
        "properties": {
            "severity": finding.get("severity"),
            "confidence": finding.get("confidence"),
            "analysisEngine": finding.get("analysis_engine"),
            "status": finding.get("status"),
        },
    }

    if finding.get("file_path"):
        region: dict[str, Any] = {}
        if finding.get("line_number"):
            region["startLine"] = int(finding["line_number"])
        location = {
            "physicalLocation": {
                "artifactLocation": {"uri": finding["file_path"]},
                **({"region": region} if region else {}),
            }
        }
        result["locations"] = [location]
    else:
        # No file: describe the logical location rather than invent a path.
        result["locations"] = [
            {
                "logicalLocations": [
                    {
                        "name": finding.get("affected_component") or finding["rule_id"],
                        "kind": "resource",
                    }
                ]
            }
        ]

    evidence = finding.get("evidence") or []
    if evidence:
        result["relatedLocations"] = [
            {
                "message": {"text": item["description"][:400]},
                **(
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": item["file_path"]},
                            **(
                                {"region": {"startLine": int(item["line_number"])}}
                                if item.get("line_number")
                                else {}
                            ),
                        }
                    }
                    if item.get("file_path")
                    else {}
                ),
            }
            for item in evidence[:10]
        ]
    return result


def _notifications(document: dict[str, Any]) -> list[dict[str, Any]]:
    """Record analyzers that did not complete as tool notifications."""
    incomplete = (document.get("scope_and_limitations") or {}).get("analyzers_incomplete", [])
    return [
        {
            "level": "warning",
            "message": {
                "text": (
                    f"{item['analyzer']} did not complete ({item['status']}): "
                    f"{item.get('reason') or 'no reason recorded'}"
                )
            },
            "descriptor": {"id": f"droidscope/analyzer/{item['analyzer']}"},
        }
        for item in incomplete
    ]


def _security_severity(severity: str) -> str:
    """GitHub code scanning reads this numeric string to rank alerts."""
    return {
        "critical": "9.5",
        "high": "7.5",
        "medium": "5.0",
        "low": "3.0",
        "info": "0.0",
    }.get(severity, "0.0")


def _precision(confidence: str) -> str:
    return {"high": "high", "medium": "medium", "low": "low"}.get(confidence, "low")
