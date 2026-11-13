"""HTML report rendering.

Everything that reaches the page is escaped by Jinja's autoescaping, and the
document carries a restrictive Content-Security-Policy meta tag. A report
derived from a hostile APK must not be able to execute script in the reviewer's
browser, so no inline event handlers, no external resources and no raw HTML
interpolation are used anywhere in the template.
"""

from __future__ import annotations

from typing import Any

from jinja2 import Environment, select_autoescape

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# Severity is conveyed by a text label and a shape glyph as well as colour, so
# the report remains readable in greyscale and for colour-blind readers.
SEVERITY_GLYPH = {
    "critical": "◆",
    "high": "▲",
    "medium": "■",
    "low": "●",
    "info": "○",
}

TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy"
      content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<title>DroidScope report - {{ application.package_name or application.file_name }}</title>
<style>
  :root {
    --bg: #ffffff; --fg: #0f172a; --muted: #475569; --line: #cbd5e1;
    --surface: #f8fafc; --accent: #0f766e;
    --critical: #7f1d1d; --high: #9a3412; --medium: #854d0e; --low: #1e40af; --info: #334155;
  }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 0 1.5rem 4rem;
         font-family: "IBM Plex Sans", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
         color: var(--fg); background: var(--bg); line-height: 1.55; }
  main { max-width: 60rem; margin: 0 auto; }
  code, pre, .mono { font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace; }
  h1 { font-size: 1.9rem; margin: 2.5rem 0 0.25rem; letter-spacing: -0.01em; }
  h2 { font-size: 1.3rem; margin: 2.5rem 0 0.75rem; padding-bottom: 0.3rem;
       border-bottom: 2px solid var(--line); }
  h3 { font-size: 1.02rem; margin: 1.75rem 0 0.4rem; }
  p { margin: 0.5rem 0; }
  .subtitle { color: var(--muted); margin-bottom: 1.5rem; }
  table { width: 100%; border-collapse: collapse; margin: 0.75rem 0; font-size: 0.9rem; }
  th, td { text-align: left; padding: 0.45rem 0.6rem; border-bottom: 1px solid var(--line);
           vertical-align: top; }
  th { font-weight: 600; background: var(--surface); font-size: 0.82rem;
       text-transform: uppercase; letter-spacing: 0.04em; color: var(--muted); }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(10rem, 1fr)); gap: 0.75rem;
          margin: 1rem 0; }
  .card { border: 1px solid var(--line); border-radius: 6px; padding: 0.75rem 0.9rem;
          background: var(--surface); }
  .card .value { font-size: 1.6rem; font-weight: 600; }
  .card .label { font-size: 0.78rem; color: var(--muted); text-transform: uppercase;
                 letter-spacing: 0.05em; }
  .sev { display: inline-block; font-weight: 600; font-size: 0.78rem; padding: 0.1rem 0.45rem;
         border: 1px solid currentColor; border-radius: 3px; white-space: nowrap; }
  .sev-critical { color: var(--critical); } .sev-high { color: var(--high); }
  .sev-medium { color: var(--medium); } .sev-low { color: var(--low); }
  .sev-info { color: var(--info); }
  .finding { border: 1px solid var(--line); border-radius: 6px; padding: 1rem 1.1rem;
             margin: 1rem 0; page-break-inside: avoid; }
  .finding h3 { margin-top: 0; }
  .meta { color: var(--muted); font-size: 0.82rem; margin-bottom: 0.6rem; }
  .meta span + span::before { content: " \\00b7 "; }
  pre { background: #0f172a; color: #e2e8f0; padding: 0.7rem 0.85rem; border-radius: 5px;
        overflow-x: auto; font-size: 0.82rem; white-space: pre-wrap; word-break: break-word; }
  .label-inline { font-weight: 600; font-size: 0.85rem; color: var(--muted); }
  .note { border-left: 3px solid var(--accent); background: var(--surface);
          padding: 0.6rem 0.9rem; margin: 1rem 0; font-size: 0.9rem; }
  ul { margin: 0.4rem 0; padding-left: 1.2rem; }
  li { margin: 0.2rem 0; }
  footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--line);
           color: var(--muted); font-size: 0.8rem; }
  @media print { body { padding: 0; } .finding { break-inside: avoid; } }
</style>
</head>
<body>
<main>
  <h1>Android application security report</h1>
  <p class="subtitle mono">{{ application.package_name or application.file_name }}
    {%- if application.version_name %} &middot; version {{ application.version_name }}{% endif %}</p>

  <div class="grid">
    <div class="card"><div class="label">Risk score</div>
      <div class="value">{{ risk.score if risk.score is not none else "n/a" }}</div>
      <div class="label">{{ risk.band or "not calculated" }}</div></div>
    <div class="card"><div class="label">Findings</div>
      <div class="value">{{ scan.findings_total }}</div>
      <div class="label">{{ scan.profile }} profile</div></div>
    {% for name in severity_order %}
    <div class="card"><div class="label">{{ name }}</div>
      <div class="value">{{ scan.severity_counts.get(name, 0) }}</div></div>
    {% endfor %}
  </div>

  <h2>Executive summary</h2>
  <p>{{ summary_text }}</p>
  <div class="note">
    <strong>How to read the risk score.</strong> {{ risk.method }}
    {% if risk.band_description %} {{ risk.band_description }}{% endif %}
  </div>

  <h2>Application identity</h2>
  <table>
    <tr><th>Package</th><td class="mono">{{ application.package_name or "not determined" }}</td></tr>
    <tr><th>Label</th><td>{{ application.label or "not determined" }}</td></tr>
    <tr><th>Version</th><td>{{ application.version_name or "?" }} (code {{ application.version_code or "?" }})</td></tr>
    <tr><th>SDK</th><td>min {{ application.min_sdk or "?" }}, target {{ application.target_sdk or "?" }}</td></tr>
    <tr><th>File</th><td class="mono">{{ application.file_name }} ({{ application.file_size }} bytes)</td></tr>
    <tr><th>SHA-256</th><td class="mono">{{ application.sha256 }}</td></tr>
    <tr><th>Signatures</th><td>{{ application.signature_schemes | join(", ") or "none detected" }}</td></tr>
    {% for cert in application.certificates[:3] %}
    <tr><th>Certificate</th><td class="mono">{{ cert.subject or "unknown" }}<br>
      {{ cert.signature_algorithm or "?" }},
      {{ cert.key_size_bits or "?" }} bits, SHA-256 {{ cert.sha256_fingerprint or "?" }}</td></tr>
    {% endfor %}
  </table>

  <h2>Scope and methodology</h2>
  <p>{{ methodology.approach }}</p>
  <p><span class="label-inline">Analyzers completed:</span>
     {{ methodology.analyzers_run | join(", ") or "none" }}</p>
  <p><span class="label-inline">Standards:</span> {{ methodology.standards }}</p>
  <table>
    <tr><th>Analyzer</th><th>Status</th><th>Findings</th><th>Duration</th><th>Notes</th></tr>
    {% for item in analyzers %}
    <tr><td class="mono">{{ item.analyzer }}</td><td>{{ item.status }}</td>
        <td>{{ item.findings }}</td>
        <td>{{ "%.1fs" | format(item.duration_seconds or 0) }}</td>
        <td>{{ item.error or "" }}</td></tr>
    {% endfor %}
  </table>

  <h2>Limitations</h2>
  <ul>{% for statement in scope_and_limitations.statements %}<li>{{ statement }}</li>{% endfor %}</ul>

  <h2>Permissions</h2>
  <p>{{ permission_analysis.total }} permissions requested,
     {{ permission_analysis.dangerous_count }} classified dangerous by the platform.</p>
  {% if permission_analysis.all %}
  <table>
    <tr><th>Permission</th><th>Protection level</th><th>Dangerous</th></tr>
    {% for permission in permission_analysis.all %}
    <tr><td class="mono">{{ permission.name }}</td>
        <td>{{ permission.protection_level or "unknown" }}</td>
        <td>{{ "yes" if permission.is_dangerous else "no" }}</td></tr>
    {% endfor %}
  </table>
  {% endif %}

  <h2>Findings</h2>
  {% if not findings %}
  <p>No findings were produced by the analyzers that ran. This is not evidence that
     the application is secure; see the limitations above.</p>
  {% endif %}
  {% for finding in findings %}
  <div class="finding">
    <h3><span class="sev sev-{{ finding.severity }}">{{ severity_glyph[finding.severity] }}
        {{ finding.severity | upper }}</span>
        {{ finding.title }}</h3>
    <p class="meta">
      <span class="mono">{{ finding.rule_id }}</span>
      <span>confidence: {{ finding.confidence }}</span>
      <span>engine: {{ finding.analysis_engine }}</span>
      <span>status: {{ finding.status }}</span>
      {% if finding.cwe_ids %}<span>{{ finding.cwe_ids | join(", ") }}</span>{% endif %}
      {% if finding.masvs_controls %}<span>{{ finding.masvs_controls | join(", ") }}</span>{% endif %}
    </p>
    <p>{{ finding.description }}</p>
    {% if finding.affected_component or finding.file_path %}
    <p class="mono meta">{{ finding.affected_component or "" }}
      {%- if finding.file_path %} &mdash; {{ finding.file_path }}
      {%- if finding.line_number %}:{{ finding.line_number }}{% endif %}{% endif %}</p>
    {% endif %}
    <p><span class="label-inline">Impact.</span> {{ finding.impact }}</p>
    <p><span class="label-inline">Remediation.</span> {{ finding.remediation }}</p>
    {% if finding.verification %}
    <p><span class="label-inline">Verification.</span> {{ finding.verification }}</p>{% endif %}
    {% if finding.limitations %}
    <p><span class="label-inline">Detection limitations.</span> {{ finding.limitations }}</p>{% endif %}
    {% if finding.evidence %}
    <p class="label-inline">Evidence</p>
    {% for item in finding.evidence[:6] %}
      <p class="meta">{{ item.description }}
        {%- if item.sensitive %} (value masked){% endif %}</p>
      {% if item.snippet %}<pre>{{ item.snippet }}</pre>{% endif %}
    {% endfor %}
    {% endif %}
    {% if finding.references %}
    <p class="label-inline">References</p>
    <ul>{% for reference in finding.references %}<li class="mono">{{ reference }}</li>{% endfor %}</ul>
    {% endif %}
  </div>
  {% endfor %}

  {% if indicators %}
  <h2>Network indicators</h2>
  <p>Extracted from application contents and classified by routing scope. These are
     observations: DroidScope does not contact them, and their presence is not
     evidence of malicious behaviour.</p>
  <table>
    <tr><th>Type</th><th>Value</th><th>Scope</th><th>Source</th><th>Count</th></tr>
    {% for indicator in indicators[:80] %}
    <tr><td>{{ indicator.type }}</td><td class="mono">{{ indicator.value[:110] }}</td>
        <td>{{ indicator.scope }}</td><td class="mono">{{ indicator.source_file or "" }}</td>
        <td>{{ indicator.occurrences }}</td></tr>
    {% endfor %}
  </table>
  {% endif %}

  <h2>Analysis metadata</h2>
  <table>
    <tr><th>Scan identifier</th><td class="mono">{{ scan.id }}</td></tr>
    <tr><th>Generated</th><td>{{ report.generated_at }}</td></tr>
    <tr><th>Generator</th><td>{{ report.generator }}</td></tr>
    <tr><th>Scan status</th><td>{{ scan.status }}</td></tr>
    <tr><th>Duration</th><td>{{ "%.1fs" | format(scan.duration_seconds or 0) }}</td></tr>
    <tr><th>APK SHA-256</th><td class="mono">{{ application.sha256 }}</td></tr>
    <tr><th>Secret redaction</th><td>{{ "applied" if report.redaction_applied else "disabled" }}</td></tr>
    <tr><th>Tool versions</th><td class="mono">
      {%- for name, version in environment.tool_versions.items() %}{{ name }} {{ version }}<br>{% endfor %}</td></tr>
    {% if environment.tools_unavailable %}
    <tr><th>Tools unavailable</th><td class="mono">{{ environment.tools_unavailable | join(", ") }}</td></tr>
    {% endif %}
  </table>

  <footer>
    Generated by {{ report.generator }} on {{ report.generated_at }}.
    This report describes the application as shipped and does not constitute a
    guarantee of security.
  </footer>
</main>
</body>
</html>
"""


def render_html(document: dict[str, Any]) -> str:
    environment = Environment(
        autoescape=select_autoescape(default=True, default_for_string=True),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = environment.from_string(TEMPLATE)
    return template.render(
        **document,
        severity_order=SEVERITY_ORDER,
        severity_glyph=SEVERITY_GLYPH,
        summary_text=build_summary_text(document),
    )


def build_summary_text(document: dict[str, Any]) -> str:
    """One paragraph stating what was found, in plain language."""
    scan = document.get("scan", {})
    risk = document.get("risk", {})
    counts = scan.get("severity_counts", {})
    application = document.get("application", {})
    total = scan.get("findings_total", 0)

    name = application.get("package_name") or application.get("file_name") or "the application"
    if not total:
        return (
            f"DroidScope analysed {name} using the {scan.get('profile')} profile and "
            "produced no findings from the rules that ran. This does not demonstrate "
            "that the application is secure: the limitations section lists what was "
            "not covered."
        )

    parts = [f"{counts.get(level, 0)} {level}" for level in SEVERITY_ORDER if counts.get(level, 0)]
    incomplete = (document.get("scope_and_limitations") or {}).get("analyzers_incomplete", [])
    coverage = (
        " All requested analyzers completed."
        if not incomplete
        else (
            f" {len(incomplete)} analyzer(s) did not complete, so the result is a "
            "partial view of the application."
        )
    )
    return (
        f"DroidScope analysed {name} using the {scan.get('profile')} profile and "
        f"recorded {total} findings ({', '.join(parts)}). The application risk score "
        f"is {risk.get('score', 'not calculated')} out of 100, placing it in the "
        f"'{risk.get('band', 'unknown')}' band.{coverage}"
    )
