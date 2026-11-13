/**
 * Scan detail: progress, risk summary, analyzer coverage and limitations.
 *
 * The coverage and limitations sections are first-class rather than footnotes:
 * a scan where half the analyzers could not run must not read like a clean one.
 */

import { Link, useParams } from 'react-router-dom';
import { AlertTriangle, Ban, Download, FileText } from 'lucide-react';
import { api } from '@/lib/api';
import { useCancelScan, useScan } from '@/hooks/queries';
import {
  Button,
  Card,
  CardHeader,
  DataTable,
  ErrorState,
  JobStatusBadge,
  KeyValue,
  LinkButton,
  LoadingState,
  Note,
  PageHeader,
  ProgressBar,
  SeverityBadge,
  StatTile,
  StatusBadge,
} from '@/components/ui';
import { SEVERITY_ORDER, formatDateTime, formatDuration, titleCase } from '@/lib/format';
import type { RiskSummary, Severity } from '@/types/api';

export default function ScanDetailPage() {
  const { scanId } = useParams<{ scanId: string }>();
  const { data: scan, isLoading, isError, error, refetch } = useScan(scanId);
  const cancelScan = useCancelScan();

  if (isLoading) return <LoadingState label="Loading scan" />;
  if (isError) return <ErrorState error={error} onRetry={() => refetch()} />;
  if (!scan) return null;

  const risk = (scan.risk ?? {}) as Partial<RiskSummary>;
  const active = scan.status === 'running' || scan.status === 'queued';
  const incomplete = scan.executions.filter((item) => item.status !== 'completed');

  return (
    <>
      <PageHeader
        title={scan.app_label ?? scan.package_name ?? 'Scan'}
        description={
          <span className="ds-mono text-xs">
            {scan.package_name} · scan {scan.id.slice(0, 12)} · {scan.profile} profile
          </span>
        }
        actions={
          <>
            {active ? (
              <Button
                variant="danger"
                onClick={() => cancelScan.mutate(scan.id)}
                disabled={cancelScan.isPending}
              >
                <Ban className="size-4" aria-hidden="true" />
                Cancel
              </Button>
            ) : null}
            <a
              href={api.exportScanUrl(scan.id)}
              className="inline-flex h-8 cursor-pointer items-center gap-1.5 rounded-sm border px-2.5 text-xs"
              style={{ borderColor: 'var(--border)', backgroundColor: 'var(--surface-raised)' }}
            >
              <Download className="size-3.5" aria-hidden="true" />
              Export JSON
            </a>
            <LinkButton to={`/reports/${scan.id}`} variant="primary">
              <FileText className="size-4" aria-hidden="true" />
              Reports
            </LinkButton>
          </>
        }
      />

      {active ? (
        <Card className="mb-4 px-4 py-3">
          <div className="mb-1.5 flex items-center justify-between text-xs">
            <span className="flex items-center gap-2">
              <JobStatusBadge status={scan.status} />
              <span className="text-muted">{scan.stage ?? 'preparing'}</span>
            </span>
            <span className="tabular-nums">{Math.round(scan.progress * 100)}%</span>
          </div>
          <ProgressBar value={scan.progress} label="Scan progress" />
        </Card>
      ) : null}

      {scan.error ? (
        <div className="mb-4">
          <Note tone="error" title="The scan reported an error">
            {scan.error}
          </Note>
        </div>
      ) : null}

      <section aria-label="Summary" className="mb-4 grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-7">
        <StatTile
          label="Risk score"
          value={risk.score ?? '—'}
          hint={risk.band ? titleCase(risk.band) : 'not calculated'}
          tone="accent"
        />
        <StatTile label="Findings" value={scan.findings_total} href={`/findings/${scan.id}`} />
        {SEVERITY_ORDER.map((severity) => (
          <StatTile
            key={severity}
            label={titleCase(severity)}
            value={scan.severity_counts[severity] ?? 0}
            tone={severity as Severity}
          />
        ))}
      </section>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader
            title="Risk summary"
            description="How the score was derived."
          />
          {risk.method ? (
            <div className="space-y-3 px-4 py-3">
              <p className="text-xs text-muted">{risk.method}</p>
              {risk.band_description ? (
                <Note tone="accent" title={`Band: ${titleCase(risk.band ?? '')}`}>
                  {risk.band_description}
                </Note>
              ) : null}
              {risk.top_contributors && risk.top_contributors.length > 0 ? (
                <DataTable
                  caption="Largest contributors to the risk score"
                  columns={[
                    { key: 'rule', label: 'Rule' },
                    { key: 'sev', label: 'Severity', width: '7rem' },
                    { key: 'conf', label: 'Confidence', width: '6rem' },
                    { key: 'weight', label: 'Weight', width: '5rem', align: 'right' },
                  ]}
                >
                  {risk.top_contributors.slice(0, 8).map((item, index) => (
                    <tr key={`${item.rule_id}-${index}`}>
                      <td className="ds-mono text-[11px]">{item.rule_id}</td>
                      <td>
                        <SeverityBadge severity={item.severity as Severity} />
                      </td>
                      <td className="text-muted">{item.confidence}</td>
                      <td className="text-right tabular-nums">{item.weight}</td>
                    </tr>
                  ))}
                </DataTable>
              ) : null}
            </div>
          ) : (
            <p className="px-4 py-3 text-xs text-muted">
              No risk summary was produced for this scan.
            </p>
          )}
        </Card>

        <Card>
          <CardHeader
            title="Analyzer coverage"
            description="What ran, and what did not."
            actions={
              incomplete.length > 0 ? (
                <StatusBadge tone="warn">{incomplete.length} incomplete</StatusBadge>
              ) : (
                <StatusBadge tone="ok">Complete</StatusBadge>
              )
            }
          />
          <DataTable
            caption="Analyzer execution"
            columns={[
              { key: 'analyzer', label: 'Analyzer' },
              { key: 'status', label: 'Status', width: '8rem' },
              { key: 'findings', label: 'Findings', width: '5rem', align: 'right' },
              { key: 'duration', label: 'Time', width: '5rem', align: 'right' },
            ]}
          >
            {scan.executions.map((item) => (
              <tr key={item.analyzer}>
                <td>
                  <div className="ds-mono text-[11px]">{item.analyzer}</div>
                  {item.error ? (
                    <div className="mt-0.5 text-[11px]" style={{ color: 'var(--status-warn)' }}>
                      {item.error}
                    </div>
                  ) : null}
                </td>
                <td>
                  <JobStatusBadge status={item.status} />
                </td>
                <td className="text-right tabular-nums">{item.findings_count}</td>
                <td className="text-right tabular-nums text-muted">
                  {formatDuration(item.duration_seconds)}
                </td>
              </tr>
            ))}
          </DataTable>
        </Card>
      </div>

      {(scan.limitations.length > 0 || (risk.caveats ?? []).length > 0) && (
        <Card className="mt-4">
          <CardHeader
            title="Limitations"
            description="What this scan did not cover. A completed scan is not proof of security."
            actions={<AlertTriangle className="size-4" aria-hidden="true" style={{ color: 'var(--status-warn)' }} />}
          />
          <ul className="space-y-1.5 px-4 py-3 text-xs text-muted">
            {[...new Set([...(risk.caveats ?? []), ...scan.limitations])].map((item) => (
              <li key={item} className="flex gap-2">
                <span aria-hidden="true">•</span>
                <span>{item}</span>
              </li>
            ))}
          </ul>
        </Card>
      )}

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader title="Scan metadata" />
          <KeyValue
            rows={[
              { label: 'Scan id', value: scan.id, mono: true },
              { label: 'APK', value: <Link to={`/applications/${scan.apk_id}`} style={{ color: 'var(--accent)' }}>{scan.apk_id.slice(0, 16)}</Link>, mono: true },
              { label: 'Profile', value: scan.profile },
              { label: 'Status', value: <JobStatusBadge status={scan.status} /> },
              { label: 'Created', value: formatDateTime(scan.created_at) },
              { label: 'Started', value: formatDateTime(scan.started_at) },
              { label: 'Finished', value: formatDateTime(scan.finished_at) },
              { label: 'Duration', value: formatDuration(scan.duration_seconds) },
              { label: 'Rules loaded', value: String(scan.environment.rules_loaded ?? '—') },
              { label: 'Artifacts', value: scan.artifacts.join(', ') || 'none', mono: true },
            ]}
          />
        </Card>

        <Card>
          <CardHeader title="Tool versions" description="Recorded at the time of the scan." />
          <KeyValue
            rows={Object.entries(scan.environment.tool_versions ?? {}).map(([name, version]) => ({
              label: name,
              value: version,
              mono: true,
            }))}
          />
          {(scan.environment.tools_unavailable ?? []).length > 0 ? (
            <div className="px-4 pb-3">
              <Note tone="warn" title="Tools not available during this scan">
                {(scan.environment.tools_unavailable ?? []).join(', ')}
              </Note>
            </div>
          ) : null}
        </Card>
      </div>

      <div className="mt-4 flex flex-wrap gap-2">
        <LinkButton to={`/findings/${scan.id}`} variant="primary">View findings</LinkButton>
        <LinkButton to={`/code/${scan.id}`}>Browse code</LinkButton>
        <LinkButton to={`/indicators/${scan.id}`}>Network indicators</LinkButton>
        <LinkButton to={`/binary/${scan.id}`}>Binary analysis</LinkButton>
        <LinkButton to={`/graphs/${scan.id}`}>Visualisations</LinkButton>
      </div>
    </>
  );
}
