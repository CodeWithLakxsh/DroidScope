/**
 * Dashboard.
 *
 * Every number here is computed by the API from stored scan results. When the
 * database is empty the page shows an explicit empty state rather than zeros
 * that could be mistaken for "nothing found".
 */

import { Link } from 'react-router-dom';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { Package, Upload } from 'lucide-react';
import { SkeletonTiles, Stagger } from '@/components/motion';
import { useDashboard } from '@/hooks/queries';
import {
  Card,
  CardHeader,
  DataTable,
  EmptyState,
  ErrorState,
  JobStatusBadge,
  LinkButton,
  PageHeader,
  SeverityBadge,
  StatTile,
} from '@/components/ui';
import { SEVERITY_ORDER, formatDuration, formatRelative, titleCase } from '@/lib/format';
import type { Severity } from '@/types/api';

export default function Dashboard() {
  const { data, isLoading, isError, error, refetch } = useDashboard();

  if (isLoading) {
    // A skeleton reserves the layout so nothing jumps when the data lands.
    return (
      <>
        <PageHeader title="Dashboard" description="Statistics computed from stored scan results." />
        <SkeletonTiles />
      </>
    );
  }
  if (isError) return <ErrorState error={error} onRetry={() => refetch()} />;
  if (!data) return null;

  const hasData = data.apks_total > 0 || data.scans_total > 0;
  const severityData = SEVERITY_ORDER.map((severity) => ({
    severity,
    label: titleCase(severity),
    count: data.findings_by_severity[severity] ?? 0,
  }));

  return (
    <>
      <PageHeader
        title="Dashboard"
        description="Statistics computed from stored scan results."
        actions={
          <LinkButton to="/upload" variant="primary" size="md">
            <Upload className="size-4" aria-hidden="true" />
            Upload APK
          </LinkButton>
        }
      />

      {!hasData ? (
        <Card>
          <EmptyState
            icon={<Package className="size-10" aria-hidden="true" />}
            title="No applications analysed yet"
            description="Upload an APK to run a static analysis. DroidScope validates the archive, extracts metadata and evaluates its detection rules, then reports evidence-backed findings."
            action={
              <LinkButton to="/upload" variant="primary" size="md">
                Upload your first APK
              </LinkButton>
            }
          />
        </Card>
      ) : (
        <>
          <Stagger
            as="section"
            aria-label="Totals"
            className="mb-4 grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6"
          >
            <StatTile label="APKs" value={data.apks_total} href="/applications" />
            <StatTile label="Scans" value={data.scans_total} href="/scans" />
            <StatTile
              label="Completed"
              value={data.scans_by_status.completed ?? 0}
              hint={`${data.scans_by_status.running ?? 0} running`}
            />
            <StatTile
              label="Failed"
              value={data.scans_by_status.failed ?? 0}
              tone={(data.scans_by_status.failed ?? 0) > 0 ? 'high' : undefined}
            />
            <StatTile label="Findings" value={data.findings_total} href="/findings" />
            <StatTile
              label="Critical"
              value={data.findings_by_severity.critical ?? 0}
              tone="critical"
            />
          </Stagger>

          <Stagger
            as="section"
            aria-label="Findings by severity"
            className="mb-4 grid grid-cols-2 gap-2 sm:grid-cols-5"
          >
            {severityData.map((item) => (
              <StatTile
                key={item.severity}
                label={item.label}
                value={item.count}
                tone={item.severity as Severity}
              />
            ))}
          </Stagger>

          <div className="grid gap-4 lg:grid-cols-2">
            <Card>
              <CardHeader
                title="Findings by severity"
                description="Across every stored scan."
              />
              <div className="p-3">
                <ResponsiveContainer width="100%" height={220}>
                  <BarChart data={severityData} margin={{ top: 4, right: 8, bottom: 0, left: -16 }}>
                    <CartesianGrid strokeDasharray="2 4" stroke="var(--border)" vertical={false} />
                    <XAxis
                      dataKey="label"
                      tick={{ fontSize: 11, fill: 'var(--text-muted)' }}
                      axisLine={{ stroke: 'var(--border)' }}
                      tickLine={false}
                    />
                    <YAxis
                      allowDecimals={false}
                      tick={{ fontSize: 11, fill: 'var(--text-muted)' }}
                      axisLine={false}
                      tickLine={false}
                    />
                    <Tooltip
                      cursor={{ fill: 'var(--surface-hover)' }}
                      contentStyle={{
                        backgroundColor: 'var(--surface-raised)',
                        border: '1px solid var(--border)',
                        borderRadius: 4,
                        fontSize: 12,
                        color: 'var(--text)',
                      }}
                    />
                    <Bar dataKey="count" name="Findings" radius={[2, 2, 0, 0]}>
                      {severityData.map((item) => (
                        <Cell key={item.severity} fill={`var(--severity-${item.severity})`} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </Card>

            <Card>
              <CardHeader title="Findings by category" description="Top categories by count." />
              {data.findings_by_category.length === 0 ? (
                <EmptyState title="No categorised findings yet" />
              ) : (
                <DataTable
                  caption="Findings grouped by category"
                  columns={[
                    { key: 'category', label: 'Category' },
                    { key: 'count', label: 'Findings', width: '6rem', align: 'right' },
                  ]}
                >
                  {data.findings_by_category.map((row) => (
                    <tr key={row.category}>
                      <td>{titleCase(row.category)}</td>
                      <td className="text-right tabular-nums">{row.count}</td>
                    </tr>
                  ))}
                </DataTable>
              )}
            </Card>
          </div>

          <Card className="mt-4">
            <CardHeader
              title="Recent analysis activity"
              description="The ten most recent scans."
              actions={<LinkButton to="/scans">View all scans</LinkButton>}
            />
            {data.recent_scans.length === 0 ? (
              <EmptyState title="No scans yet" />
            ) : (
              <DataTable
                caption="Recent scans"
                columns={[
                  { key: 'scan', label: 'Scan' },
                  { key: 'profile', label: 'Profile', width: '6rem' },
                  { key: 'status', label: 'Status', width: '8rem' },
                  { key: 'findings', label: 'Findings', width: '14rem' },
                  { key: 'risk', label: 'Risk', width: '7rem' },
                  { key: 'duration', label: 'Duration', width: '6rem', align: 'right' },
                  { key: 'when', label: 'When', width: '8rem', align: 'right' },
                ]}
                staggerRows
              >
                {data.recent_scans.map((scan) => (
                  <tr key={scan.id}>
                    <td>
                      <Link
                        to={`/scans/${scan.id}`}
                        className="ds-mono text-xs hover:underline"
                        style={{ color: 'var(--accent)' }}
                      >
                        {scan.id.slice(0, 12)}
                      </Link>
                    </td>
                    <td className="text-muted">{scan.profile}</td>
                    <td>
                      <JobStatusBadge status={scan.status} />
                    </td>
                    <td>
                      {scan.findings_total === 0 ? (
                        <span className="text-subtle">none</span>
                      ) : (
                        <span className="flex flex-wrap items-center gap-1">
                          {SEVERITY_ORDER.filter(
                            (severity) => (scan.severity_counts[severity] ?? 0) > 0,
                          ).map((severity) => (
                            <span key={severity} className="inline-flex items-center gap-0.5">
                              <SeverityBadge severity={severity} showLabel={false} />
                              <span className="text-xs tabular-nums">
                                {scan.severity_counts[severity]}
                              </span>
                            </span>
                          ))}
                        </span>
                      )}
                    </td>
                    <td className="tabular-nums">
                      {scan.risk_score === null ? (
                        <span className="text-subtle">—</span>
                      ) : (
                        <span>
                          {scan.risk_score}
                          <span className="ml-1 text-[11px] text-subtle">{scan.risk_band}</span>
                        </span>
                      )}
                    </td>
                    <td className="text-right tabular-nums text-muted">
                      {formatDuration(scan.duration_seconds)}
                    </td>
                    <td className="text-right text-muted">{formatRelative(scan.created_at)}</td>
                  </tr>
                ))}
              </DataTable>
            )}
          </Card>
        </>
      )}
    </>
  );
}
