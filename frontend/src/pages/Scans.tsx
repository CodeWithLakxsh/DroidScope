/** Scan history. */

import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Activity } from 'lucide-react';
import { useScans } from '@/hooks/queries';
import {
  Card,
  DataTable,
  EmptyState,
  ErrorState,
  JobStatusBadge,
  LinkButton,
  LoadingState,
  PageHeader,
  ProgressBar,
  Select,
  SeverityBadge,
} from '@/components/ui';
import { SEVERITY_ORDER, formatDuration, formatRelative } from '@/lib/format';

export default function Scans() {
  const [status, setStatus] = useState('');
  const { data, isLoading, isError, error, refetch } = useScans({
    limit: 100,
    status: status || undefined,
  });

  return (
    <>
      <PageHeader
        title="Scans"
        description="Every analysis run, including those that failed or were cancelled."
        actions={
          <>
            <label htmlFor="status-filter" className="sr-only">
              Filter by status
            </label>
            <Select
              id="status-filter"
              value={status}
              onChange={(event) => setStatus(event.target.value)}
              className="w-auto"
            >
              <option value="">All statuses</option>
              <option value="completed">Completed</option>
              <option value="running">Running</option>
              <option value="queued">Queued</option>
              <option value="failed">Failed</option>
              <option value="cancelled">Cancelled</option>
            </Select>
            <LinkButton to="/upload" variant="primary">New analysis</LinkButton>
          </>
        }
      />

      <Card>
        {isLoading ? (
          <LoadingState label="Loading scans" />
        ) : isError ? (
          <ErrorState error={error} onRetry={() => refetch()} />
        ) : !data || data.items.length === 0 ? (
          <EmptyState
            icon={<Activity className="size-9" aria-hidden="true" />}
            title={status ? `No ${status} scans` : 'No scans yet'}
            description="Upload an APK and start an analysis to see results here."
            action={<LinkButton to="/upload" variant="primary">Upload APK</LinkButton>}
          />
        ) : (
          <DataTable
            caption="Scan history"
            staggerRows
            columns={[
              { key: 'scan', label: 'Scan' },
              { key: 'app', label: 'Application' },
              { key: 'profile', label: 'Profile', width: '6rem' },
              { key: 'status', label: 'Status', width: '11rem' },
              { key: 'findings', label: 'Findings', width: '14rem' },
              { key: 'duration', label: 'Duration', width: '6rem', align: 'right' },
              { key: 'when', label: 'Started', width: '8rem', align: 'right' },
            ]}
          >
            {data.items.map((scan) => (
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
                <td>
                  <div className="truncate">{scan.app_label ?? scan.package_name ?? '—'}</div>
                  <div className="ds-mono text-[11px] text-subtle">{scan.package_name ?? ''}</div>
                </td>
                <td className="text-muted">{scan.profile}</td>
                <td>
                  <JobStatusBadge status={scan.status} />
                  {scan.status === 'running' ? (
                    <div className="mt-1">
                      <ProgressBar
                        value={scan.progress}
                        indeterminate={scan.progress === 0}
                        label={`Scan progress: ${scan.stage ?? ''}`}
                      />
                      <div className="mt-0.5 text-[11px] text-subtle">{scan.stage}</div>
                    </div>
                  ) : null}
                  {scan.error ? (
                    <div className="mt-0.5 max-w-[16rem] truncate text-[11px]" title={scan.error}
                      style={{ color: 'var(--status-error)' }}>
                      {scan.error}
                    </div>
                  ) : null}
                </td>
                <td>
                  {scan.findings_total === 0 ? (
                    <span className="text-subtle">none</span>
                  ) : (
                    <span className="flex flex-wrap items-center gap-1">
                      {SEVERITY_ORDER.filter((s) => (scan.severity_counts[s] ?? 0) > 0).map((s) => (
                        <span key={s} className="inline-flex items-center gap-0.5">
                          <SeverityBadge severity={s} showLabel={false} />
                          <span className="text-xs tabular-nums">{scan.severity_counts[s]}</span>
                        </span>
                      ))}
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
  );
}
