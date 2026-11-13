/** List of uploaded APKs. */

import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Package, Search } from 'lucide-react';
import { useApks } from '@/hooks/queries';
import {
  Card,
  DataTable,
  EmptyState,
  ErrorState,
  Input,
  JobStatusBadge,
  LinkButton,
  LoadingState,
  PageHeader,
} from '@/components/ui';
import { formatBytes, formatRelative, shortId } from '@/lib/format';

export default function Applications() {
  const [search, setSearch] = useState('');
  const { data, isLoading, isError, error, refetch } = useApks({
    limit: 100,
    search: search.trim() || undefined,
  });

  return (
    <>
      <PageHeader
        title="Applications"
        description="APKs stored by DroidScope, identified by content hash."
        actions={<LinkButton to="/upload" variant="primary">Upload APK</LinkButton>}
      />

      <Card>
        <div className="flex items-center gap-2 border-b px-4 py-2.5" style={{ borderColor: 'var(--border)' }}>
          <Search className="size-4 text-subtle" aria-hidden="true" />
          <label htmlFor="apk-search" className="sr-only">
            Search applications
          </label>
          <Input
            id="apk-search"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Filter by package, label, filename or SHA-256"
            className="border-0 bg-transparent"
            style={{ backgroundColor: 'transparent', borderColor: 'transparent' }}
          />
        </div>

        {isLoading ? (
          <LoadingState label="Loading applications" />
        ) : isError ? (
          <ErrorState error={error} onRetry={() => refetch()} />
        ) : !data || data.items.length === 0 ? (
          <EmptyState
            icon={<Package className="size-9" aria-hidden="true" />}
            title={search ? 'No applications match that filter' : 'No applications yet'}
            description={
              search
                ? 'Try a different package name, label or hash.'
                : 'Upload an APK to begin.'
            }
            action={search ? undefined : <LinkButton to="/upload" variant="primary">Upload APK</LinkButton>}
          />
        ) : (
          <DataTable
            caption="Uploaded applications"
            columns={[
              { key: 'app', label: 'Application' },
              { key: 'version', label: 'Version', width: '9rem' },
              { key: 'sdk', label: 'SDK', width: '7rem' },
              { key: 'size', label: 'Size', width: '6rem', align: 'right' },
              { key: 'scans', label: 'Scans', width: '10rem' },
              { key: 'added', label: 'Added', width: '8rem', align: 'right' },
            ]}
          >
            {data.items.map((apk) => (
              <tr key={apk.id}>
                <td>
                  <Link
                    to={`/applications/${apk.id}`}
                    className="font-medium hover:underline"
                    style={{ color: 'var(--accent)' }}
                  >
                    {apk.app_label ?? apk.package_name ?? apk.original_filename}
                  </Link>
                  <div className="ds-mono text-[11px] text-subtle">
                    {apk.package_name ?? apk.original_filename} · {shortId(apk.sha256, 16)}
                  </div>
                </td>
                <td className="ds-mono text-xs">
                  {apk.version_name ?? '—'}
                  {apk.version_code !== null ? (
                    <span className="text-subtle"> ({apk.version_code})</span>
                  ) : null}
                </td>
                <td className="text-xs text-muted">
                  {apk.min_sdk ?? '?'} → {apk.target_sdk ?? '?'}
                </td>
                <td className="text-right tabular-nums text-muted">{formatBytes(apk.file_size)}</td>
                <td>
                  {apk.scan_count === 0 ? (
                    <span className="text-subtle">none</span>
                  ) : (
                    <span className="flex items-center gap-1.5">
                      <span className="tabular-nums">{apk.scan_count}</span>
                      {apk.latest_scan_status ? (
                        <JobStatusBadge status={apk.latest_scan_status} />
                      ) : null}
                    </span>
                  )}
                </td>
                <td className="text-right text-muted">{formatRelative(apk.created_at)}</td>
              </tr>
            ))}
          </DataTable>
        )}
      </Card>
    </>
  );
}
