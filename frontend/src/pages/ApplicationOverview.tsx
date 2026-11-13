/** Application overview: identity, components, signing, contents. */

import { useParams } from 'react-router-dom';
import { Play } from 'lucide-react';
import { api } from '@/lib/api';
import { useApk, useCreateScan, useScans } from '@/hooks/queries';
import { useNavigate } from 'react-router-dom';
import { useState } from 'react';
import {
  Button,
  Card,
  CardHeader,
  Chip,
  DataTable,
  EmptyState,
  ErrorState,
  JobStatusBadge,
  KeyValue,
  LinkButton,
  LoadingState,
  Note,
  PageHeader,
  Select,
  StatTile,
  StatusBadge,
} from '@/components/ui';
import { formatBytes, formatDateTime, formatRelative } from '@/lib/format';
import type { ScanProfile } from '@/types/api';

export default function ApplicationOverview() {
  const { apkId } = useParams<{ apkId: string }>();
  const navigate = useNavigate();
  const [profile, setProfile] = useState<ScanProfile>('standard');
  const apk = useApk(apkId);
  const scans = useScans({ apk_id: apkId, limit: 20 });
  const createScan = useCreateScan();

  if (apk.isLoading) return <LoadingState label="Loading application" />;
  if (apk.isError) return <ErrorState error={apk.error} onRetry={() => apk.refetch()} />;
  if (!apk.data) return null;

  const metadata = apk.data.apk_metadata;
  const components = metadata.components ?? [];
  const exported = components.filter((item) => item.exported);

  const startScan = async () => {
    const created = await createScan.mutateAsync({ apk_id: apk.data!.id, profile });
    navigate(`/scans/${created.scan.id}`);
  };

  return (
    <>
      <PageHeader
        title={
          <span className="flex items-center gap-2.5">
            {apk.data.has_icon ? (
              <img
                src={api.apkIconUrl(apk.data.id)}
                alt=""
                className="size-7 rounded-sm"
                onError={(event) => {
                  (event.target as HTMLImageElement).style.display = 'none';
                }}
              />
            ) : null}
            {apk.data.app_label ?? apk.data.package_name ?? apk.data.original_filename}
          </span>
        }
        description={<span className="ds-mono text-xs">{apk.data.package_name}</span>}
        actions={
          <>
            <label htmlFor="scan-profile" className="sr-only">Analysis profile</label>
            <Select
              id="scan-profile"
              value={profile}
              onChange={(event) => setProfile(event.target.value as ScanProfile)}
              className="w-auto"
            >
              <option value="quick">Quick</option>
              <option value="standard">Standard</option>
              <option value="full">Full</option>
            </Select>
            <Button variant="primary" onClick={startScan} disabled={createScan.isPending}>
              <Play className="size-3.5" aria-hidden="true" />
              {createScan.isPending ? 'Queueing…' : 'Run analysis'}
            </Button>
          </>
        }
      />

      {metadata.partial ? (
        <div className="mb-4">
          <Note tone="warn" title="Metadata extraction was incomplete">
            {metadata.parse_errors.join('; ') || 'Some metadata could not be parsed.'}
          </Note>
        </div>
      ) : null}

      <section aria-label="Contents" className="mb-4 grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
        <StatTile label="Components" value={components.length} />
        <StatTile label="Exported" value={exported.length} tone={exported.length ? 'medium' : undefined} />
        <StatTile label="Permissions" value={metadata.requested_permissions.length} />
        <StatTile label="DEX files" value={metadata.dex_files.length} />
        <StatTile label="Native libs" value={metadata.native_libraries.length} />
        <StatTile label="Scans" value={apk.data.scan_count} />
      </section>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader title="Identity" />
          <KeyValue
            rows={[
              { label: 'Package', value: metadata.package_name ?? '—', mono: true },
              { label: 'Label', value: metadata.app_label ?? '—' },
              { label: 'Version name', value: metadata.version_name ?? '—', mono: true },
              { label: 'Version code', value: String(metadata.version_code ?? '—'), mono: true },
              { label: 'Minimum SDK', value: String(metadata.min_sdk ?? '—') },
              { label: 'Target SDK', value: String(metadata.target_sdk ?? '—') },
              { label: 'File name', value: apk.data.original_filename, mono: true },
              { label: 'File size', value: formatBytes(apk.data.file_size) },
              { label: 'SHA-256', value: apk.data.sha256, mono: true },
              { label: 'SHA-1', value: apk.data.sha1 ?? '—', mono: true },
              { label: 'MD5', value: apk.data.md5 ?? '—', mono: true },
              { label: 'Uploaded', value: formatDateTime(apk.data.created_at) },
            ]}
          />
        </Card>

        <div className="space-y-4">
          <Card>
            <CardHeader
              title="Signing"
              description={metadata.signature_schemes.join(', ') || 'no signature detected'}
            />
            {metadata.certificates.length === 0 ? (
              <EmptyState title="No certificate information" />
            ) : (
              metadata.certificates.map((certificate) => (
                <KeyValue
                  key={certificate.sha256_fingerprint ?? certificate.subject ?? 'cert'}
                  rows={[
                    { label: 'Subject', value: certificate.subject ?? '—', mono: true },
                    { label: 'Issuer', value: certificate.issuer ?? '—', mono: true },
                    { label: 'Algorithm', value: certificate.signature_algorithm ?? '—' },
                    { label: 'Key size', value: `${certificate.key_size_bits ?? '?'} bits` },
                    { label: 'Valid from', value: certificate.not_before ?? '—' },
                    { label: 'Valid to', value: certificate.not_after ?? '—' },
                    { label: 'SHA-256', value: certificate.sha256_fingerprint ?? '—', mono: true },
                    {
                      label: 'Self signed',
                      value: certificate.is_self_signed ? 'yes' : 'no',
                    },
                  ]}
                />
              ))
            )}
          </Card>

          <Card>
            <CardHeader title="Contents" />
            <KeyValue
              rows={[
                { label: 'ABIs', value: metadata.abis.join(', ') || 'none', mono: true },
                {
                  label: 'DEX files',
                  value: metadata.dex_files.map((dex) => dex.name).join(', ') || 'none',
                  mono: true,
                },
                { label: 'Archive entries', value: String(metadata.entry_count) },
                {
                  label: 'Archive checks',
                  value: (
                    <span className="flex flex-wrap gap-1">
                      {Object.entries(apk.data.validation.checks ?? {}).map(([name, state]) => (
                        <StatusBadge key={name} tone={state === 'pass' ? 'ok' : 'warn'}>
                          {name.replace(/_/g, ' ')}
                        </StatusBadge>
                      ))}
                    </span>
                  ),
                },
              ]}
            />
          </Card>
        </div>
      </div>

      <Card className="mt-4">
        <CardHeader
          title="Exported components"
          description="Components reachable by other applications on the device."
        />
        {exported.length === 0 ? (
          <EmptyState title="No exported components" description="Nothing is reachable from another application." />
        ) : (
          <DataTable
            caption="Exported components"
            columns={[
              { key: 'kind', label: 'Kind', width: '7rem' },
              { key: 'name', label: 'Component' },
              { key: 'permission', label: 'Guarded by', width: '16rem' },
              { key: 'implied', label: 'Declared', width: '8rem' },
            ]}
          >
            {exported.map((component) => (
              <tr key={`${component.kind}:${component.name}`}>
                <td><Chip>{component.kind}</Chip></td>
                <td className="ds-mono text-[11px] break-all">{component.name}</td>
                <td className="ds-mono text-[10px] break-all text-muted">
                  {component.permission ?? <span className="text-subtle">nothing</span>}
                </td>
                <td>
                  {component.exported_implied ? (
                    <StatusBadge tone="warn">implied</StatusBadge>
                  ) : (
                    <StatusBadge tone="neutral">explicit</StatusBadge>
                  )}
                </td>
              </tr>
            ))}
          </DataTable>
        )}
      </Card>

      <Card className="mt-4">
        <CardHeader title="Scan history" description="Analyses of this APK." />
        {scans.isLoading ? (
          <LoadingState />
        ) : !scans.data || scans.data.items.length === 0 ? (
          <EmptyState title="Not yet analysed" description="Run an analysis to produce findings." />
        ) : (
          <DataTable
            caption="Scans of this application"
            columns={[
              { key: 'scan', label: 'Scan' },
              { key: 'profile', label: 'Profile', width: '6rem' },
              { key: 'status', label: 'Status', width: '8rem' },
              { key: 'findings', label: 'Findings', width: '6rem', align: 'right' },
              { key: 'when', label: 'When', width: '8rem', align: 'right' },
            ]}
          >
            {scans.data.items.map((scan) => (
              <tr key={scan.id}>
                <td>
                  <LinkButton to={`/scans/${scan.id}`} variant="ghost" className="h-auto px-0 text-xs">
                    {scan.id.slice(0, 12)}
                  </LinkButton>
                </td>
                <td className="text-muted">{scan.profile}</td>
                <td><JobStatusBadge status={scan.status} /></td>
                <td className="text-right tabular-nums">{scan.findings_total}</td>
                <td className="text-right text-muted">{formatRelative(scan.created_at)}</td>
              </tr>
            ))}
          </DataTable>
        )}
      </Card>
    </>
  );
}
