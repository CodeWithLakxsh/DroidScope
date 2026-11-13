/** Report generation and download. */

import { useState } from 'react';
import { useParams } from 'react-router-dom';
import { Download, FileText } from 'lucide-react';
import { api } from '@/lib/api';
import { ScanPicker } from '@/components/ScanPicker';
import { useCreateReport, useReports, useScan } from '@/hooks/queries';
import {
  Button,
  Card,
  CardHeader,
  DataTable,
  EmptyState,
  JobStatusBadge,
  LoadingState,
  Note,
  PageHeader,
} from '@/components/ui';
import { formatBytes, formatRelative } from '@/lib/format';
import type { ReportFormat } from '@/types/api';

const FORMATS: { value: ReportFormat; label: string; description: string }[] = [
  { value: 'pdf', label: 'PDF', description: 'Paginated report for review and distribution.' },
  { value: 'html', label: 'HTML', description: 'Same content as a self-contained web page.' },
  { value: 'json', label: 'JSON', description: 'The complete result document for tooling.' },
  { value: 'sarif', label: 'SARIF', description: 'SARIF 2.1.0 for code-scanning integrations.' },
];

export default function Reports() {
  const { scanId } = useParams<{ scanId: string }>();
  const [includeInformational, setIncludeInformational] = useState(true);
  const [includeEvidence, setIncludeEvidence] = useState(true);
  const scan = useScan(scanId);
  const reports = useReports(scanId);
  const createReport = useCreateReport();

  if (!scanId) {
    return (
      <>
        <PageHeader title="Reports" description="Generate a report from a completed scan." />
        <ScanPicker basePath="/reports" />
      </>
    );
  }

  const generate = (format: ReportFormat) =>
    createReport.mutate({
      scan_id: scanId,
      format,
      include_evidence: includeEvidence,
      include_informational: includeInformational,
    });

  return (
    <>
      <PageHeader
        title="Reports"
        description={
          scan.data
            ? `${scan.data.package_name ?? 'Application'} · ${scan.data.findings_total} findings`
            : undefined
        }
        actions={<ScanPicker basePath="/reports" currentScanId={scanId} />}
      />

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_20rem]">
        <Card>
          <CardHeader title="Generate" description="Reports are rendered from stored scan data." />
          <div className="grid gap-2 p-4 sm:grid-cols-2">
            {FORMATS.map((format) => (
              <div
                key={format.value}
                className="flex flex-col justify-between rounded-sm border p-3"
                style={{ borderColor: 'var(--border)' }}
              >
                <div>
                  <h3 className="text-sm font-semibold">{format.label}</h3>
                  <p className="mt-0.5 text-xs text-muted">{format.description}</p>
                </div>
                <Button
                  variant="primary"
                  className="mt-3 self-start"
                  onClick={() => generate(format.value)}
                  disabled={createReport.isPending}
                >
                  <FileText className="size-3.5" aria-hidden="true" />
                  {createReport.isPending && createReport.variables?.format === format.value
                    ? 'Generating…'
                    : `Generate ${format.label}`}
                </Button>
              </div>
            ))}
          </div>

          <div className="border-t px-4 py-3" style={{ borderColor: 'var(--border)' }}>
            <fieldset>
              <legend className="mb-2 text-xs font-medium">Options</legend>
              <label className="flex cursor-pointer items-center gap-2 text-xs">
                <input
                  type="checkbox"
                  checked={includeEvidence}
                  onChange={(event) => setIncludeEvidence(event.target.checked)}
                />
                Include supporting evidence
              </label>
              <label className="mt-1.5 flex cursor-pointer items-center gap-2 text-xs">
                <input
                  type="checkbox"
                  checked={includeInformational}
                  onChange={(event) => setIncludeInformational(event.target.checked)}
                />
                Include informational findings
              </label>
            </fieldset>
          </div>

          {createReport.isError ? (
            <div className="px-4 pb-3">
              <Note tone="error" title="Report generation failed">
                {(createReport.error as Error).message}
              </Note>
            </div>
          ) : null}
        </Card>

        <Card>
          <CardHeader title="Redaction" />
          <div className="px-4 py-3">
            <Note tone="accent" title="Secrets are masked by default">
              Evidence for a detected credential shows a masked preview and a non-reversible
              fingerprint. The plaintext is not stored unless a deployment explicitly opts in.
            </Note>
          </div>
        </Card>
      </div>

      <Card className="mt-4">
        <CardHeader title="Generated reports" />
        {reports.isLoading ? (
          <LoadingState />
        ) : !reports.data || reports.data.length === 0 ? (
          <EmptyState title="No reports yet" description="Generate one above." />
        ) : (
          <DataTable
            caption="Generated reports"
            columns={[
              { key: 'file', label: 'File' },
              { key: 'format', label: 'Format', width: '6rem' },
              { key: 'status', label: 'Status', width: '8rem' },
              { key: 'size', label: 'Size', width: '7rem', align: 'right' },
              { key: 'when', label: 'Created', width: '8rem', align: 'right' },
              { key: 'download', label: '', width: '7rem', align: 'right' },
            ]}
          >
            {reports.data.map((report) => (
              <tr key={report.id}>
                <td className="ds-mono text-[11px] break-all">{report.filename ?? report.id}</td>
                <td className="text-muted uppercase">{report.format}</td>
                <td><JobStatusBadge status={report.status} /></td>
                <td className="text-right tabular-nums text-muted">
                  {formatBytes(report.size_bytes)}
                </td>
                <td className="text-right text-muted">{formatRelative(report.created_at)}</td>
                <td className="text-right">
                  {report.status === 'completed' ? (
                    <a
                      href={api.reportDownloadUrl(report.id)}
                      className="inline-flex h-7 cursor-pointer items-center gap-1 rounded-sm border px-2 text-[11px]"
                      style={{ borderColor: 'var(--border)' }}
                      download
                    >
                      <Download className="size-3" aria-hidden="true" />
                      Download
                    </a>
                  ) : (
                    <span className="text-subtle">—</span>
                  )}
                </td>
              </tr>
            ))}
          </DataTable>
        )}
      </Card>
    </>
  );
}
