/**
 * Vulnerability explorer: filterable findings list with a detail panel.
 *
 * The detail panel shows the full chain a reviewer needs: what was detected,
 * the evidence, why it matters, how to verify it, how to fix it, and what the
 * detection cannot tell you.
 */

import { useMemo, useState } from 'react';
import { useParams } from 'react-router-dom';
import { Link } from 'react-router-dom';
import { AlertTriangle, ExternalLink, X } from 'lucide-react';
import { ScanPicker } from '@/components/ScanPicker';
import { useFinding, useFindings, useReviewFinding, useScan } from '@/hooks/queries';
import {
  Button,
  Card,
  CardHeader,
  Chip,
  DataTable,
  EmptyState,
  ErrorState,
  Input,
  LoadingState,
  Note,
  PageHeader,
  Select,
  SeverityBadge,
  StatusBadge,
} from '@/components/ui';
import { SEVERITY_ORDER, titleCase } from '@/lib/format';
import type { FindingStatus, Severity } from '@/types/api';

const REVIEW_STATUSES: { value: FindingStatus; label: string; help: string }[] = [
  { value: 'open', label: 'Open', help: 'Not yet triaged.' },
  { value: 'confirmed', label: 'Confirmed', help: 'Verified as a real issue.' },
  { value: 'false_positive', label: 'False positive', help: 'Not an issue; excluded from the risk score.' },
  { value: 'accepted_risk', label: 'Accepted risk', help: 'Real but accepted; contributes little to the score.' },
  { value: 'resolved', label: 'Resolved', help: 'Fixed; excluded from the risk score.' },
];

export default function Findings() {
  const { scanId } = useParams<{ scanId: string }>();
  const [severity, setSeverity] = useState<string[]>([]);
  const [status, setStatus] = useState('');
  const [engine, setEngine] = useState('');
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState<string | null>(null);

  const scan = useScan(scanId);
  const filters = useMemo(
    () => ({
      severity: severity.length ? severity : undefined,
      status: status ? [status] : undefined,
      engine: engine || undefined,
      search: search.trim() || undefined,
      limit: 300,
    }),
    [severity, status, engine, search],
  );
  const findings = useFindings(scanId, filters);

  if (!scanId) {
    return (
      <>
        <PageHeader title="Findings" description="Select a completed scan to review its findings." />
        <ScanPicker basePath="/findings" />
      </>
    );
  }

  const engines = [...new Set((findings.data?.items ?? []).map((item) => item.analysis_engine))].sort();

  const toggleSeverity = (value: string) => {
    setSeverity((current) =>
      current.includes(value) ? current.filter((item) => item !== value) : [...current, value],
    );
  };

  return (
    <>
      <PageHeader
        title="Findings"
        description={
          scan.data
            ? `${scan.data.findings_total} findings from ${scan.data.package_name ?? 'this application'}`
            : undefined
        }
        actions={<ScanPicker basePath="/findings" currentScanId={scanId} />}
      />

      <Card className="mb-4">
        <div className="flex flex-wrap items-end gap-3 px-4 py-3">
          <div className="min-w-[14rem] flex-1">
            <label htmlFor="finding-search" className="mb-1 block text-xs font-medium">
              Search
            </label>
            <Input
              id="finding-search"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Title, description or component"
            />
          </div>
          <div>
            <label htmlFor="status-filter" className="mb-1 block text-xs font-medium">
              Review status
            </label>
            <Select
              id="status-filter"
              value={status}
              onChange={(event) => setStatus(event.target.value)}
              className="w-auto"
            >
              <option value="">Any status</option>
              {REVIEW_STATUSES.map((item) => (
                <option key={item.value} value={item.value}>
                  {item.label}
                </option>
              ))}
            </Select>
          </div>
          <div>
            <label htmlFor="engine-filter" className="mb-1 block text-xs font-medium">
              Analysis engine
            </label>
            <Select
              id="engine-filter"
              value={engine}
              onChange={(event) => setEngine(event.target.value)}
              className="w-auto"
            >
              <option value="">Any engine</option>
              {engines.map((item) => (
                <option key={item} value={item}>
                  {item}
                </option>
              ))}
            </Select>
          </div>
        </div>

        <div
          className="flex flex-wrap items-center gap-1.5 border-t px-4 py-2.5"
          style={{ borderColor: 'var(--border)' }}
        >
          <span className="mr-1 text-xs font-medium">Severity</span>
          {SEVERITY_ORDER.map((item) => {
            const active = severity.includes(item);
            return (
              <button
                key={item}
                type="button"
                aria-pressed={active}
                onClick={() => toggleSeverity(item)}
                className="cursor-pointer rounded-xs transition-opacity"
                style={{ opacity: active || severity.length === 0 ? 1 : 0.4 }}
              >
                <SeverityBadge severity={item} />
              </button>
            );
          })}
          {severity.length > 0 || status || engine || search ? (
            <Button
              variant="ghost"
              className="ml-auto"
              onClick={() => {
                setSeverity([]);
                setStatus('');
                setEngine('');
                setSearch('');
              }}
            >
              Clear filters
            </Button>
          ) : null}
        </div>
      </Card>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_28rem]">
        <Card>
          <CardHeader
            title="Results"
            description={
              findings.data
                ? `${findings.data.total} finding${findings.data.total === 1 ? '' : 's'} match`
                : undefined
            }
          />
          {findings.isLoading ? (
            <LoadingState label="Loading findings" />
          ) : findings.isError ? (
            <ErrorState error={findings.error} onRetry={() => findings.refetch()} />
          ) : !findings.data || findings.data.items.length === 0 ? (
            <EmptyState
              icon={<AlertTriangle className="size-9" aria-hidden="true" />}
              title="No findings match these filters"
              description={
                scan.data && scan.data.findings_total === 0
                  ? 'This scan produced no findings. That is not evidence the application is secure — check the scan limitations.'
                  : 'Try widening the filters.'
              }
            />
          ) : (
            <DataTable
              caption="Findings"
              fixed
              staggerRows
              columns={[
                { key: 'severity', label: 'Severity', width: '7.5rem' },
                { key: 'title', label: 'Finding' },
                { key: 'confidence', label: 'Confidence', width: '6rem' },
                { key: 'status', label: 'Status', width: '8rem' },
              ]}
            >
              {findings.data.items.map((finding) => (
                <tr
                  key={finding.id}
                  onClick={() => setSelected(finding.id)}
                  className="cursor-pointer"
                  style={
                    selected === finding.id
                      ? { backgroundColor: 'var(--surface-hover)' }
                      : undefined
                  }
                >
                  <td>
                    <SeverityBadge severity={finding.severity} />
                  </td>
                  {/* max-w-0 lets this cell shrink below its content width so a
                      long file path cannot force the whole table to overflow. */}
                  <td className="max-w-0">
                    <button
                      type="button"
                      className="block w-full cursor-pointer truncate text-left font-medium hover:underline"
                      onClick={() => setSelected(finding.id)}
                      title={finding.title}
                    >
                      {finding.title}
                    </button>
                    <div className="mt-0.5 flex items-center gap-1 text-[11px] text-subtle">
                      <span className="ds-mono shrink-0">{finding.rule_id}</span>
                      {finding.file_path ? (
                        <span
                          className="ds-mono truncate"
                          title={`${finding.file_path}${finding.line_number ? `:${finding.line_number}` : ''}`}
                        >
                          · {finding.file_path}
                          {finding.line_number ? `:${finding.line_number}` : ''}
                        </span>
                      ) : finding.affected_component ? (
                        <span className="ds-mono truncate" title={finding.affected_component}>
                          · {finding.affected_component}
                        </span>
                      ) : null}
                    </div>
                  </td>
                  <td className="text-muted">{finding.confidence}</td>
                  <td>
                    <StatusBadge
                      tone={
                        finding.status === 'confirmed'
                          ? 'error'
                          : finding.status === 'false_positive' || finding.status === 'resolved'
                            ? 'ok'
                            : finding.status === 'accepted_risk'
                              ? 'warn'
                              : 'neutral'
                      }
                    >
                      {finding.status.replace(/_/g, ' ')}
                    </StatusBadge>
                  </td>
                </tr>
              ))}
            </DataTable>
          )}
        </Card>

        <div className="xl:sticky xl:top-4 xl:self-start">
          <FindingPanel findingId={selected} onClose={() => setSelected(null)} />
        </div>
      </div>
    </>
  );
}

function FindingPanel({ findingId, onClose }: { findingId: string | null; onClose: () => void }) {
  const { data: finding, isLoading, isError, error } = useFinding(findingId ?? undefined);
  const review = useReviewFinding();
  const [note, setNote] = useState('');

  if (!findingId) {
    return (
      <Card>
        <EmptyState
          title="Select a finding"
          description="Choose a finding to see its evidence, impact, verification steps and remediation."
        />
      </Card>
    );
  }
  if (isLoading) return <Card><LoadingState label="Loading finding" /></Card>;
  if (isError) return <Card><ErrorState error={error} /></Card>;
  if (!finding) return null;

  return (
    <Card className="ds-animate-slide-in">
      <CardHeader
        title={
          <span className="flex items-start gap-2">
            <SeverityBadge severity={finding.severity as Severity} />
            <span>{finding.title}</span>
          </span>
        }
        actions={
          <button type="button" onClick={onClose} aria-label="Close finding detail" className="cursor-pointer p-1">
            <X className="size-4" />
          </button>
        }
      />

      <div className="max-h-[calc(100vh-14rem)] space-y-4 overflow-y-auto px-4 py-3 text-xs">
        <div className="flex flex-wrap gap-1">
          <Chip>{finding.rule_id} v{finding.rule_version}</Chip>
          <Chip>{finding.analysis_engine}</Chip>
          <Chip>confidence: {finding.confidence}</Chip>
          <Chip>{titleCase(finding.category)}</Chip>
          {finding.cwe_ids.map((cwe) => (
            <Chip key={cwe}>{cwe}</Chip>
          ))}
          {finding.masvs_controls.map((control) => (
            <Chip key={control}>{control}</Chip>
          ))}
        </div>

        <section>
          <h3 className="mb-1 text-xs font-semibold">Description</h3>
          <p className="text-muted">{finding.description}</p>
        </section>

        {finding.affected_component || finding.file_path ? (
          <section>
            <h3 className="mb-1 text-xs font-semibold">Location</h3>
            <p className="ds-mono text-[11px] break-all text-muted">
              {finding.affected_component}
              {finding.file_path ? (
                <>
                  {finding.affected_component ? ' — ' : ''}
                  {finding.file_path}
                  {finding.line_number ? `:${finding.line_number}` : ''}
                </>
              ) : null}
            </p>
          </section>
        ) : null}

        {finding.evidence.length > 0 ? (
          <section>
            <h3 className="mb-1 text-xs font-semibold">Evidence</h3>
            <div className="space-y-2">
              {finding.evidence.map((item, index) => (
                <div
                  key={index}
                  className="rounded-sm border p-2"
                  style={{ borderColor: 'var(--border)', backgroundColor: 'var(--surface-sunken)' }}
                >
                  <div className="flex items-start justify-between gap-2">
                    <p className="text-[11px] text-muted">{item.description}</p>
                    {item.sensitive ? <StatusBadge tone="warn">masked</StatusBadge> : null}
                  </div>
                  {item.snippet ? (
                    <pre className="ds-mono mt-1.5 overflow-x-auto rounded-xs p-2 text-[11px] whitespace-pre-wrap"
                      style={{ backgroundColor: 'var(--surface)', color: 'var(--text)' }}>
                      {item.snippet}
                    </pre>
                  ) : null}
                  {item.file_path ? (
                    <p className="ds-mono mt-1 text-[10px] text-subtle">
                      {item.file_path}
                      {item.line_number ? `:${item.line_number}` : ''}
                    </p>
                  ) : null}
                </div>
              ))}
            </div>
          </section>
        ) : null}

        <section>
          <h3 className="mb-1 text-xs font-semibold">Security impact</h3>
          <p className="text-muted">{finding.impact}</p>
        </section>

        <section>
          <h3 className="mb-1 text-xs font-semibold">Remediation</h3>
          <p className="text-muted">{finding.remediation}</p>
        </section>

        {finding.verification ? (
          <section>
            <h3 className="mb-1 text-xs font-semibold">How to verify</h3>
            <p className="text-muted">{finding.verification}</p>
          </section>
        ) : null}

        {finding.limitations ? (
          <Note tone="warn" title="Detection limitations">
            {finding.limitations}
          </Note>
        ) : null}

        {finding.references.length > 0 ? (
          <section>
            <h3 className="mb-1 text-xs font-semibold">References</h3>
            <ul className="space-y-0.5">
              {finding.references.map((reference) => (
                <li key={reference}>
                  <a
                    href={reference}
                    target="_blank"
                    rel="noreferrer noopener"
                    className="ds-mono inline-flex items-start gap-1 text-[11px] break-all hover:underline"
                    style={{ color: 'var(--accent)' }}
                  >
                    {reference}
                    <ExternalLink className="mt-0.5 size-3 shrink-0" aria-hidden="true" />
                  </a>
                </li>
              ))}
            </ul>
          </section>
        ) : null}

        <section className="border-t pt-3" style={{ borderColor: 'var(--border)' }}>
          <h3 className="mb-1.5 text-xs font-semibold">Review</h3>
          <label htmlFor="review-note" className="mb-1 block text-[11px] text-muted">
            Note (optional)
          </label>
          <Input
            id="review-note"
            value={note}
            onChange={(event) => setNote(event.target.value)}
            placeholder="Why this decision?"
            className="mb-2"
          />
          <div className="flex flex-wrap gap-1.5">
            {REVIEW_STATUSES.map((item) => (
              <Button
                key={item.value}
                title={item.help}
                variant={finding.status === item.value ? 'primary' : 'secondary'}
                disabled={review.isPending}
                onClick={() =>
                  review.mutate({ findingId: finding.id, status: item.value, note: note || undefined })
                }
              >
                {item.label}
              </Button>
            ))}
          </div>
          {finding.reviews.length > 0 ? (
            <ul className="mt-2 space-y-1 text-[11px] text-subtle">
              {finding.reviews.map((entry, index) => (
                <li key={index}>
                  {entry.previous_status.replace(/_/g, ' ')} → {entry.new_status.replace(/_/g, ' ')}
                  {entry.note ? ` — ${entry.note}` : ''}
                </li>
              ))}
            </ul>
          ) : null}
        </section>

        {finding.file_path ? (
          <Link
            to={`/code/${finding.scan_id}?path=${encodeURIComponent(finding.file_path)}`}
            className="inline-block text-[11px] hover:underline"
            style={{ color: 'var(--accent)' }}
          >
            Open in code explorer →
          </Link>
        ) : null}
      </div>
    </Card>
  );
}
