/** APK version comparison. */

import { useState } from 'react';
import { GitCompare } from 'lucide-react';
import { useApks, useCompare } from '@/hooks/queries';
import {
  Button,
  Card,
  CardHeader,
  DataTable,
  EmptyState,
  Field,
  LinkButton,
  LoadingState,
  Note,
  PageHeader,
  Select,
  SeverityBadge,
  StatTile,
  StatusBadge,
} from '@/components/ui';
import type { Severity } from '@/types/api';

export default function Compare() {
  const apks = useApks({ limit: 100 });
  const compare = useCompare();
  const [baseline, setBaseline] = useState('');
  const [updated, setUpdated] = useState('');

  const options = apks.data?.items ?? [];
  const canCompare = baseline && updated && baseline !== updated;

  return (
    <>
      <PageHeader
        title="Compare APKs"
        description="Differences between two versions: permissions, components, signing and findings."
      />

      {apks.isLoading ? (
        <LoadingState label="Loading applications" />
      ) : options.length < 2 ? (
        <Card>
          <EmptyState
            icon={<GitCompare className="size-9" aria-hidden="true" />}
            title="Two APKs are needed to compare"
            description={`You have ${options.length} uploaded. Upload another version to compare against.`}
            action={<LinkButton to="/upload" variant="primary">Upload APK</LinkButton>}
          />
        </Card>
      ) : (
        <>
          <Card className="mb-4">
            <div className="flex flex-wrap items-end gap-3 px-4 py-3">
              <Field label="Baseline (older)" htmlFor="baseline-select" className="min-w-[16rem] flex-1">
                <Select
                  id="baseline-select"
                  value={baseline}
                  onChange={(event) => setBaseline(event.target.value)}
                >
                  <option value="">Select an APK</option>
                  {options.map((apk) => (
                    <option key={apk.id} value={apk.id}>
                      {apk.package_name ?? apk.original_filename} · {apk.version_name ?? '?'}
                    </option>
                  ))}
                </Select>
              </Field>
              <Field label="Updated (newer)" htmlFor="updated-select" className="min-w-[16rem] flex-1">
                <Select
                  id="updated-select"
                  value={updated}
                  onChange={(event) => setUpdated(event.target.value)}
                >
                  <option value="">Select an APK</option>
                  {options.map((apk) => (
                    <option key={apk.id} value={apk.id}>
                      {apk.package_name ?? apk.original_filename} · {apk.version_name ?? '?'}
                    </option>
                  ))}
                </Select>
              </Field>
              <Button
                variant="primary"
                size="md"
                disabled={!canCompare || compare.isPending}
                onClick={() =>
                  compare.mutate({ baseline_apk_id: baseline, updated_apk_id: updated })
                }
              >
                {compare.isPending ? 'Comparing…' : 'Compare'}
              </Button>
            </div>
            {baseline && updated && baseline === updated ? (
              <div className="px-4 pb-3">
                <Note tone="warn">Select two different APKs.</Note>
              </div>
            ) : null}
            {compare.isError ? (
              <div className="px-4 pb-3">
                <Note tone="error" title="Comparison failed">
                  {(compare.error as Error).message}
                </Note>
              </div>
            ) : null}
          </Card>

          {compare.data ? <ComparisonView data={compare.data} /> : null}
        </>
      )}
    </>
  );
}

function ComparisonView({ data }: { data: import('@/types/api').ComparisonResult }) {
  const result = data.result;
  const summary = data.summary as Record<string, number | boolean | string>;

  return (
    <div className="space-y-4">
      <section className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
        <StatTile label="Permissions +" value={String(summary.permissions_added ?? 0)} tone={Number(summary.permissions_added) > 0 ? 'medium' : undefined} />
        <StatTile label="Permissions −" value={String(summary.permissions_removed ?? 0)} />
        <StatTile label="Components +" value={String(summary.components_added ?? 0)} />
        <StatTile label="Exported +" value={String(summary.exported_added ?? 0)} tone={Number(summary.exported_added) > 0 ? 'high' : undefined} />
        <StatTile label="New findings" value={String(summary.findings_new ?? 0)} tone={Number(summary.findings_new) > 0 ? 'high' : undefined} />
        <StatTile label="Resolved" value={String(summary.findings_resolved ?? 0)} />
      </section>

      <Card>
        <CardHeader
          title="Signing certificate"
          actions={
            result.signing.changed ? (
              <StatusBadge tone="error">changed</StatusBadge>
            ) : (
              <StatusBadge tone="ok">unchanged</StatusBadge>
            )
          }
        />
        <p className="px-4 py-3 text-xs text-muted">{result.signing.note}</p>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <DiffCard title="Permissions" diff={result.permissions} />
        <DiffCard title="Components" diff={result.components} />
        <DiffCard title="Exported components" diff={result.exported_components} />
        <DiffCard title="Native libraries" diff={result.native_libraries} />
      </div>

      {Object.keys(result.sdk_changes).length > 0 || Object.keys(result.application_flag_changes).length > 0 ? (
        <Card>
          <CardHeader title="Configuration changes" />
          <DataTable
            caption="Changed configuration"
            columns={[
              { key: 'field', label: 'Field' },
              { key: 'baseline', label: 'Baseline', width: '12rem' },
              { key: 'updated', label: 'Updated', width: '12rem' },
            ]}
          >
            {[
              ...Object.entries(result.sdk_changes),
              ...Object.entries(result.application_flag_changes),
            ].map(([field, change]) => (
              <tr key={field}>
                <td className="ds-mono text-[11px]">{field}</td>
                <td className="ds-mono text-[11px] text-muted">{String(change.baseline)}</td>
                <td className="ds-mono text-[11px]">{String(change.updated)}</td>
              </tr>
            ))}
          </DataTable>
        </Card>
      ) : null}

      <Card>
        <CardHeader title="Findings" description={result.scans.note} />
        {!result.findings.available ? (
          <EmptyState
            title="Finding comparison unavailable"
            description="Both APKs need a completed scan before their findings can be correlated."
          />
        ) : (
          <div className="grid gap-4 p-4 lg:grid-cols-2">
            <FindingList title="New in the updated version" items={result.findings.new} tone="error" />
            <FindingList title="Resolved since the baseline" items={result.findings.resolved} tone="ok" />
          </div>
        )}
      </Card>
    </div>
  );
}

function DiffCard({
  title,
  diff,
}: {
  title: string;
  diff: { added: string[]; removed: string[]; unchanged: string[] };
}) {
  const hasChanges = diff.added.length > 0 || diff.removed.length > 0;
  return (
    <Card>
      <CardHeader
        title={title}
        description={`${diff.added.length} added, ${diff.removed.length} removed, ${diff.unchanged.length} unchanged`}
      />
      {!hasChanges ? (
        <p className="px-4 py-3 text-xs text-muted">No changes.</p>
      ) : (
        <ul className="max-h-64 space-y-0.5 overflow-y-auto px-4 py-3 text-[11px]">
          {diff.added.map((item) => (
            <li key={`+${item}`} className="ds-mono break-all" style={{ color: 'var(--status-ok)' }}>
              + {item}
            </li>
          ))}
          {diff.removed.map((item) => (
            <li key={`-${item}`} className="ds-mono break-all" style={{ color: 'var(--status-error)' }}>
              − {item}
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

function FindingList({
  title,
  items,
  tone,
}: {
  title: string;
  items: { rule_id: string; title: string; severity: string }[];
  tone: 'ok' | 'error';
}) {
  return (
    <div>
      <h3 className="mb-2 flex items-center gap-2 text-xs font-semibold">
        {title}
        <StatusBadge tone={tone}>{items.length}</StatusBadge>
      </h3>
      {items.length === 0 ? (
        <p className="text-xs text-muted">None.</p>
      ) : (
        <ul className="max-h-64 space-y-1 overflow-y-auto">
          {items.map((item, index) => (
            <li key={`${item.rule_id}-${index}`} className="flex items-start gap-1.5 text-[11px]">
              <SeverityBadge severity={item.severity as Severity} showLabel={false} />
              <span className="min-w-0">
                <span className="ds-mono text-[10px] text-subtle">{item.rule_id}</span>{' '}
                {item.title}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
