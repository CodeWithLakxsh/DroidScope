/** Operational settings and environment capabilities. */

import { useEffect, useState } from 'react';
import { useCapabilities, useRules, useSettings, useUpdateSettings } from '@/hooks/queries';
import {
  Button,
  Card,
  CardHeader,
  DataTable,
  ErrorState,
  Field,
  Input,
  LoadingState,
  Note,
  PageHeader,
  SeverityBadge,
  StatusBadge,
} from '@/components/ui';
import { formatBytes } from '@/lib/format';
import type { SettingsOut } from '@/types/api';

export default function SettingsPage() {
  const settings = useSettings();
  const capabilities = useCapabilities();
  const rules = useRules();
  const update = useUpdateSettings();
  const [draft, setDraft] = useState<Partial<SettingsOut>>({});

  useEffect(() => {
    if (settings.data) setDraft({});
  }, [settings.data]);

  if (settings.isLoading) return <LoadingState label="Loading settings" />;
  if (settings.isError) return <ErrorState error={settings.error} onRetry={() => settings.refetch()} />;
  if (!settings.data) return null;

  const current = { ...settings.data, ...draft };
  const dirty = Object.keys(draft).length > 0;

  const numberField = (
    key: keyof SettingsOut,
    label: string,
    hint: string,
    min: number,
    max: number,
  ) => (
    <Field label={label} htmlFor={key} hint={hint}>
      <Input
        id={key}
        type="number"
        min={min}
        max={max}
        value={String(current[key] ?? '')}
        onChange={(event) =>
          setDraft((previous) => ({ ...previous, [key]: Number(event.target.value) }))
        }
      />
    </Field>
  );

  const toggleField = (key: keyof SettingsOut, label: string, hint: string) => (
    <label className="flex cursor-pointer items-start gap-2.5 py-1.5">
      <input
        type="checkbox"
        className="mt-0.5"
        checked={Boolean(current[key])}
        onChange={(event) =>
          setDraft((previous) => ({ ...previous, [key]: event.target.checked }))
        }
      />
      <span>
        <span className="block text-xs font-medium">{label}</span>
        <span className="block text-xs text-muted">{hint}</span>
      </span>
    </label>
  );

  return (
    <>
      <PageHeader
        title="Settings"
        description="Operational configuration for this DroidScope instance."
        actions={
          <Button
            variant="primary"
            disabled={!dirty || update.isPending}
            onClick={() => update.mutate(draft)}
          >
            {update.isPending ? 'Saving…' : 'Save changes'}
          </Button>
        }
      />

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader title="Analysis" />
          <div className="space-y-3 px-4 py-3">
            {numberField('analysis_concurrency', 'Concurrent analyses', 'How many scans a worker runs at once.', 1, 16)}
            {numberField('analyzer_timeout_seconds', 'Analyzer timeout (s)', 'Per-analyzer time budget.', 30, 7200)}
            {numberField('decompile_timeout_seconds', 'Decompile timeout (s)', 'Time budget for JADX.', 30, 7200)}
            {numberField('artifact_retention_days', 'Artifact retention (days)', 'How long decompiled output is kept.', 1, 3650)}
            {toggleField('reuse_identical_scans', 'Reuse identical scans', 'Return an existing completed scan when the APK and configuration match.')}
          </div>
        </Card>

        <Card>
          <CardHeader title="Security" />
          <div className="space-y-1 px-4 py-3">
            {toggleField('redact_secrets_in_reports', 'Redact secrets in reports', 'Store and render a mask plus a fingerprint instead of the plaintext.')}
            {toggleField('dynamic_analysis_enabled', 'Enable dynamic analysis', 'Permits installing and running an uploaded application on a selected device.')}
            {toggleField('dynamic_allow_physical_devices', 'Allow physical devices', 'Without this, only emulators may be selected for a dynamic session.')}
          </div>
          <div className="px-4 pb-3">
            <Note tone="warn" title="Tool paths are not configurable through the API">
              A writable executable path would be a command execution primitive. Point DroidScope at
              a different tool with the DROIDSCOPE_*_PATH environment variables instead.
            </Note>
          </div>
        </Card>

        <Card>
          <CardHeader title="Limits" description="Read-only; set through environment variables." />
          <div className="space-y-2 px-4 py-3 text-xs">
            <div className="flex justify-between">
              <span className="text-muted">Maximum upload size</span>
              <span className="ds-mono">{formatBytes(settings.data.max_upload_bytes)}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted">Scan timeout</span>
              <span className="ds-mono">{settings.data.scan_timeout_seconds}s</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted">Log level</span>
              <span className="ds-mono">{settings.data.log_level}</span>
            </div>
          </div>
        </Card>

        <Card>
          <CardHeader
            title="Environment"
            description={capabilities.data ? `${capabilities.data.rules_loaded} rules loaded` : undefined}
          />
          <div className="px-4 py-3">
            <ul className="space-y-1 text-xs">
              {Object.entries(settings.data.tools).map(([name, available]) => (
                <li key={name} className="flex items-center justify-between gap-2">
                  <span className="ds-mono text-[11px]">{name}</span>
                  <StatusBadge tone={available ? 'ok' : 'warn'}>
                    {available ? 'available' : 'missing'}
                  </StatusBadge>
                </li>
              ))}
            </ul>
          </div>
        </Card>
      </div>

      <Card className="mt-4">
        <CardHeader
          title="Detection rules"
          description={rules.data ? `${rules.data.length} rules loaded` : undefined}
        />
        {rules.isLoading ? (
          <LoadingState />
        ) : rules.data ? (
          <DataTable
            caption="Loaded detection rules"
            columns={[
              { key: 'id', label: 'Rule', width: '11rem' },
              { key: 'severity', label: 'Severity', width: '7.5rem' },
              { key: 'name', label: 'Name' },
              { key: 'engine', label: 'Engine', width: '13rem' },
              { key: 'mappings', label: 'Mappings', width: '16rem' },
            ]}
          >
            {rules.data.map((rule) => (
              <tr key={rule.id}>
                <td className="ds-mono text-[11px]">{rule.id}</td>
                <td><SeverityBadge severity={rule.severity} /></td>
                <td>{rule.name}</td>
                <td className="ds-mono text-[10px] text-muted">{rule.engine}</td>
                <td className="text-[10px] text-muted">
                  {[...rule.cwe_ids, ...rule.masvs_controls].join(', ') || '—'}
                </td>
              </tr>
            ))}
          </DataTable>
        ) : null}
      </Card>
    </>
  );
}
