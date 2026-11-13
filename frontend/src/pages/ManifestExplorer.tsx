/** AndroidManifest explorer: raw XML and a structured component view. */

import { useState } from 'react';
import { useParams } from 'react-router-dom';
import { useApk, useApks, useManifest } from '@/hooks/queries';
import {
  Card,
  CardHeader,
  Chip,
  DataTable,
  EmptyState,
  ErrorState,
  KeyValue,
  LinkButton,
  LoadingState,
  Note,
  PageHeader,
  StatusBadge,
} from '@/components/ui';
import { titleCase } from '@/lib/format';
import type { Component } from '@/types/api';

type Tab = 'structured' | 'raw';

export default function ManifestExplorer() {
  const { apkId } = useParams<{ apkId: string }>();
  const [tab, setTab] = useState<Tab>('structured');
  const apks = useApks({ limit: 50 });
  const apk = useApk(apkId);
  const manifest = useManifest(apkId);

  if (!apkId) {
    return (
      <>
        <PageHeader title="Manifest explorer" />
        {apks.isLoading ? (
          <LoadingState />
        ) : !apks.data || apks.data.items.length === 0 ? (
          <Card>
            <EmptyState
              title="No applications"
              description="Upload an APK to inspect its manifest."
              action={<LinkButton to="/upload" variant="primary">Upload APK</LinkButton>}
            />
          </Card>
        ) : (
          <Card>
            <CardHeader title="Choose an application" />
            <ul className="divide-y" style={{ borderColor: 'var(--border)' }}>
              {apks.data.items.map((item) => (
                <li key={item.id}>
                  <a
                    href={`/manifest/${item.id}`}
                    className="block px-4 py-2 text-sm hover:underline"
                    style={{ color: 'var(--accent)' }}
                  >
                    {item.app_label ?? item.package_name ?? item.original_filename}
                  </a>
                </li>
              ))}
            </ul>
          </Card>
        )}
      </>
    );
  }

  if (apk.isLoading) return <LoadingState label="Loading manifest" />;
  if (apk.isError) return <ErrorState error={apk.error} onRetry={() => apk.refetch()} />;
  if (!apk.data) return null;

  const metadata = apk.data.apk_metadata;
  const flags = metadata.application_flags ?? {};
  const components = metadata.components ?? [];
  const byKind = (kind: Component['kind']) => components.filter((c) => c.kind === kind);

  return (
    <>
      <PageHeader
        title="Manifest explorer"
        description={<span className="ds-mono text-xs">{metadata.package_name}</span>}
        actions={
          <div className="flex gap-1" role="tablist" aria-label="Manifest view">
            {(['structured', 'raw'] as Tab[]).map((item) => (
              <button
                key={item}
                role="tab"
                aria-selected={tab === item}
                onClick={() => setTab(item)}
                className="cursor-pointer rounded-sm border px-2.5 py-1 text-xs"
                style={
                  tab === item
                    ? { backgroundColor: 'var(--accent)', color: 'var(--accent-text)', borderColor: 'var(--accent)' }
                    : { borderColor: 'var(--border)' }
                }
              >
                {item === 'structured' ? 'Structured' : 'Raw XML'}
              </button>
            ))}
          </div>
        }
      />

      {tab === 'raw' ? (
        <Card>
          <CardHeader title="AndroidManifest.xml" description="Decoded from binary AXML." />
          {manifest.isLoading ? (
            <LoadingState />
          ) : manifest.isError ? (
            <div className="p-4">
              <Note tone="warn" title="The decoded manifest is unavailable">
                {(manifest.error as Error).message}
              </Note>
            </div>
          ) : (
            <pre
              className="ds-mono max-h-[70vh] overflow-auto p-4 text-[11px] whitespace-pre"
              style={{ backgroundColor: 'var(--surface-sunken)' }}
            >
              {manifest.data}
            </pre>
          )}
        </Card>
      ) : (
        <div className="space-y-4">
          <Card>
            <CardHeader title="Application configuration" />
            <KeyValue
              rows={[
                { label: 'Package', value: metadata.package_name ?? '—', mono: true },
                { label: 'Version', value: `${metadata.version_name ?? '?'} (${metadata.version_code ?? '?'})` },
                {
                  label: 'SDK',
                  value: `min ${metadata.min_sdk ?? '?'}, target ${metadata.target_sdk ?? '?'}, compile ${metadata.compile_sdk ?? '?'}`,
                },
                {
                  label: 'Debuggable',
                  value: <FlagValue value={flags.debuggable} dangerousWhenTrue />,
                },
                {
                  label: 'Allow backup',
                  value: <FlagValue value={flags.allow_backup} dangerousWhenTrue nullMeans="defaults to true" />,
                },
                {
                  label: 'Cleartext traffic',
                  value: <FlagValue value={flags.uses_cleartext_traffic} dangerousWhenTrue nullMeans="not declared" />,
                },
                {
                  label: 'Network security config',
                  value: flags.network_security_config ?? 'not declared',
                  mono: true,
                },
                { label: 'Test only', value: <FlagValue value={flags.test_only} dangerousWhenTrue /> },
                {
                  label: 'Application class',
                  value: flags.custom_application_class ?? 'default',
                  mono: true,
                },
              ]}
            />
          </Card>

          <Card>
            <CardHeader
              title="Permissions"
              description={`${metadata.requested_permissions.length} requested, ${metadata.declared_permissions.length} declared`}
            />
            {metadata.requested_permissions.length === 0 ? (
              <EmptyState title="No permissions requested" />
            ) : (
              <DataTable
                caption="Requested permissions"
                columns={[
                  { key: 'name', label: 'Permission' },
                  { key: 'level', label: 'Protection level', width: '12rem' },
                  { key: 'dangerous', label: 'Runtime', width: '7rem' },
                ]}
              >
                {metadata.requested_permissions.map((permission) => (
                  <tr key={permission.name}>
                    <td className="ds-mono text-[11px]">{permission.name}</td>
                    <td className="text-muted">{permission.protection_level ?? 'normal'}</td>
                    <td>
                      {permission.is_dangerous ? (
                        <StatusBadge tone="warn">dangerous</StatusBadge>
                      ) : (
                        <span className="text-subtle">normal</span>
                      )}
                    </td>
                  </tr>
                ))}
              </DataTable>
            )}
          </Card>

          {(['activity', 'service', 'receiver', 'provider'] as Component['kind'][]).map((kind) => {
            const items = byKind(kind);
            if (items.length === 0) return null;
            return (
              <Card key={kind}>
                <CardHeader
                  title={`${titleCase(kind)}s`}
                  description={`${items.length} declared, ${items.filter((c) => c.exported).length} exported`}
                />
                <DataTable
                  caption={`${kind} components`}
                  columns={[
                    { key: 'name', label: 'Component' },
                    { key: 'exported', label: 'Exported', width: '9rem' },
                    { key: 'permission', label: 'Permission', width: '14rem' },
                    { key: 'filters', label: 'Intent filters', width: '8rem' },
                  ]}
                >
                  {items.map((component) => (
                    <tr key={component.name}>
                      <td className="ds-mono text-[11px] break-all">{component.name}</td>
                      <td>
                        {component.exported ? (
                          <StatusBadge tone={component.permission ? 'warn' : 'error'}>
                            {component.exported_implied ? 'implied' : 'yes'}
                          </StatusBadge>
                        ) : (
                          <StatusBadge tone="ok">no</StatusBadge>
                        )}
                      </td>
                      <td className="ds-mono text-[10px] break-all text-muted">
                        {component.permission ?? '—'}
                        {component.permission_protection_level ? (
                          <span className="block text-subtle">
                            ({component.permission_protection_level})
                          </span>
                        ) : null}
                      </td>
                      <td>
                        {component.intent_filters.length === 0 ? (
                          <span className="text-subtle">none</span>
                        ) : (
                          <span className="flex flex-wrap gap-1">
                            {component.intent_filters.slice(0, 3).map((filter, index) => (
                              <Chip key={index}>
                                {filter.actions[0]?.split('.').pop() ?? 'filter'}
                              </Chip>
                            ))}
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </DataTable>
              </Card>
            );
          })}
        </div>
      )}
    </>
  );
}

function FlagValue({
  value,
  dangerousWhenTrue,
  nullMeans,
}: {
  value: boolean | null | undefined;
  dangerousWhenTrue?: boolean;
  nullMeans?: string;
}) {
  if (value === null || value === undefined) {
    return <span className="text-subtle">{nullMeans ?? 'not declared'}</span>;
  }
  if (value && dangerousWhenTrue) return <StatusBadge tone="error">true</StatusBadge>;
  if (!value && dangerousWhenTrue) return <StatusBadge tone="ok">false</StatusBadge>;
  return <span>{String(value)}</span>;
}
