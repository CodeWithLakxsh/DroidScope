/**
 * Network indicator explorer.
 *
 * Indicators are presented as observations with a routing-scope classification.
 * Nothing here is labelled malicious, and DroidScope never contacts them.
 */

import { useState } from 'react';
import { useParams } from 'react-router-dom';
import { Globe } from 'lucide-react';
import { ScanPicker } from '@/components/ScanPicker';
import { useIndicators } from '@/hooks/queries';
import {
  Card,
  CardHeader,
  DataTable,
  EmptyState,
  ErrorState,
  LoadingState,
  Note,
  PageHeader,
  Select,
  StatusBadge,
} from '@/components/ui';

const SCOPE_HELP: Record<string, { tone: 'ok' | 'warn' | 'neutral' | 'error' | 'accent'; text: string }> = {
  public: { tone: 'neutral', text: 'A publicly routable destination.' },
  private: { tone: 'warn', text: 'An RFC 1918 private address: internal infrastructure.' },
  loopback: { tone: 'neutral', text: 'The device itself; normal for local development.' },
  'link-local': { tone: 'warn', text: 'A link-local address.' },
  documentation: { tone: 'neutral', text: 'A reserved documentation range or example domain.' },
  reserved: { tone: 'neutral', text: 'A reserved or special-use name.' },
  multicast: { tone: 'neutral', text: 'A multicast address.' },
  unspecified: { tone: 'neutral', text: 'An unspecified address.' },
  unknown: { tone: 'neutral', text: 'Could not be classified.' },
};

export default function Indicators() {
  const { scanId } = useParams<{ scanId: string }>();
  const [scope, setScope] = useState('');
  const [type, setType] = useState('');
  const { data, isLoading, isError, error, refetch } = useIndicators(scanId, {
    scope: scope || undefined,
    indicator_type: type || undefined,
    limit: 500,
  });

  if (!scanId) {
    return (
      <>
        <PageHeader title="Network indicators" />
        <ScanPicker basePath="/indicators" />
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Network indicators"
        description="URLs, domains and addresses extracted from the application, classified by routing scope."
        actions={<ScanPicker basePath="/indicators" currentScanId={scanId} />}
      />

      <div className="mb-4">
        <Note tone="accent" title="These are observations, not verdicts">
          An extracted destination is evidence that a string exists in the application, not that the
          application contacts it or that the destination is malicious. DroidScope never connects to
          an extracted endpoint and performs no scanning.
        </Note>
      </div>

      <Card>
        <CardHeader
          title="Indicators"
          description={data ? `${data.total} extracted` : undefined}
          actions={
            <>
              <label htmlFor="scope-filter" className="sr-only">Scope</label>
              <Select
                id="scope-filter"
                value={scope}
                onChange={(event) => setScope(event.target.value)}
                className="h-7 w-auto text-[11px]"
              >
                <option value="">All scopes</option>
                {Object.keys(SCOPE_HELP).map((item) => (
                  <option key={item} value={item}>{item}</option>
                ))}
              </Select>
              <label htmlFor="type-filter" className="sr-only">Type</label>
              <Select
                id="type-filter"
                value={type}
                onChange={(event) => setType(event.target.value)}
                className="h-7 w-auto text-[11px]"
              >
                <option value="">All types</option>
                <option value="url">URL</option>
                <option value="domain">Domain</option>
                <option value="ip">IP address</option>
              </Select>
            </>
          }
        />

        {isLoading ? (
          <LoadingState label="Loading indicators" />
        ) : isError ? (
          <ErrorState error={error} onRetry={() => refetch()} />
        ) : !data || data.items.length === 0 ? (
          <EmptyState
            icon={<Globe className="size-9" aria-hidden="true" />}
            title="No indicators extracted"
            description="No URLs, domains or addresses matched in this application's contents."
          />
        ) : (
          <DataTable
            caption="Extracted network indicators"
            staggerRows
            columns={[
              { key: 'type', label: 'Type', width: '5.5rem' },
              { key: 'value', label: 'Value' },
              { key: 'scope', label: 'Scope', width: '10rem' },
              { key: 'source', label: 'Found in', width: '14rem' },
              { key: 'count', label: 'Count', width: '4.5rem', align: 'right' },
            ]}
          >
            {data.items.map((indicator) => {
              const help = SCOPE_HELP[indicator.scope] ?? SCOPE_HELP.unknown;
              return (
                <tr key={indicator.id}>
                  <td className="text-muted">{indicator.indicator_type}</td>
                  <td className="ds-mono text-[11px] break-all">
                    {indicator.value}
                    {indicator.scheme === 'http' ? (
                      <StatusBadge tone="warn" className="ml-1.5">cleartext</StatusBadge>
                    ) : null}
                  </td>
                  <td>
                    <StatusBadge tone={help.tone} title={help.text}>
                      {indicator.scope}
                    </StatusBadge>
                  </td>
                  <td className="ds-mono text-[10px] break-all text-subtle">
                    {indicator.source_file ?? '—'}
                  </td>
                  <td className="text-right tabular-nums text-muted">{indicator.occurrences}</td>
                </tr>
              );
            })}
          </DataTable>
        )}
      </Card>
    </>
  );
}
