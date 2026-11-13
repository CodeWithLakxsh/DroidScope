/** Native library inspection results. */

import { useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Binary } from 'lucide-react';
import { ScanPicker } from '@/components/ScanPicker';
import { useArtifacts, useScan } from '@/hooks/queries';
import {
  Card,
  CardHeader,
  Chip,
  DataTable,
  EmptyState,
  LoadingState,
  Note,
  PageHeader,
  StatusBadge,
} from '@/components/ui';
import { formatBytes } from '@/lib/format';

export default function BinaryAnalysis() {
  const { scanId } = useParams<{ scanId: string }>();
  const scan = useScan(scanId);
  const artifacts = useArtifacts(scanId);

  // The native analyzer stores its full output as a scan artifact; the scan
  // export carries it, so read it from there rather than adding an endpoint.
  const analysis = useQuery({
    queryKey: ['native-analysis', scanId],
    enabled: Boolean(scanId),
    queryFn: async () => {
      const response = await fetch(`/api/v1/scans/${scanId}/export`);
      if (!response.ok) throw new Error('could not load the scan export');
      const document = await response.json();
      const execution = (document.analyzers ?? []).find(
        (item: { analyzer: string }) => item.analyzer === 'native-analyzer',
      );
      return { execution, application: document.application };
    },
  });

  if (!scanId) {
    return (
      <>
        <PageHeader title="Binary analysis" />
        <ScanPicker basePath="/binary" />
      </>
    );
  }

  const nativeFromMetadata = (analysis.data?.application?.native_libraries ?? []) as {
    path: string;
    abi: string;
    size_bytes: number;
  }[];
  const hasNativeArtifact = (artifacts.data ?? []).some((item) => item.kind === 'native-analysis');
  const execution = analysis.data?.execution as
    | { status: string; findings: number; limitations?: string[]; error?: string }
    | undefined;

  return (
    <>
      <PageHeader
        title="Binary analysis"
        description="ELF metadata, symbols and hardening for bundled native libraries."
        actions={<ScanPicker basePath="/binary" currentScanId={scanId} />}
      />

      {analysis.isLoading || scan.isLoading ? (
        <LoadingState label="Loading binary analysis" />
      ) : nativeFromMetadata.length === 0 ? (
        <Card>
          <EmptyState
            icon={<Binary className="size-9" aria-hidden="true" />}
            title="This application contains no native libraries"
            description="No lib/*.so entries were present in the APK, so there is nothing for the native analyzer to inspect."
          />
        </Card>
      ) : (
        <div className="space-y-4">
          {execution && execution.status !== 'completed' ? (
            <Note tone="warn" title={`Native analyzer status: ${execution.status}`}>
              {execution.error ?? 'The analyzer did not complete, so results may be missing.'}
            </Note>
          ) : null}

          <Card>
            <CardHeader
              title="Bundled libraries"
              description={`${nativeFromMetadata.length} native librar${nativeFromMetadata.length === 1 ? 'y' : 'ies'}`}
              actions={
                hasNativeArtifact ? (
                  <StatusBadge tone="ok">inspected</StatusBadge>
                ) : (
                  <StatusBadge tone="warn">not inspected</StatusBadge>
                )
              }
            />
            <DataTable
              caption="Native libraries"
              columns={[
                { key: 'path', label: 'Library' },
                { key: 'abi', label: 'ABI', width: '9rem' },
                { key: 'size', label: 'Size', width: '7rem', align: 'right' },
              ]}
            >
              {nativeFromMetadata.map((library) => (
                <tr key={library.path}>
                  <td className="ds-mono text-[11px] break-all">{library.path}</td>
                  <td><Chip>{library.abi}</Chip></td>
                  <td className="text-right tabular-nums text-muted">
                    {formatBytes(library.size_bytes)}
                  </td>
                </tr>
              ))}
            </DataTable>
          </Card>

          <Note tone="accent" title="Ghidra decompilation">
            Ghidra runs only on the full profile and only when it is installed. When it is absent,
            DroidScope reports the ELF inspection above, produced by its own parser, and does not
            imply that decompilation occurred.
          </Note>
        </div>
      )}
    </>
  );
}
