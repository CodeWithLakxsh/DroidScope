/**
 * Decompiled code browser.
 *
 * The tree can hold tens of thousands of entries, so it is filtered and
 * windowed rather than rendered in full, and file contents load on demand.
 */

import { useEffect, useMemo, useState } from 'react';
import { useParams, useSearchParams } from 'react-router-dom';
import Editor from '@monaco-editor/react';
import { Code2, Copy, FileCode, Search } from 'lucide-react';
import { ScanPicker } from '@/components/ScanPicker';
import { useArtifacts, useSourceFile, useSourceTree } from '@/hooks/queries';
import {
  Button,
  Card,
  CardHeader,
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
import { formatBytes } from '@/lib/format';

const MAX_VISIBLE_ENTRIES = 600;

export default function CodeExplorer() {
  const { scanId } = useParams<{ scanId: string }>();
  const [searchParams, setSearchParams] = useSearchParams();
  const [artifact, setArtifact] = useState('decompiled-sources');
  const [filter, setFilter] = useState('');
  const [dark, setDark] = useState(() => document.documentElement.classList.contains('dark'));

  const selectedPath = searchParams.get('path');
  const artifacts = useArtifacts(scanId);
  const tree = useSourceTree(scanId, artifact);
  const file = useSourceFile(scanId, selectedPath, artifact);

  // Follow the application theme in the editor.
  useEffect(() => {
    const observer = new MutationObserver(() =>
      setDark(document.documentElement.classList.contains('dark')),
    );
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] });
    return () => observer.disconnect();
  }, []);

  const files = useMemo(() => {
    const entries = (tree.data?.entries ?? []).filter((entry) => entry.type === 'file');
    if (!filter.trim()) return entries;
    const needle = filter.trim().toLowerCase();
    return entries.filter((entry) => entry.path.toLowerCase().includes(needle));
  }, [tree.data, filter]);

  if (!scanId) {
    return (
      <>
        <PageHeader title="Code explorer" description="Browse decompiled sources and smali." />
        <ScanPicker basePath="/code" />
      </>
    );
  }

  const browsable = (artifacts.data ?? [])
    .filter((item) => ['decompiled-sources', 'decoded-resources'].includes(item.kind))
    .map((item) => item.kind);

  const selectPath = (path: string) => {
    const next = new URLSearchParams(searchParams);
    next.set('path', path);
    setSearchParams(next, { replace: true });
  };

  return (
    <>
      <PageHeader
        title="Code explorer"
        description="Decompiled Java from JADX and smali from apktool."
        actions={<ScanPicker basePath="/code" currentScanId={scanId} />}
      />

      {browsable.length === 0 && !artifacts.isLoading ? (
        <Card>
          <EmptyState
            icon={<Code2 className="size-9" aria-hidden="true" />}
            title="No browsable code for this scan"
            description="The quick profile does not decompile. Run a standard or full scan to produce a source tree."
          />
        </Card>
      ) : (
        <div className="grid gap-4 lg:grid-cols-[20rem_minmax(0,1fr)]">
          <Card className="flex max-h-[calc(100vh-11rem)] flex-col">
            <CardHeader
              title="Files"
              description={tree.data ? `${files.length} shown` : undefined}
              actions={
                browsable.length > 1 ? (
                  <Select
                    aria-label="Artifact"
                    value={artifact}
                    onChange={(event) => setArtifact(event.target.value)}
                    className="h-7 w-auto text-[11px]"
                  >
                    {browsable.map((kind) => (
                      <option key={kind} value={kind}>
                        {kind === 'decompiled-sources' ? 'JADX sources' : 'apktool output'}
                      </option>
                    ))}
                  </Select>
                ) : null
              }
            />
            <div className="flex items-center gap-2 border-b px-3 py-2" style={{ borderColor: 'var(--border)' }}>
              <Search className="size-3.5 text-subtle" aria-hidden="true" />
              <label htmlFor="file-filter" className="sr-only">
                Filter files
              </label>
              <Input
                id="file-filter"
                value={filter}
                onChange={(event) => setFilter(event.target.value)}
                placeholder="Filter by path"
                className="h-7 border-0 text-xs"
                style={{ backgroundColor: 'transparent', borderColor: 'transparent' }}
              />
            </div>

            <div className="min-h-0 flex-1 overflow-y-auto">
              {tree.isLoading ? (
                <LoadingState label="Loading file tree" />
              ) : tree.isError ? (
                <ErrorState error={tree.error} onRetry={() => tree.refetch()} />
              ) : files.length === 0 ? (
                <EmptyState title="No files match" description="Try a different filter." />
              ) : (
                <ul className="py-1">
                  {files.slice(0, MAX_VISIBLE_ENTRIES).map((entry) => (
                    <li key={entry.path}>
                      <button
                        type="button"
                        onClick={() => selectPath(entry.path)}
                        className="flex w-full cursor-pointer items-center gap-1.5 px-3 py-1 text-left text-[11px] transition-colors"
                        style={
                          selectedPath === entry.path
                            ? { backgroundColor: 'var(--surface-hover)', color: 'var(--accent)' }
                            : undefined
                        }
                        title={entry.path}
                      >
                        <FileCode className="size-3 shrink-0 text-subtle" aria-hidden="true" />
                        <span className="ds-mono truncate">{entry.path}</span>
                      </button>
                    </li>
                  ))}
                  {files.length > MAX_VISIBLE_ENTRIES ? (
                    <li className="px-3 py-2 text-[11px] text-subtle">
                      {files.length - MAX_VISIBLE_ENTRIES} more files — refine the filter to see them.
                    </li>
                  ) : null}
                </ul>
              )}
            </div>
          </Card>

          <Card className="flex max-h-[calc(100vh-11rem)] min-h-[32rem] flex-col">
            {!selectedPath ? (
              <EmptyState
                icon={<Code2 className="size-9" aria-hidden="true" />}
                title="Select a file"
                description="Choose a file from the tree to view its decompiled source."
              />
            ) : file.isLoading ? (
              <LoadingState label="Loading file" />
            ) : file.isError ? (
              <ErrorState error={file.error} onRetry={() => file.refetch()} />
            ) : file.data ? (
              <>
                <CardHeader
                  title={<span className="ds-mono text-xs break-all">{file.data.path}</span>}
                  description={`${file.data.language} · ${formatBytes(file.data.size_bytes)}`}
                  actions={
                    <>
                      {file.data.findings.length > 0 ? (
                        <StatusBadge tone="warn">
                          {file.data.findings.length} finding
                          {file.data.findings.length === 1 ? '' : 's'}
                        </StatusBadge>
                      ) : null}
                      <Button
                        onClick={() => navigator.clipboard?.writeText(file.data!.content)}
                        title="Copy file contents"
                      >
                        <Copy className="size-3.5" aria-hidden="true" />
                        Copy
                      </Button>
                    </>
                  }
                />

                {file.data.truncated ? (
                  <div className="px-4 pt-3">
                    <Note tone="warn" title="File truncated">
                      Only the first portion of this file is shown because it exceeds the display limit.
                    </Note>
                  </div>
                ) : null}

                {file.data.findings.length > 0 ? (
                  <ul className="space-y-1 border-b px-4 py-2" style={{ borderColor: 'var(--border)' }}>
                    {file.data.findings.map((finding) => (
                      <li key={finding.id} className="flex items-center gap-2 text-[11px]">
                        <SeverityBadge severity={finding.severity} />
                        <span className="truncate">{finding.title}</span>
                        {finding.line_number ? (
                          <span className="ds-mono text-subtle">line {finding.line_number}</span>
                        ) : null}
                      </li>
                    ))}
                  </ul>
                ) : null}

                <div className="min-h-0 flex-1">
                  <Editor
                    height="100%"
                    language={file.data.language}
                    value={file.data.content}
                    theme={dark ? 'vs-dark' : 'light'}
                    options={{
                      readOnly: true,
                      domReadOnly: true,
                      minimap: { enabled: true, maxColumn: 60 },
                      fontSize: 12,
                      fontFamily: 'JetBrains Mono, ui-monospace, monospace',
                      lineNumbers: 'on',
                      scrollBeyondLastLine: false,
                      renderWhitespace: 'selection',
                      wordWrap: 'off',
                      automaticLayout: true,
                    }}
                  />
                </div>
              </>
            ) : null}
          </Card>
        </div>
      )}
    </>
  );
}
