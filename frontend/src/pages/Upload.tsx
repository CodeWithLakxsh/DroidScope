/** APK upload with drag and drop, client-side checks and progress. */

import { useCallback, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { FileUp, ShieldCheck, Upload as UploadIcon } from 'lucide-react';
import { ApiError } from '@/lib/api';
import { api } from '@/lib/api';
import { useCapabilities, useCreateScan, useSettings } from '@/hooks/queries';
import {
  Button,
  Card,
  CardHeader,
  Field,
  KeyValue,
  Note,
  PageHeader,
  ProgressBar,
  Select,
  StatusBadge,
} from '@/components/ui';
import { formatBytes } from '@/lib/format';
import type { ApkDetail, ScanProfile } from '@/types/api';

type Stage = 'idle' | 'uploading' | 'uploaded' | 'error';

export default function UploadPage() {
  const navigate = useNavigate();
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  const [stage, setStage] = useState<Stage>('idle');
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<{ apk: ApkDetail; created: boolean; message: string } | null>(null);
  const [profile, setProfile] = useState<ScanProfile>('standard');

  const capabilities = useCapabilities();
  const settings = useSettings();
  const createScan = useCreateScan();

  const maxBytes = settings.data?.max_upload_bytes ?? 512 * 1024 * 1024;

  const handleFile = useCallback(
    async (file: File) => {
      setError(null);
      setResult(null);

      // Cheap client-side checks first; the server validates the archive itself.
      if (!file.name.toLowerCase().endsWith('.apk')) {
        setStage('error');
        setError(
          `${file.name} does not have a .apk extension. DroidScope analyses Android application packages.`,
        );
        return;
      }
      if (file.size === 0) {
        setStage('error');
        setError('The selected file is empty.');
        return;
      }
      if (file.size > maxBytes) {
        setStage('error');
        setError(
          `The file is ${formatBytes(file.size)}, which exceeds the server limit of ${formatBytes(maxBytes)}.`,
        );
        return;
      }

      setStage('uploading');
      setProgress(0);
      try {
        const uploaded = await api.uploadApk(file, setProgress);
        setResult(uploaded);
        setStage('uploaded');
      } catch (uploadError) {
        setStage('error');
        setError(
          uploadError instanceof ApiError
            ? uploadError.message
            : 'The upload failed before reaching the server.',
        );
      }
    },
    [maxBytes],
  );

  const onDrop = useCallback(
    (event: React.DragEvent) => {
      event.preventDefault();
      setDragging(false);
      const file = event.dataTransfer.files?.[0];
      if (file) void handleFile(file);
    },
    [handleFile],
  );

  const startScan = async () => {
    if (!result) return;
    const created = await createScan.mutateAsync({
      apk_id: result.apk.id,
      profile,
      reuse_existing: false,
    });
    navigate(`/scans/${created.scan.id}`);
  };

  const profiles = capabilities.data?.profiles ?? {};

  return (
    <>
      <PageHeader
        title="Upload an APK"
        description="The archive is validated before any parser reads it, then stored by content hash."
      />

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_20rem]">
        <div className="space-y-4">
          <Card>
            <div
              onDragOver={(event) => {
                event.preventDefault();
                setDragging(true);
              }}
              onDragLeave={() => setDragging(false)}
              onDrop={onDrop}
              className="flex flex-col items-center justify-center rounded-md border-2 border-dashed px-6 py-12 text-center transition-colors duration-150"
              style={{
                borderColor: dragging ? 'var(--accent)' : 'var(--border)',
                backgroundColor: dragging ? 'var(--surface-hover)' : 'transparent',
              }}
            >
              <FileUp className="mb-3 size-9 text-subtle" aria-hidden="true" />
              <p className="text-sm font-medium">Drag an APK here</p>
              <p className="mt-1 text-xs text-muted">
                or choose a file. Maximum {formatBytes(maxBytes)}.
              </p>
              <input
                ref={inputRef}
                type="file"
                accept=".apk,application/vnd.android.package-archive"
                className="sr-only"
                id="apk-file-input"
                onChange={(event) => {
                  const file = event.target.files?.[0];
                  if (file) void handleFile(file);
                  event.target.value = '';
                }}
              />
              <Button
                variant="primary"
                size="md"
                className="mt-4"
                onClick={() => inputRef.current?.click()}
                disabled={stage === 'uploading'}
              >
                <UploadIcon className="size-4" aria-hidden="true" />
                Choose APK file
              </Button>
            </div>

            {stage === 'uploading' ? (
              <div className="border-t px-4 py-3" style={{ borderColor: 'var(--border)' }}>
                <div className="mb-1.5 flex items-center justify-between text-xs">
                  <span>Uploading…</span>
                  <span className="tabular-nums">{progress}%</span>
                </div>
                <ProgressBar value={progress / 100} label="Upload progress" />
              </div>
            ) : null}

            {stage === 'error' && error ? (
              <div className="border-t px-4 py-3" style={{ borderColor: 'var(--border)' }}>
                <div role="alert" className="flex items-start gap-2">
                  <StatusBadge tone="error">Rejected</StatusBadge>
                  <p className="text-xs text-muted">{error}</p>
                </div>
              </div>
            ) : null}
          </Card>

          {result ? (
            <Card>
              <CardHeader
                title={result.apk.package_name ?? result.apk.original_filename}
                description={result.message}
                actions={
                  result.created ? (
                    <StatusBadge tone="ok">Stored</StatusBadge>
                  ) : (
                    <StatusBadge tone="neutral">Already present</StatusBadge>
                  )
                }
              />
              <KeyValue
                rows={[
                  { label: 'Package', value: result.apk.package_name ?? 'not determined', mono: true },
                  { label: 'Label', value: result.apk.app_label ?? 'not determined' },
                  {
                    label: 'Version',
                    value: `${result.apk.version_name ?? '?'} (code ${result.apk.version_code ?? '?'})`,
                  },
                  {
                    label: 'SDK',
                    value: `min ${result.apk.min_sdk ?? '?'}, target ${result.apk.target_sdk ?? '?'}`,
                  },
                  { label: 'Size', value: formatBytes(result.apk.file_size) },
                  { label: 'SHA-256', value: result.apk.sha256, mono: true },
                  {
                    label: 'Archive checks',
                    value: (
                      <span className="flex flex-wrap gap-1">
                        {Object.entries(result.apk.validation.checks ?? {}).map(([name, state]) => (
                          <StatusBadge key={name} tone={state === 'pass' ? 'ok' : 'warn'}>
                            {name.replace(/_/g, ' ')}
                          </StatusBadge>
                        ))}
                      </span>
                    ),
                  },
                ]}
              />
              {(result.apk.validation.warnings ?? []).length > 0 ? (
                <div className="px-4 pb-3">
                  <Note tone="warn" title="Archive warnings">
                    <ul className="list-disc pl-4">
                      {result.apk.validation.warnings?.map((warning) => (
                        <li key={warning}>{warning}</li>
                      ))}
                    </ul>
                  </Note>
                </div>
              ) : null}
              {result.apk.metadata_error ? (
                <div className="px-4 pb-3">
                  <Note tone="warn" title="Metadata parsing was incomplete">
                    {result.apk.metadata_error}
                  </Note>
                </div>
              ) : null}

              <div
                className="flex flex-wrap items-end gap-3 border-t px-4 py-3"
                style={{ borderColor: 'var(--border)' }}
              >
                <Field
                  label="Analysis profile"
                  htmlFor="profile-select"
                  className="min-w-[12rem] flex-1"
                  hint={profiles[profile]}
                >
                  <Select
                    id="profile-select"
                    value={profile}
                    onChange={(event) => setProfile(event.target.value as ScanProfile)}
                  >
                    <option value="quick">Quick — metadata and manifest</option>
                    <option value="standard">Standard — plus decompilation</option>
                    <option value="full">Full — plus Ghidra where available</option>
                  </Select>
                </Field>
                <Button
                  variant="primary"
                  size="md"
                  onClick={startScan}
                  disabled={createScan.isPending}
                >
                  {createScan.isPending ? 'Queueing…' : 'Start analysis'}
                </Button>
              </div>
              {createScan.isError ? (
                <div className="px-4 pb-3">
                  <Note tone="error" title="The scan could not be queued">
                    {(createScan.error as Error).message}
                  </Note>
                </div>
              ) : null}
            </Card>
          ) : null}
        </div>

        <aside className="space-y-4">
          <Card>
            <CardHeader title="How uploads are handled" />
            <ul className="space-y-2 px-4 py-3 text-xs text-muted">
              <li className="flex gap-2">
                <ShieldCheck className="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
                Streamed to disk with a size cap, hashed as it is written.
              </li>
              <li className="flex gap-2">
                <ShieldCheck className="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
                Rejected unless the archive parses and contains an AndroidManifest and code.
              </li>
              <li className="flex gap-2">
                <ShieldCheck className="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
                Zip bombs, path traversal, symlinks and duplicate entries are refused.
              </li>
              <li className="flex gap-2">
                <ShieldCheck className="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
                Stored under its SHA-256, so the uploaded filename never affects a path.
              </li>
              <li className="flex gap-2">
                <ShieldCheck className="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
                The APK is never executed on the analysis host.
              </li>
            </ul>
          </Card>

          {capabilities.data ? (
            <Card>
              <CardHeader
                title="Analyzer availability"
                description="Missing tooling reduces coverage; it never produces invented results."
              />
              <ul className="space-y-1 px-4 py-3 text-xs">
                {Object.entries(capabilities.data.analyzers).map(([name, available]) => (
                  <li key={name} className="flex items-center justify-between gap-2">
                    <span className="ds-mono text-[11px]">{name}</span>
                    <StatusBadge tone={available ? 'ok' : 'warn'}>
                      {available ? 'ready' : 'unavailable'}
                    </StatusBadge>
                  </li>
                ))}
              </ul>
            </Card>
          ) : null}
        </aside>
      </div>
    </>
  );
}
