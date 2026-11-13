/**
 * Dynamic analysis workspace.
 *
 * The page states plainly what the connected device can and cannot support
 * before a session is created, and requires an explicit authorisation
 * confirmation, because a session installs and runs the application.
 */

import { useState } from 'react';
import { Smartphone } from 'lucide-react';
import {
  useApks,
  useCreateSession,
  useDevices,
  useInstrumentationModules,
  useSessionEvents,
  useSessions,
  useSettings,
} from '@/hooks/queries';
import {
  Button,
  Card,
  CardHeader,
  Chip,
  DataTable,
  EmptyState,
  Field,
  JobStatusBadge,
  LoadingState,
  Note,
  PageHeader,
  Select,
  StatusBadge,
} from '@/components/ui';
import { formatDateTime, formatRelative } from '@/lib/format';

export default function DynamicAnalysis() {
  const devices = useDevices();
  const apks = useApks({ limit: 100 });
  const modules = useInstrumentationModules();
  const sessions = useSessions();
  const settings = useSettings();
  const createSession = useCreateSession();

  const [apkId, setApkId] = useState('');
  const [serial, setSerial] = useState('');
  const [selectedModules, setSelectedModules] = useState<string[]>([
    'file-access',
    'crypto-api',
    'network-api',
    'process-ipc',
  ]);
  const [duration, setDuration] = useState(120);
  const [authorised, setAuthorised] = useState(false);
  const [activeSession, setActiveSession] = useState<string | null>(null);

  const events = useSessionEvents(activeSession ?? undefined, { limit: 200 });
  const enabled = settings.data?.dynamic_analysis_enabled ?? false;
  const usableDevices = (devices.data?.devices ?? []).filter((device) => device.state === 'device');

  return (
    <>
      <PageHeader
        title="Dynamic analysis"
        description="Install and run an application on a selected device, with read-only instrumentation."
      />

      {!enabled ? (
        <div className="mb-4">
          <Note tone="warn" title="Dynamic analysis is disabled">
            A session installs and executes the uploaded application on a device, so it is off by
            default. Enable it with DROIDSCOPE_DYNAMIC_ANALYSIS_ENABLED=true and point it at an
            isolated test device you are authorised to use.
          </Note>
        </div>
      ) : null}

      <div className="mb-4">
        <Note tone="accent" title="What instrumentation does and does not do">
          Modules observe API calls and record what they see. DroidScope deliberately ships no
          module that bypasses certificate validation, root detection or biometric checks, and TLS
          payloads are not decrypted.
        </Note>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader
            title="Devices"
            description={devices.data?.message ?? undefined}
            actions={
              <>
                <StatusBadge tone={devices.data?.adb_available ? 'ok' : 'error'}>
                  adb {devices.data?.adb_available ? 'ready' : 'missing'}
                </StatusBadge>
                <StatusBadge tone={devices.data?.frida_available ? 'ok' : 'warn'}>
                  frida {devices.data?.frida_available ? 'ready' : 'missing'}
                </StatusBadge>
              </>
            }
          />
          {devices.isLoading ? (
            <LoadingState label="Discovering devices" />
          ) : (devices.data?.devices ?? []).length === 0 ? (
            <EmptyState
              icon={<Smartphone className="size-9" aria-hidden="true" />}
              title="No devices connected"
              description="Start an emulator or connect a device with USB debugging enabled, then refresh."
            />
          ) : (
            <ul className="divide-y" style={{ borderColor: 'var(--border)' }}>
              {devices.data!.devices.map((device) => (
                <li key={device.serial} className="px-4 py-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="ds-mono text-xs font-medium">{device.serial}</span>
                    <span className="flex gap-1">
                      <StatusBadge tone={device.state === 'device' ? 'ok' : 'warn'}>
                        {device.state}
                      </StatusBadge>
                      <Chip>{device.is_emulator ? 'emulator' : 'physical'}</Chip>
                    </span>
                  </div>
                  <div className="mt-1 flex flex-wrap gap-1.5 text-[11px] text-muted">
                    {device.model ? <span>{device.manufacturer} {device.model}</span> : null}
                    {device.android_version ? <span>Android {device.android_version} (API {device.sdk_int})</span> : null}
                    {device.abi ? <span>{device.abi}</span> : null}
                    {device.rooted !== null ? (
                      <span>{device.rooted ? 'rooted' : 'not rooted'}</span>
                    ) : null}
                    {device.frida_server_running !== null ? (
                      <span>frida-server {device.frida_server_running ? 'running' : 'not running'}</span>
                    ) : null}
                  </div>
                  {device.notes.length > 0 ? (
                    <ul className="mt-1.5 space-y-0.5 text-[11px] text-subtle">
                      {device.notes.map((note) => (
                        <li key={note}>• {note}</li>
                      ))}
                    </ul>
                  ) : null}
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card>
          <CardHeader title="New session" />
          <div className="space-y-3 px-4 py-3">
            <Field label="Application" htmlFor="session-apk">
              <Select id="session-apk" value={apkId} onChange={(event) => setApkId(event.target.value)}>
                <option value="">Select an APK</option>
                {(apks.data?.items ?? []).map((apk) => (
                  <option key={apk.id} value={apk.id}>
                    {apk.package_name ?? apk.original_filename}
                  </option>
                ))}
              </Select>
            </Field>

            <Field
              label="Device"
              htmlFor="session-device"
              hint="A device must be selected explicitly; DroidScope never picks one for you."
            >
              <Select
                id="session-device"
                value={serial}
                onChange={(event) => setSerial(event.target.value)}
              >
                <option value="">Select a device</option>
                {usableDevices.map((device) => (
                  <option key={device.serial} value={device.serial}>
                    {device.serial} {device.is_emulator ? '(emulator)' : '(physical)'}
                  </option>
                ))}
              </Select>
            </Field>

            <Field label="Duration (seconds)" htmlFor="session-duration" hint="Between 10 and 3600.">
              <input
                id="session-duration"
                type="number"
                min={10}
                max={3600}
                value={duration}
                onChange={(event) => setDuration(Number(event.target.value))}
                className="h-8 w-full rounded-sm border px-2 text-sm"
                style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}
              />
            </Field>

            <fieldset>
              <legend className="mb-1.5 text-xs font-medium">Instrumentation modules</legend>
              <div className="space-y-1">
                {(modules.data?.modules ?? []).map((module) => (
                  <label key={module.name} className="flex cursor-pointer items-start gap-2 text-xs">
                    <input
                      type="checkbox"
                      className="mt-0.5"
                      checked={selectedModules.includes(module.name)}
                      onChange={(event) =>
                        setSelectedModules((current) =>
                          event.target.checked
                            ? [...current, module.name]
                            : current.filter((item) => item !== module.name),
                        )
                      }
                    />
                    <span>
                      <span className="ds-mono block text-[11px] font-medium">{module.name}</span>
                      <span className="block text-[11px] text-muted">{module.description}</span>
                    </span>
                  </label>
                ))}
              </div>
            </fieldset>

            <label
              className="flex cursor-pointer items-start gap-2 rounded-sm border p-2.5 text-xs"
              style={{ borderColor: 'var(--status-warn)', backgroundColor: 'var(--status-warn-bg)' }}
            >
              <input
                type="checkbox"
                className="mt-0.5"
                checked={authorised}
                onChange={(event) => setAuthorised(event.target.checked)}
              />
              <span>
                I am authorised to install and execute this application on the selected device.
              </span>
            </label>

            <Button
              variant="primary"
              size="md"
              disabled={!enabled || !apkId || !serial || !authorised || createSession.isPending}
              onClick={() =>
                createSession.mutate(
                  {
                    apk_id: apkId,
                    device_serial: serial,
                    modules: selectedModules,
                    duration_seconds: duration,
                    authorised,
                  },
                  { onSuccess: (session) => setActiveSession(session.id) },
                )
              }
            >
              {createSession.isPending ? 'Starting…' : 'Start session'}
            </Button>

            {createSession.isError ? (
              <Note tone="error" title="The session could not be started">
                {(createSession.error as Error).message}
              </Note>
            ) : null}
          </div>
        </Card>
      </div>

      <Card className="mt-4">
        <CardHeader title="Sessions" />
        {sessions.isLoading ? (
          <LoadingState />
        ) : !sessions.data || sessions.data.items.length === 0 ? (
          <EmptyState title="No sessions yet" description="Create one above to capture runtime behaviour." />
        ) : (
          <DataTable
            caption="Dynamic analysis sessions"
            columns={[
              { key: 'id', label: 'Session' },
              { key: 'device', label: 'Device', width: '12rem' },
              { key: 'status', label: 'Status', width: '8rem' },
              { key: 'events', label: 'Events', width: '6rem', align: 'right' },
              { key: 'when', label: 'Started', width: '9rem', align: 'right' },
            ]}
          >
            {sessions.data.items.map((session) => (
              <tr
                key={session.id}
                onClick={() => setActiveSession(session.id)}
                className="cursor-pointer"
                style={activeSession === session.id ? { backgroundColor: 'var(--surface-hover)' } : undefined}
              >
                <td className="ds-mono text-[11px]">{session.id.slice(0, 12)}</td>
                <td className="ds-mono text-[11px]">{session.device_serial}</td>
                <td><JobStatusBadge status={session.status} /></td>
                <td className="text-right tabular-nums">{session.events_count}</td>
                <td className="text-right text-muted">{formatRelative(session.created_at)}</td>
              </tr>
            ))}
          </DataTable>
        )}
      </Card>

      {activeSession ? (
        <Card className="mt-4">
          <CardHeader
            title="Runtime timeline"
            description={`Session ${activeSession.slice(0, 12)}`}
          />
          {events.isLoading ? (
            <LoadingState />
          ) : !events.data || events.data.items.length === 0 ? (
            <EmptyState
              title="No events captured"
              description="The session may still be running, or instrumentation may not have attached. Check the session's capability report."
            />
          ) : (
            <DataTable
              caption="Captured runtime events"
              columns={[
                { key: 'time', label: 'Time', width: '10rem' },
                { key: 'type', label: 'Type', width: '8rem' },
                { key: 'api', label: 'API', width: '16rem' },
                { key: 'summary', label: 'Detail' },
              ]}
            >
              {events.data.items.map((event) => (
                <tr key={event.id}>
                  <td className="ds-mono text-[10px] text-muted">
                    {formatDateTime(event.observed_at)}
                  </td>
                  <td><Chip>{event.event_type}</Chip></td>
                  <td className="ds-mono text-[10px] break-all">{event.api ?? '—'}</td>
                  <td className="text-[11px] break-all">{event.summary}</td>
                </tr>
              ))}
            </DataTable>
          )}
        </Card>
      ) : null}
    </>
  );
}
