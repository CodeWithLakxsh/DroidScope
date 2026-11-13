/** TanStack Query hooks wrapping the API client. */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, type FindingFilters } from '@/lib/api';
import type { FindingStatus, ReportFormat, ScanProfile } from '@/types/api';

/** Scans in a non-terminal state are polled; finished ones are not. */
const ACTIVE_STATUSES = new Set(['queued', 'running']);

export function useHealth() {
  return useQuery({ queryKey: ['health'], queryFn: api.health, refetchInterval: 30_000 });
}

export function useCapabilities() {
  return useQuery({ queryKey: ['capabilities'], queryFn: api.capabilities, staleTime: 60_000 });
}

export function useRules() {
  return useQuery({ queryKey: ['rules'], queryFn: api.rules, staleTime: 300_000 });
}

export function useDashboard() {
  return useQuery({ queryKey: ['dashboard'], queryFn: api.dashboard, refetchInterval: 15_000 });
}

export function useApks(params?: { limit?: number; offset?: number; search?: string }) {
  return useQuery({ queryKey: ['apks', params], queryFn: () => api.listApks(params) });
}

export function useApk(apkId: string | undefined) {
  return useQuery({
    queryKey: ['apk', apkId],
    queryFn: () => api.getApk(apkId as string),
    enabled: Boolean(apkId),
  });
}

export function useManifest(apkId: string | undefined) {
  return useQuery({
    queryKey: ['manifest', apkId],
    queryFn: () => api.getManifest(apkId as string),
    enabled: Boolean(apkId),
    retry: false,
  });
}

export function useScans(params?: { limit?: number; offset?: number; status?: string; apk_id?: string }) {
  return useQuery({
    queryKey: ['scans', params],
    queryFn: () => api.listScans(params),
    refetchInterval: 10_000,
  });
}

export function useScan(scanId: string | undefined) {
  return useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => api.getScan(scanId as string),
    enabled: Boolean(scanId),
    // Poll only while the scan is still moving.
    refetchInterval: (query) =>
      query.state.data && ACTIVE_STATUSES.has(query.state.data.status) ? 1500 : false,
  });
}

export function useFindings(scanId: string | undefined, filters?: FindingFilters) {
  return useQuery({
    queryKey: ['findings', scanId, filters],
    queryFn: () => api.listFindings(scanId as string, filters),
    enabled: Boolean(scanId),
    placeholderData: (previous) => previous,
  });
}

export function useFinding(findingId: string | undefined) {
  return useQuery({
    queryKey: ['finding', findingId],
    queryFn: () => api.getFinding(findingId as string),
    enabled: Boolean(findingId),
  });
}

export function useIndicators(
  scanId: string | undefined,
  params?: { scope?: string; indicator_type?: string; limit?: number; offset?: number },
) {
  return useQuery({
    queryKey: ['indicators', scanId, params],
    queryFn: () => api.listIndicators(scanId as string, params),
    enabled: Boolean(scanId),
  });
}

export function useArtifacts(scanId: string | undefined) {
  return useQuery({
    queryKey: ['artifacts', scanId],
    queryFn: () => api.listArtifacts(scanId as string),
    enabled: Boolean(scanId),
  });
}

export function useSourceTree(scanId: string | undefined, artifact = 'decompiled-sources') {
  return useQuery({
    queryKey: ['tree', scanId, artifact],
    queryFn: () => api.sourceTree(scanId as string, { artifact }),
    enabled: Boolean(scanId),
    retry: false,
  });
}

export function useSourceFile(
  scanId: string | undefined,
  path: string | null,
  artifact = 'decompiled-sources',
) {
  return useQuery({
    queryKey: ['file', scanId, path, artifact],
    queryFn: () => api.sourceFile(scanId as string, path as string, artifact),
    enabled: Boolean(scanId && path),
  });
}

export function useDevices() {
  return useQuery({ queryKey: ['devices'], queryFn: api.devices, refetchInterval: 10_000 });
}

export function useInstrumentationModules() {
  return useQuery({
    queryKey: ['instrumentation-modules'],
    queryFn: api.instrumentationModules,
    staleTime: 300_000,
  });
}

export function useSessions(apkId?: string) {
  return useQuery({
    queryKey: ['sessions', apkId],
    queryFn: () => api.listSessions(apkId),
    refetchInterval: 5_000,
  });
}

export function useSessionEvents(sessionId: string | undefined, params?: { limit?: number }) {
  return useQuery({
    queryKey: ['session-events', sessionId, params],
    queryFn: () => api.sessionEvents(sessionId as string, params),
    enabled: Boolean(sessionId),
    refetchInterval: 5_000,
  });
}

export function useReports(scanId?: string) {
  return useQuery({ queryKey: ['reports', scanId], queryFn: () => api.listReports(scanId) });
}

export function useSettings() {
  return useQuery({ queryKey: ['settings'], queryFn: api.getSettings });
}

/* ------------------------------------------------------------- mutations */

export function useCreateScan() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: { apk_id: string; profile: ScanProfile; reuse_existing?: boolean }) =>
      api.createScan(body),
    onSuccess: () => {
      client.invalidateQueries({ queryKey: ['scans'] });
      client.invalidateQueries({ queryKey: ['dashboard'] });
    },
  });
}

export function useCancelScan() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (scanId: string) => api.cancelScan(scanId),
    onSuccess: (scan) => {
      client.invalidateQueries({ queryKey: ['scan', scan.id] });
      client.invalidateQueries({ queryKey: ['scans'] });
    },
  });
}

export function useReviewFinding() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({
      findingId,
      status,
      note,
    }: {
      findingId: string;
      status: FindingStatus;
      note?: string;
    }) => api.reviewFinding(findingId, { status, note }),
    onSuccess: (finding) => {
      client.invalidateQueries({ queryKey: ['finding', finding.id] });
      client.invalidateQueries({ queryKey: ['findings'] });
      client.invalidateQueries({ queryKey: ['scan', finding.scan_id] });
    },
  });
}

export function useCreateReport() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: {
      scan_id: string;
      format: ReportFormat;
      include_evidence?: boolean;
      include_informational?: boolean;
    }) => api.createReport(body),
    onSuccess: () => client.invalidateQueries({ queryKey: ['reports'] }),
  });
}

export function useCompare() {
  return useMutation({
    mutationFn: (body: { baseline_apk_id: string; updated_apk_id: string }) => api.compare(body),
  });
}

export function useCreateSession() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: {
      apk_id: string;
      device_serial: string;
      modules: string[];
      duration_seconds: number;
      authorised: boolean;
    }) => api.createSession(body),
    onSuccess: () => client.invalidateQueries({ queryKey: ['sessions'] }),
  });
}

export function useUpdateSettings() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: api.updateSettings,
    onSuccess: () => client.invalidateQueries({ queryKey: ['settings'] }),
  });
}
