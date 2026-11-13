/**
 * Typed DroidScope API client.
 *
 * Every response is parsed through a single helper so API errors arrive as a
 * typed ApiError carrying the server's structured error body, rather than an
 * opaque failure the UI has to guess at.
 */

import type {
  ApkDetail,
  ApkSummary,
  CapabilitiesResponse,
  ComparisonResult,
  DashboardStats,
  DeviceListResponse,
  DynamicSession,
  FindingDetail,
  FindingStatus,
  FindingSummary,
  HealthResponse,
  Indicator,
  Page,
  ReportFormat,
  ReportOut,
  RuleOut,
  RuntimeEvent,
  ScanDetail,
  ScanProfile,
  ScanSummary,
  SettingsOut,
  SourceFileResponse,
  SourceTreeResponse,
} from '@/types/api';

export const API_BASE = import.meta.env.VITE_API_BASE ?? '/api/v1';

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details: Record<string, unknown>;

  constructor(status: number, code: string, message: string, details: Record<string, unknown> = {}) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

function buildQuery(params: Record<string, unknown> | undefined): string {
  if (!params) return '';
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') continue;
    if (Array.isArray(value)) {
      value.forEach((item) => search.append(key, String(item)));
    } else {
      search.append(key, String(value));
    }
  }
  const text = search.toString();
  return text ? `?${text}` : '';
}

async function parse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    let code = `http_${response.status}`;
    let message = response.statusText || 'request failed';
    let details: Record<string, unknown> = {};
    try {
      const body = await response.json();
      if (body?.error) {
        code = body.error.code ?? code;
        message = body.error.message ?? message;
        details = body.error.details ?? {};
      }
    } catch {
      /* the body was not JSON; keep the status text */
    }
    throw new ApiError(response.status, code, message, details);
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

async function request<T>(
  path: string,
  options: RequestInit & { params?: Record<string, unknown> } = {},
): Promise<T> {
  const { params, ...init } = options;
  const response = await fetch(`${API_BASE}${path}${buildQuery(params)}`, {
    ...init,
    headers: {
      Accept: 'application/json',
      ...(init.body && !(init.body instanceof FormData)
        ? { 'Content-Type': 'application/json' }
        : {}),
      ...init.headers,
    },
  });
  return parse<T>(response);
}

export interface FindingFilters {
  // Index signature so the filter object can be passed straight to buildQuery.
  [key: string]: unknown;
  severity?: string[];
  confidence?: string[];
  status?: string[];
  category?: string;
  engine?: string;
  rule_id?: string;
  cwe?: string;
  masvs?: string;
  file_path?: string;
  search?: string;
  sort?: string;
  limit?: number;
  offset?: number;
}

export const api = {
  health: () => request<HealthResponse>('/health'),
  capabilities: () => request<CapabilitiesResponse>('/capabilities'),
  rules: () => request<RuleOut[]>('/rules'),
  analyzers: () => request<Record<string, unknown>[]>('/analyzers'),
  dashboard: () => request<DashboardStats>('/dashboard'),

  listApks: (params?: { limit?: number; offset?: number; search?: string }) =>
    request<Page<ApkSummary>>('/apks', { params }),
  getApk: (apkId: string) => request<ApkDetail>(`/apks/${apkId}`),
  apkIconUrl: (apkId: string) => `${API_BASE}/apks/${apkId}/icon`,
  getManifest: async (apkId: string): Promise<string> => {
    const response = await fetch(`${API_BASE}/apks/${apkId}/manifest`);
    if (!response.ok) {
      return parse<string>(response);
    }
    return response.text();
  },

  /** Uploads with progress; fetch cannot report upload progress, so XHR is used. */
  uploadApk: (
    file: File,
    onProgress?: (percent: number) => void,
  ): Promise<{ apk: ApkDetail; created: boolean; message: string }> =>
    new Promise((resolve, reject) => {
      const form = new FormData();
      form.append('file', file);
      const xhr = new XMLHttpRequest();
      xhr.open('POST', `${API_BASE}/apks`);
      xhr.upload.addEventListener('progress', (event) => {
        if (event.lengthComputable && onProgress) {
          onProgress(Math.round((event.loaded / event.total) * 100));
        }
      });
      xhr.addEventListener('load', () => {
        let body: unknown;
        try {
          body = JSON.parse(xhr.responseText);
        } catch {
          reject(new ApiError(xhr.status, 'invalid_response', 'the server response was not JSON'));
          return;
        }
        if (xhr.status >= 200 && xhr.status < 300) {
          resolve(body as { apk: ApkDetail; created: boolean; message: string });
        } else {
          const error = (body as { error?: { code: string; message: string; details?: Record<string, unknown> } })
            ?.error;
          reject(
            new ApiError(
              xhr.status,
              error?.code ?? `http_${xhr.status}`,
              error?.message ?? 'upload failed',
              error?.details ?? {},
            ),
          );
        }
      });
      xhr.addEventListener('error', () =>
        reject(new ApiError(0, 'network_error', 'the upload could not reach the server')),
      );
      xhr.addEventListener('abort', () =>
        reject(new ApiError(0, 'aborted', 'the upload was cancelled')),
      );
      xhr.send(form);
    }),

  listScans: (params?: { limit?: number; offset?: number; status?: string; apk_id?: string }) =>
    request<Page<ScanSummary>>('/scans', { params }),
  getScan: (scanId: string) => request<ScanDetail>(`/scans/${scanId}`),
  createScan: (body: { apk_id: string; profile: ScanProfile; reuse_existing?: boolean }) =>
    request<{ scan: ScanSummary; reused: boolean; message: string }>('/scans', {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  cancelScan: (scanId: string) =>
    request<ScanSummary>(`/scans/${scanId}/cancel`, { method: 'POST' }),

  listFindings: (scanId: string, filters?: FindingFilters) =>
    request<Page<FindingSummary>>(`/scans/${scanId}/findings`, { params: filters }),
  getFinding: (findingId: string) => request<FindingDetail>(`/findings/${findingId}`),
  reviewFinding: (findingId: string, body: { status: FindingStatus; note?: string }) =>
    request<FindingDetail>(`/findings/${findingId}/review`, {
      method: 'PATCH',
      body: JSON.stringify(body),
    }),

  listIndicators: (
    scanId: string,
    params?: { scope?: string; indicator_type?: string; limit?: number; offset?: number },
  ) => request<Page<Indicator>>(`/scans/${scanId}/indicators`, { params }),

  listArtifacts: (scanId: string) =>
    request<{ kind: string; size_bytes: number; entry_count: number; produced_by: string | null }[]>(
      `/scans/${scanId}/artifacts`,
    ),
  sourceTree: (scanId: string, params?: { artifact?: string; prefix?: string; limit?: number }) =>
    request<SourceTreeResponse>(`/scans/${scanId}/tree`, { params }),
  sourceFile: (scanId: string, path: string, artifact = 'decompiled-sources') =>
    request<SourceFileResponse>(`/scans/${scanId}/file`, { params: { path, artifact } }),
  exportScanUrl: (scanId: string) => `${API_BASE}/scans/${scanId}/export`,

  createReport: (body: {
    scan_id: string;
    format: ReportFormat;
    include_evidence?: boolean;
    include_informational?: boolean;
  }) => request<ReportOut>('/reports', { method: 'POST', body: JSON.stringify(body) }),
  listReports: (scanId?: string) =>
    request<ReportOut[]>('/reports', { params: scanId ? { scan_id: scanId } : undefined }),
  reportDownloadUrl: (reportId: string) => `${API_BASE}/reports/${reportId}/download`,

  compare: (body: { baseline_apk_id: string; updated_apk_id: string }) =>
    request<ComparisonResult>('/compare', { method: 'POST', body: JSON.stringify(body) }),

  devices: () => request<DeviceListResponse>('/devices'),
  instrumentationModules: () =>
    request<{ modules: { name: string; description: string }[]; note: string }>('/dynamic/modules'),
  listSessions: (apkId?: string) =>
    request<Page<DynamicSession>>('/dynamic/sessions', {
      params: apkId ? { apk_id: apkId } : undefined,
    }),
  getSession: (sessionId: string) => request<DynamicSession>(`/dynamic/sessions/${sessionId}`),
  createSession: (body: {
    apk_id: string;
    device_serial: string;
    modules: string[];
    duration_seconds: number;
    authorised: boolean;
  }) => request<DynamicSession>('/dynamic/sessions', { method: 'POST', body: JSON.stringify(body) }),
  stopSession: (sessionId: string) =>
    request<DynamicSession>(`/dynamic/sessions/${sessionId}/stop`, { method: 'POST' }),
  sessionEvents: (sessionId: string, params?: { limit?: number; offset?: number; event_type?: string }) =>
    request<Page<RuntimeEvent>>(`/dynamic/sessions/${sessionId}/events`, { params }),

  getSettings: () => request<SettingsOut>('/settings'),
  updateSettings: (body: Partial<SettingsOut>) =>
    request<SettingsOut>('/settings', { method: 'PATCH', body: JSON.stringify(body) }),
};
