/** Types mirroring the DroidScope API schemas. */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Confidence = 'high' | 'medium' | 'low';
export type FindingStatus =
  | 'open'
  | 'confirmed'
  | 'false_positive'
  | 'accepted_risk'
  | 'resolved';
export type JobStatus =
  | 'queued'
  | 'running'
  | 'completed'
  | 'failed'
  | 'cancelled'
  | 'timed_out';
export type ScanProfile = 'quick' | 'standard' | 'full';
export type ReportFormat = 'pdf' | 'html' | 'json' | 'sarif';

export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface ApiErrorBody {
  error: { code: string; message: string; details: Record<string, unknown> };
}

export interface Capability {
  name: string;
  available: boolean;
  kind: string;
  version: string | null;
  detail: string | null;
  install_hint: string | null;
  required_for: string[];
  optional: boolean;
}

export interface CapabilitiesResponse {
  capabilities: Capability[];
  analyzers: Record<string, boolean>;
  profiles: Record<string, string>;
  rules_loaded: number;
  version: string;
}

export interface HealthResponse {
  status: 'ok' | 'degraded';
  database: boolean;
  version: string;
  queue_pending: number | null;
}

export interface ApkSummary {
  id: string;
  sha256: string;
  file_size: number;
  original_filename: string;
  package_name: string | null;
  app_label: string | null;
  version_name: string | null;
  version_code: number | null;
  min_sdk: number | null;
  target_sdk: number | null;
  created_at: string;
  has_icon: boolean;
  scan_count: number;
  latest_scan_id: string | null;
  latest_scan_status: JobStatus | null;
}

export interface Certificate {
  subject: string | null;
  issuer: string | null;
  not_before: string | null;
  not_after: string | null;
  signature_algorithm: string | null;
  public_key_algorithm: string | null;
  key_size_bits: number | null;
  sha256_fingerprint: string | null;
  is_self_signed: boolean | null;
}

export interface IntentFilter {
  actions: string[];
  categories: string[];
  data: Record<string, string>[];
  priority: number | null;
  auto_verify: boolean;
}

export interface Component {
  kind: 'activity' | 'activity-alias' | 'service' | 'receiver' | 'provider';
  name: string;
  exported: boolean;
  exported_implied: boolean;
  exported_attribute: boolean | null;
  enabled: boolean;
  permission: string | null;
  read_permission: string | null;
  write_permission: string | null;
  intent_filters: IntentFilter[];
  authorities: string[];
  grant_uri_permissions: boolean;
  launch_mode: string | null;
  permission_protection_level: string | null;
}

export interface RequestedPermission {
  name: string;
  protection_level: string | null;
  is_dangerous: boolean;
  max_sdk_version: number | null;
}

export interface ApplicationFlags {
  debuggable: boolean | null;
  allow_backup: boolean | null;
  uses_cleartext_traffic: boolean | null;
  network_security_config: string | null;
  test_only: boolean | null;
  custom_application_class: string | null;
  [key: string]: unknown;
}

export interface ApkMetadata {
  package_name: string | null;
  app_label: string | null;
  version_name: string | null;
  version_code: number | null;
  min_sdk: number | null;
  target_sdk: number | null;
  compile_sdk: number | null;
  application_flags: ApplicationFlags;
  requested_permissions: RequestedPermission[];
  declared_permissions: { name: string; protection_level: string | null }[];
  components: Component[];
  certificates: Certificate[];
  signature_schemes: string[];
  dex_files: { name: string; size_bytes: number; sha256: string | null }[];
  native_libraries: { path: string; abi: string; size_bytes: number }[];
  abis: string[];
  asset_summary: Record<string, unknown>;
  entry_count: number;
  parse_errors: string[];
  partial: boolean;
  metadata_entries: { name: string; value: string; resource: string }[];
}

export interface ApkDetail extends ApkSummary {
  sha1: string | null;
  md5: string | null;
  compile_sdk: number | null;
  metadata_error: string | null;
  validation: {
    valid?: boolean;
    entry_count?: number;
    total_uncompressed?: number;
    dex_files?: string[];
    signature_schemes?: string[];
    warnings?: string[];
    checks?: Record<string, string>;
  };
  apk_metadata: ApkMetadata;
}

export interface RiskSummary {
  score: number;
  band: string;
  band_description: string;
  raw_weight: number;
  scored_findings: number;
  severity_counts: Record<string, number>;
  confidence_counts: Record<string, number>;
  category_counts: Record<string, number>;
  top_contributors: {
    rule_id: string;
    title: string;
    severity: string;
    confidence: string;
    weight: number;
  }[];
  coverage: {
    profile: string | null;
    analyzers_completed: string[];
    analyzers_incomplete: { analyzer: string; status: string; reason: string }[];
    complete: boolean;
  };
  caveats: string[];
  method: string;
}

export interface AnalyzerExecution {
  analyzer: string;
  analyzer_version: string;
  status: 'completed' | 'skipped' | 'failed' | 'timed_out' | 'unavailable';
  duration_seconds: number | null;
  findings_count: number;
  error: string | null;
  detail: Record<string, unknown>;
}

export interface ScanSummary {
  id: string;
  apk_id: string;
  profile: ScanProfile;
  status: JobStatus;
  progress: number;
  stage: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  duration_seconds: number | null;
  findings_total: number;
  severity_counts: Record<string, number>;
  error: string | null;
  package_name: string | null;
  app_label: string | null;
}

export interface ScanDetail extends ScanSummary {
  risk: RiskSummary | Record<string, never>;
  limitations: string[];
  environment: {
    profile?: string;
    tool_versions?: Record<string, string>;
    tools_unavailable?: string[];
    rules_loaded?: number;
    analyzers?: unknown[];
  };
  config: Record<string, unknown>;
  executions: AnalyzerExecution[];
  artifacts: string[];
}

export interface Evidence {
  kind: string;
  description: string;
  snippet: string | null;
  file_path: string | null;
  line_number: number | null;
  sensitive: boolean;
  value_fingerprint: string | null;
  metadata: Record<string, unknown>;
}

export interface FindingSummary {
  id: string;
  scan_id: string;
  rule_id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  category: string;
  status: FindingStatus;
  analysis_engine: string;
  affected_component: string | null;
  file_path: string | null;
  line_number: number | null;
  cwe_ids: string[];
  masvs_controls: string[];
}

export interface FindingDetail extends FindingSummary {
  description: string;
  impact: string;
  remediation: string;
  verification: string | null;
  limitations: string | null;
  references: string[];
  rule_version: string;
  fingerprint: string;
  created_at: string;
  evidence: Evidence[];
  reviews: {
    previous_status: FindingStatus;
    new_status: FindingStatus;
    note: string | null;
    reviewer: string | null;
    created_at: string;
  }[];
  metadata: Record<string, unknown>;
}

export interface Indicator {
  id: string;
  indicator_type: string;
  value: string;
  scope: string;
  scheme: string | null;
  host: string | null;
  port: number | null;
  source: string;
  source_file: string | null;
  context: string | null;
  occurrences: number;
}

export interface TreeEntry {
  path: string;
  type: 'file' | 'directory';
  size: number;
  language: string | null;
}

export interface SourceTreeResponse {
  scan_id: string;
  artifact: string;
  entries: TreeEntry[];
  truncated: boolean;
}

export interface SourceFileResponse {
  path: string;
  language: string;
  content: string;
  size_bytes: number;
  truncated: boolean;
  findings: FindingSummary[];
}

export interface ReportOut {
  id: string;
  scan_id: string;
  format: ReportFormat;
  status: JobStatus;
  filename: string | null;
  size_bytes: number | null;
  sha256: string | null;
  error: string | null;
  created_at: string;
  completed_at: string | null;
}

export interface DeviceOut {
  serial: string;
  state: string;
  is_emulator: boolean;
  model: string | null;
  manufacturer: string | null;
  android_version: string | null;
  sdk_int: number | null;
  abi: string | null;
  rooted: boolean | null;
  frida_server_running: boolean | null;
  notes: string[];
}

export interface DeviceListResponse {
  devices: DeviceOut[];
  adb_available: boolean;
  frida_available: boolean;
  emulator_available: boolean;
  message: string | null;
}

export interface DynamicSession {
  id: string;
  apk_id: string;
  device_serial: string;
  status: string;
  modules: string[];
  device_info: Record<string, unknown>;
  capability_report: {
    install_and_launch?: boolean;
    log_capture?: boolean;
    instrumentation_possible?: boolean;
    network_capture?: boolean;
    blockers?: string[];
    notes?: string[];
  };
  events_count: number;
  error: string | null;
  created_at: string;
  started_at: string | null;
  stopped_at: string | null;
}

export interface RuntimeEvent {
  id: string;
  observed_at: string;
  event_type: string;
  module: string;
  process: string | null;
  api: string | null;
  severity: string | null;
  summary: string | null;
  data: Record<string, unknown>;
}

export interface DashboardStats {
  apks_total: number;
  scans_total: number;
  scans_by_status: Record<string, number>;
  findings_total: number;
  findings_by_severity: Record<string, number>;
  findings_by_category: { category: string; count: number }[];
  recent_scans: {
    id: string;
    apk_id: string;
    profile: string;
    status: string;
    findings_total: number;
    severity_counts: Record<string, number>;
    risk_score: number | null;
    risk_band: string | null;
    created_at: string | null;
    duration_seconds: number | null;
  }[];
}

export interface ComparisonResult {
  id: string;
  baseline_apk_id: string;
  updated_apk_id: string;
  summary: Record<string, unknown>;
  result: {
    baseline: Record<string, unknown>;
    updated: Record<string, unknown>;
    permissions: { added: string[]; removed: string[]; unchanged: string[] };
    components: { added: string[]; removed: string[]; unchanged: string[] };
    exported_components: { added: string[]; removed: string[]; unchanged: string[] };
    native_libraries: { added: string[]; removed: string[]; unchanged: string[] };
    dex_files: { added: string[]; removed: string[]; unchanged: string[] };
    sdk_changes: Record<string, { baseline: unknown; updated: unknown }>;
    application_flag_changes: Record<string, { baseline: unknown; updated: unknown }>;
    signing: {
      changed: boolean;
      baseline_fingerprints: string[];
      updated_fingerprints: string[];
      note: string;
    };
    findings: {
      available: boolean;
      new: FindingSummary[];
      resolved: FindingSummary[];
      unchanged: FindingSummary[];
    };
    scans: { comparable: boolean; note: string };
  };
  created_at: string;
}

export interface SettingsOut {
  analysis_concurrency: number;
  max_upload_bytes: number;
  analyzer_timeout_seconds: number;
  scan_timeout_seconds: number;
  decompile_timeout_seconds: number;
  artifact_retention_days: number;
  reuse_identical_scans: boolean;
  redact_secrets_in_reports: boolean;
  dynamic_analysis_enabled: boolean;
  dynamic_allow_physical_devices: boolean;
  log_level: string;
  tools: Record<string, boolean>;
}

export interface RuleOut {
  id: string;
  name: string;
  description: string;
  category: string;
  severity: Severity;
  confidence: Confidence;
  engine: string;
  version: string;
  cwe_ids: string[];
  masvs_controls: string[];
  references: string[];
  enabled: boolean;
}
