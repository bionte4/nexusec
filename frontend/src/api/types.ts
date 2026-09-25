export type Severity =
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'info'
  | 'unknown'

export type FindingStatus =
  | 'open'
  | 'in_progress'
  | 'false_positive'
  | 'resolved'
  | 'confirmed'
  | 'accepted_risk'
  | 'remediated'
  | 'reopened'

export interface SeverityCount {
  critical: number
  high: number
  medium: number
  low: number
  info: number
  unknown: number
  total: number
}

export interface TrendPoint {
  day: string
  open_count: number
  resolved_count: number
}

export interface AssetRiskSummary {
  asset_id: string
  asset_name: string
  asset_type: string
  is_cde_scope: boolean
  criticality: string
  active_critical: number
  active_high: number
  active_medium: number
  active_low: number
  active_total: number
  risk_score: number
}

export interface DashboardOverview {
  generated_at: string
  active_by_severity: SeverityCount
  status_breakdown: Record<string, number>
  total_assets: number
  assets_with_active_findings: number
  overdue_findings?: number
  asset_risk_posture: AssetRiskSummary[]
  trend: TrendPoint[]
}

export interface VulnerabilityComment {
  id: string
  vulnerability_id: string
  author_id: string | null
  body: string
  created_at: string
}

export interface Vulnerability {
  id: string
  scan_id: string
  asset_id: string
  fingerprint: string
  title: string
  description: string | null
  severity: Severity
  status: FindingStatus
  cve_id: string | null
  cwe_id: string | null
  cvss_score: number | null
  cvss_vector: string | null
  affected_component: string | null
  port: number | null
  protocol: string | null
  evidence: Record<string, unknown>
  remediation: string | null
  owasp_category: string | null
  mitre_attack_techniques: unknown[]
  compliance_metadata: Record<string, unknown>
  source_tool: string | null
  remediation_owner_id: string | null
  remediation_owner_label: string | null
  status_changed_at: string | null
  is_actively_exploited?: boolean
  has_public_exploit?: boolean
  epss_score?: number | null
  epss_percentile?: number | null
  threat_risk_score?: number | null
  remediation_due_at?: string | null
  last_retest_scan_id?: string | null
  threat_intel_metadata?: Record<string, unknown>
  first_seen_at: string
  last_seen_at: string
  created_at: string
  updated_at: string
  comments: VulnerabilityComment[]
}

export interface AIFPAnalysisResponse {
  vulnerability_id: string
  provider: string
  model: string
  confidence_score: number
  is_likely_false_positive: boolean
  reasoning: string
  vulnerability: Vulnerability
}

export interface AIRemediationResponse {
  vulnerability_id: string
  provider: string
  model: string
  explanation: string
  remediation_steps: string
  patch_example: string
  remediation: string
  vulnerability: Vulnerability
}

export interface SocChatResponse {
  answer: string
  provider: string
  model: string
  intent: Record<string, boolean>
  stats: Record<string, unknown>
  sources: Record<string, unknown>[]
  context_chars: number
}

export interface VulnerabilityListResponse {
  items: Vulnerability[]
  total: number
  page: number
  page_size: number
  pages: number
}

export interface LoginResponse {
  access_token: string
  refresh_token: string
  token_type: string
  user?: AuthUser
}

export interface AuthUser {
  id: string
  email: string
  full_name: string
  role: 'super_admin' | 'admin' | 'pentester' | 'soc_analyst'
  organization_id: string | null
  is_active: boolean
  created_at: string
  updated_at: string
}

export interface UserListResponse {
  items: AuthUser[]
  total: number
  page: number
  page_size: number
  pages: number
}

export interface Organization {
  id: string
  name: string
  slug: string
  description: string | null
  is_active: boolean
  workspace_token_prefix: string | null
  settings: Record<string, unknown>
  created_at: string
  updated_at: string
}

export interface OrganizationListResponse {
  items: Organization[]
  total: number
  page: number
  page_size: number
  pages: number
}

export interface OrganizationMetrics {
  organization_id: string
  users: number
  assets: number
  scans: number
  open_vulnerabilities: number
  critical_open: number
  actively_exploited: number
  cde_assets: number
}

export interface VulnListParams {
  page?: number
  page_size?: number
  status?: FindingStatus | ''
  severity?: Severity | ''
  asset_id?: string
  scan_id?: string
  search?: string
  overdue?: boolean
}

export type AssetType = 'ip' | 'domain' | 'cloud_resource'
export type AssetCriticality = 'critical' | 'high' | 'medium' | 'low'
export type ScanStatus =
  | 'pending'
  | 'queued'
  | 'running'
  | 'completed'
  | 'failed'
  | 'cancelled'
export type ScanType = 'va' | 'pt' | 'discovery' | 'compliance' | 'custom'
export type ScannerEngine = 'nexusec' | 'nmap' | 'nuclei' | 'openvas' | 'other'

export interface Asset {
  id: string
  organization_id: string
  name: string
  asset_type: AssetType
  criticality: AssetCriticality
  ip_address: string | null
  domain: string | null
  cloud_resource_id: string | null
  cloud_provider: string | null
  is_cde_scope: boolean
  hostname: string | null
  url: string | null
  environment: string | null
  owner: string | null
  description: string | null
  tags: Record<string, unknown>
  metadata: Record<string, unknown>
  created_by_id: string | null
  created_at: string
  updated_at: string
}

export interface AssetListResponse {
  items: Asset[]
  total: number
  page: number
  page_size: number
  pages: number
}

export interface AssetCreatePayload {
  name: string
  asset_type: AssetType
  criticality?: AssetCriticality
  ip_address?: string | null
  domain?: string | null
  cloud_resource_id?: string | null
  cloud_provider?: string | null
  is_cde_scope?: boolean
  hostname?: string | null
  url?: string | null
  environment?: string | null
  owner?: string | null
  description?: string | null
}

export interface Scan {
  id: string
  organization_id: string | null
  name: string
  scan_type: ScanType
  engine: ScannerEngine
  status: ScanStatus
  progress: number
  config: Record<string, unknown>
  celery_task_id: string | null
  error_message: string | null
  started_at: string | null
  completed_at: string | null
  created_by_id: string | null
  created_at: string
  updated_at: string
  asset_ids: string[]
}

export interface ScanListResponse {
  items: Scan[]
  total: number
  page: number
  page_size: number
  pages: number
}

export interface ScanEnqueueResponse {
  scan: Scan
  celery_task_id: string | null
  message: string
}

export interface ScanCreatePayload {
  name: string
  scan_type?: ScanType
  engine?: ScannerEngine
  asset_ids: string[]
  config?: Record<string, unknown>
  start_immediately?: boolean
}

export interface ScanSchedule {
  id: string
  organization_id: string
  name: string
  scan_type: ScanType
  engine: ScannerEngine
  config: Record<string, unknown>
  interval_minutes: number
  enabled: boolean
  next_run_at: string
  last_run_at: string | null
  last_scan_id: string | null
  last_error: string | null
  created_by_id: string | null
  created_at: string
  updated_at: string
  asset_ids: string[]
}

export interface ScanScheduleListResponse {
  items: ScanSchedule[]
  total: number
  page: number
  page_size: number
  pages: number
}

export interface ScanScheduleCreatePayload {
  name: string
  scan_type?: ScanType
  engine?: ScannerEngine
  asset_ids: string[]
  config?: Record<string, unknown>
  interval_minutes: number
  enabled?: boolean
  run_immediately?: boolean
}
