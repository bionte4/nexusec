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
}

export interface VulnListParams {
  page?: number
  page_size?: number
  status?: FindingStatus | ''
  severity?: Severity | ''
  asset_id?: string
  search?: string
}
