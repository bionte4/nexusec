import type {
  AIFPAnalysisResponse,
  AIRemediationResponse,
  Asset,
  AssetCreatePayload,
  AssetListResponse,
  AuthUser,
  DashboardOverview,
  LoginResponse,
  Organization,
  OrganizationListResponse,
  OrganizationMetrics,
  ScanCreatePayload,
  ScanEnqueueResponse,
  ScanListResponse,
  ScanSchedule,
  ScanScheduleCreatePayload,
  ScanScheduleListResponse,
  SocChatResponse,
  Scan,
  UserListResponse,
  VulnListParams,
  Vulnerability,
  VulnerabilityListResponse,
} from './types'

const TOKEN_KEY = 'nexusec_access_token'
const ORG_KEY = 'nexusec_organization_id'

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

export function setToken(token: string | null): void {
  if (token) localStorage.setItem(TOKEN_KEY, token)
  else localStorage.removeItem(TOKEN_KEY)
}

export function getOrganizationId(): string | null {
  return localStorage.getItem(ORG_KEY)
}

export function setOrganizationId(orgId: string | null): void {
  if (orgId) localStorage.setItem(ORG_KEY, orgId)
  else localStorage.removeItem(ORG_KEY)
}

export class ApiError extends Error {
  status: number

  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function request<T>(
  path: string,
  options: RequestInit = {},
  allowStatuses: number[] = [],
): Promise<T> {
  const headers = new Headers(options.headers)
  if (!headers.has('Content-Type') && options.body) {
    headers.set('Content-Type', 'application/json')
  }
  const token = getToken()
  if (token) headers.set('Authorization', `Bearer ${token}`)
  const orgId = getOrganizationId()
  if (orgId && !headers.has('X-Organization-Id')) {
    headers.set('X-Organization-Id', orgId)
  }

  const res = await fetch(path, { ...options, headers })
  if (!res.ok && !allowStatuses.includes(res.status)) {
    let detail = res.statusText
    try {
      const body = (await res.json()) as { detail?: string | unknown }
      if (typeof body.detail === 'string') detail = body.detail
      else if (body.detail != null) detail = JSON.stringify(body.detail)
    } catch {
      /* ignore */
    }
    throw new ApiError(res.status, detail)
  }
  if (res.status === 204) return undefined as T
  return (await res.json()) as T
}

export const api = {
  login(email: string, password: string) {
    return request<LoginResponse>('/api/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    })
  },

  dashboardOverview(trendDays = 30) {
    return request<DashboardOverview>(
      `/api/v1/dashboard/overview?trend_days=${trendDays}`,
    )
  },

  listVulnerabilities(params: VulnListParams = {}) {
    const q = new URLSearchParams()
    if (params.page) q.set('page', String(params.page))
    if (params.page_size) q.set('page_size', String(params.page_size))
    if (params.status) q.set('status', params.status)
    if (params.severity) q.set('severity', params.severity)
    if (params.asset_id) q.set('asset_id', params.asset_id)
    if (params.scan_id) q.set('scan_id', params.scan_id)
    if (params.search) q.set('search', params.search)
    const qs = q.toString()
    return request<VulnerabilityListResponse>(
      `/api/v1/vulnerabilities${qs ? `?${qs}` : ''}`,
    )
  },

  getVulnerability(id: string) {
    return request<Vulnerability>(`/api/v1/vulnerabilities/${id}`)
  },

  assignOwner(id: string, remediation_owner_label: string) {
    return request<Vulnerability>(`/api/v1/vulnerabilities/${id}/assign`, {
      method: 'POST',
      body: JSON.stringify({ remediation_owner_label }),
    })
  },

  updateVulnerability(
    id: string,
    payload: {
      status?: string
      remediation?: string
      remediation_owner_label?: string
    },
  ) {
    return request<Vulnerability>(`/api/v1/vulnerabilities/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    })
  },

  analyzeFalsePositive(id: string, persist = true) {
    const q = persist ? '' : '?persist=false'
    return request<AIFPAnalysisResponse>(
      `/api/v1/vulnerabilities/${id}/analyze-fp${q}`,
      { method: 'POST' },
    )
  },

  generateAiPatch(id: string, persist = true) {
    const q = persist ? '' : '?persist=false'
    return request<AIRemediationResponse>(
      `/api/v1/vulnerabilities/${id}/generate-ai-patch${q}`,
      { method: 'POST' },
    )
  },

  socChat(query: string) {
    return request<SocChatResponse>('/api/v1/soc/chat', {
      method: 'POST',
      body: JSON.stringify({ query }),
    })
  },

  me() {
    return request<AuthUser>('/api/v1/auth/me')
  },

  listUsers(params: { page?: number; page_size?: number; search?: string } = {}) {
    const q = new URLSearchParams()
    if (params.page) q.set('page', String(params.page))
    if (params.page_size) q.set('page_size', String(params.page_size))
    if (params.search) q.set('search', params.search)
    const qs = q.toString()
    return request<UserListResponse>(`/api/v1/auth/users${qs ? `?${qs}` : ''}`)
  },

  registerUser(payload: {
    email: string
    full_name: string
    password: string
    role: string
    organization_id?: string | null
  }) {
    return request<AuthUser>('/api/v1/auth/register', {
      method: 'POST',
      body: JSON.stringify(payload),
    })
  },

  listRoles() {
    return request<{ roles: string[] }>('/api/v1/auth/roles')
  },

  myOrganization() {
    return request<Organization>('/api/v1/organizations/me')
  },

  myOrganizationMetrics() {
    return request<OrganizationMetrics>('/api/v1/organizations/me/metrics')
  },

  listOrganizations(params: { page?: number; page_size?: number; search?: string } = {}) {
    const q = new URLSearchParams()
    if (params.page) q.set('page', String(params.page))
    if (params.page_size) q.set('page_size', String(params.page_size))
    if (params.search) q.set('search', params.search)
    const qs = q.toString()
    return request<OrganizationListResponse>(
      `/api/v1/organizations${qs ? `?${qs}` : ''}`,
    )
  },

  createOrganization(payload: {
    name: string
    slug?: string
    description?: string
  }) {
    return request<Organization>('/api/v1/organizations', {
      method: 'POST',
      body: JSON.stringify(payload),
    })
  },

  healthDetailed() {
    return request<Record<string, unknown>>('/api/v1/health/detailed', {}, [503])
  },

  healthWorkers() {
    return request<Record<string, unknown>>('/api/v1/health/workers', {}, [503])
  },

  listAssets(params: {
    page?: number
    page_size?: number
    search?: string
    asset_type?: string
    criticality?: string
    is_cde_scope?: boolean
  } = {}) {
    const q = new URLSearchParams()
    if (params.page) q.set('page', String(params.page))
    if (params.page_size) q.set('page_size', String(params.page_size))
    if (params.search) q.set('search', params.search)
    if (params.asset_type) q.set('asset_type', params.asset_type)
    if (params.criticality) q.set('criticality', params.criticality)
    if (params.is_cde_scope != null) q.set('is_cde_scope', String(params.is_cde_scope))
    const qs = q.toString()
    return request<AssetListResponse>(`/api/v1/assets${qs ? `?${qs}` : ''}`)
  },

  createAsset(payload: AssetCreatePayload) {
    return request<Asset>('/api/v1/assets', {
      method: 'POST',
      body: JSON.stringify(payload),
    })
  },

  updateAsset(id: string, payload: Partial<AssetCreatePayload>) {
    return request<Asset>(`/api/v1/assets/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    })
  },

  listScans(params: {
    page?: number
    page_size?: number
    status?: string
    engine?: string
  } = {}) {
    const q = new URLSearchParams()
    if (params.page) q.set('page', String(params.page))
    if (params.page_size) q.set('page_size', String(params.page_size))
    if (params.status) q.set('status', params.status)
    if (params.engine) q.set('engine', params.engine)
    const qs = q.toString()
    return request<ScanListResponse>(`/api/v1/scans${qs ? `?${qs}` : ''}`)
  },

  createScan(payload: ScanCreatePayload) {
    return request<ScanEnqueueResponse>('/api/v1/scans', {
      method: 'POST',
      body: JSON.stringify(payload),
    })
  },

  startScan(id: string) {
    return request<ScanEnqueueResponse>(`/api/v1/scans/${id}/start`, {
      method: 'POST',
    })
  },

  getComplianceReport(kind: 'iso27001' | 'pci-dss' | 'gdpr' | 'nist-csf') {
    return request<Record<string, unknown>>(`/api/v1/reports/${kind}`)
  },

  suggestNistControls(id: string, opts: { persist?: boolean; use_llm?: boolean } = {}) {
    const q = new URLSearchParams()
    if (opts.persist != null) q.set('persist', String(opts.persist))
    if (opts.use_llm != null) q.set('use_llm', String(opts.use_llm))
    const qs = q.toString()
    return request<{
      vulnerability_id: string
      nist_csf: string[]
      nist_800_53: string[]
      reasoning: string
      provider: string
      model: string
      status: string
      current_compliance: { nist_csf: string[]; nist_800_53: string[] }
    }>(`/api/v1/vulnerabilities/${id}/suggest-nist-controls${qs ? `?${qs}` : ''}`, {
      method: 'POST',
    })
  },

  acceptNistControls(
    id: string,
    payload: { nist_csf?: string[]; nist_800_53?: string[] } = {},
  ) {
    return request<{
      vulnerability_id: string
      status: string
      compliance_metadata: Record<string, unknown>
    }>(`/api/v1/vulnerabilities/${id}/accept-nist-controls`, {
      method: 'POST',
      body: JSON.stringify(payload),
    })
  },

  getScan(id: string) {
    return request<Scan>(`/api/v1/scans/${id}`)
  },

  getScanEvidence(id: string) {
    return request<{
      scan_id: string
      status: string
      progress: number
      error_message: string | null
      engine: string
      command?: string[]
      returncode?: number
      truncated?: boolean
      finished_at?: string
      ingest?: Record<string, unknown>
      stderr: string
      stdout_preview: string
      stdout_truncated: boolean
      stdout_chars: number
    }>(`/api/v1/scans/${id}/evidence`)
  },

  getScanDiff(id: string, baselineScanId?: string) {
    const q = baselineScanId
      ? `?baseline_scan_id=${encodeURIComponent(baselineScanId)}`
      : ''
    return request<{
      scan_id: string
      baseline_scan_id: string
      engine: string
      method: string
      new: Array<Record<string, unknown>>
      resolved: Array<Record<string, unknown>>
      unchanged_count: number
      counts: { new: number; resolved: number; unchanged: number }
    }>(`/api/v1/scans/${id}/diff${q}`)
  },

  getDiscoveredHosts(scanId: string) {
    return request<{
      scan_id: string
      total: number
      new_count: number
      hosts: Array<{
        ip_address: string | null
        hostname: string | null
        already_known: boolean
        matched_asset_id: string | null
        suggested_asset: Record<string, unknown>
        open_ports: Array<Record<string, unknown>>
      }>
    }>(`/api/v1/scans/${scanId}/discovered-hosts`)
  },

  acceptDiscoveredHosts(
    scanId: string,
    hosts: Array<{
      ip_address?: string | null
      hostname?: string | null
      name?: string
      criticality?: string
    }>,
  ) {
    return request<{
      created_count: number
      skipped_count: number
      created: unknown[]
      skipped: unknown[]
    }>(`/api/v1/scans/${scanId}/discovered-hosts/accept`, {
      method: 'POST',
      body: JSON.stringify({ hosts }),
    })
  },

  getIntegrationsStatus() {
    return request<{
      webhook: {
        enabled: boolean
        provider: string
        endpoints_configured: number
        urls_masked?: string[]
        min_severity: string
        source?: string
      }
      ticketing: Record<string, unknown>
      siem: Record<string, unknown>
    }>('/api/v1/integrations/status')
  },

  getWebhookSettings() {
    return request<{
      enabled: boolean
      provider: string
      min_severity: string
      urls_masked: string[]
      endpoints_configured: number
      source: string
    }>('/api/v1/integrations/webhook-settings')
  },

  updateWebhookSettings(payload: {
    enabled?: boolean
    provider?: string
    min_severity?: string
    urls?: string[]
  }) {
    return request<{
      enabled: boolean
      provider: string
      min_severity: string
      urls_masked: string[]
      endpoints_configured: number
      source: string
    }>('/api/v1/integrations/webhook-settings', {
      method: 'PATCH',
      body: JSON.stringify(payload),
    })
  },

  listScanSchedules(params: { page?: number; page_size?: number; enabled?: boolean } = {}) {
    const q = new URLSearchParams()
    if (params.page) q.set('page', String(params.page))
    if (params.page_size) q.set('page_size', String(params.page_size))
    if (params.enabled != null) q.set('enabled', String(params.enabled))
    const qs = q.toString()
    return request<ScanScheduleListResponse>(
      `/api/v1/scan-schedules${qs ? `?${qs}` : ''}`,
    )
  },

  createScanSchedule(payload: ScanScheduleCreatePayload) {
    return request<ScanSchedule>('/api/v1/scan-schedules', {
      method: 'POST',
      body: JSON.stringify(payload),
    })
  },

  updateScanSchedule(
    id: string,
    payload: Partial<ScanScheduleCreatePayload> & { enabled?: boolean },
  ) {
    return request<ScanSchedule>(`/api/v1/scan-schedules/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    })
  },

  deleteScanSchedule(id: string) {
    return request<void>(`/api/v1/scan-schedules/${id}`, { method: 'DELETE' })
  },
}
