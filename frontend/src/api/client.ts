import type {
  AIFPAnalysisResponse,
  AuthUser,
  DashboardOverview,
  LoginResponse,
  Organization,
  OrganizationListResponse,
  OrganizationMetrics,
  SocChatResponse,
  UserListResponse,
  VulnListParams,
  Vulnerability,
  VulnerabilityListResponse,
} from './types'

const TOKEN_KEY = 'nexusec_access_token'

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

export function setToken(token: string | null): void {
  if (token) localStorage.setItem(TOKEN_KEY, token)
  else localStorage.removeItem(TOKEN_KEY)
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
}
