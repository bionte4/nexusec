import { useCallback, useEffect, useState, type FormEvent } from 'react'
import {
  Bell,
  Building2,
  HeartPulse,
  Shield,
  UserPlus,
  Users,
} from 'lucide-react'
import { api, ApiError } from '../api/client'
import type {
  AuthUser,
  Organization,
  OrganizationMetrics,
} from '../api/types'
import { useAuth } from '../auth/AuthContext'
import { useLocale } from '../i18n/locale'

type Tab = 'overview' | 'users' | 'organizations' | 'system' | 'alerts'

function roleLabel(role: string): string {
  return role.replaceAll('_', ' ')
}

export function AdminPage() {
  const { user, isAdmin, usingMock, token } = useAuth()
  const { t } = useLocale()
  const [tab, setTab] = useState<Tab>('overview')
  const [error, setError] = useState<string | null>(null)
  const [org, setOrg] = useState<Organization | null>(null)
  const [metrics, setMetrics] = useState<OrganizationMetrics | null>(null)
  const [users, setUsers] = useState<AuthUser[]>([])
  const [orgs, setOrgs] = useState<Organization[]>([])
  const [health, setHealth] = useState<Record<string, unknown> | null>(null)
  const [workers, setWorkers] = useState<Record<string, unknown> | null>(null)
  const [loading, setLoading] = useState(true)

  const [invite, setInvite] = useState({
    email: '',
    full_name: '',
    password: '',
    role: 'soc_analyst',
  })
  const [newOrg, setNewOrg] = useState({ name: '', slug: '', description: '' })
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState<string | null>(null)
  const [integrations, setIntegrations] = useState<{
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
  } | null>(null)
  const [webhookForm, setWebhookForm] = useState({
    enabled: false,
    provider: 'generic',
    min_severity: 'high',
    urlsText: '',
  })

  const load = useCallback(async () => {
    if (usingMock || token === 'demo') {
      setLoading(false)
      setError(t('admin.liveRequired'))
      return
    }
    if (!isAdmin) {
      setLoading(false)
      setError(t('admin.roleDenied'))
      return
    }
    setLoading(true)
    setError(null)
    try {
      const [meOrg, meMetrics, userList] = await Promise.all([
        api.myOrganization().catch(() => null),
        api.myOrganizationMetrics().catch(() => null),
        api.listUsers({ page_size: 50 }),
      ])
      setOrg(meOrg)
      setMetrics(meMetrics)
      setUsers(userList.items)

      if (user?.role === 'super_admin') {
        const orgList = await api.listOrganizations({ page_size: 50 })
        setOrgs(orgList.items)
      }

      if (tab === 'system') {
        const [h, w] = await Promise.all([
          api.healthDetailed().catch((err) => ({
            status: 'error',
            detail: err instanceof ApiError ? err.message : 'health failed',
          })),
          api.healthWorkers().catch((err) => ({
            status: 'error',
            detail: err instanceof ApiError ? err.message : 'workers failed',
          })),
        ])
        setHealth(h)
        setWorkers(w)
      }

      if (tab === 'alerts') {
        const status = await api.getIntegrationsStatus()
        setIntegrations(status)
        const settings = await api.getWebhookSettings().catch(() => null)
        if (settings) {
          setWebhookForm({
            enabled: settings.enabled,
            provider: settings.provider,
            min_severity: settings.min_severity,
            urlsText: '',
          })
        } else {
          setWebhookForm({
            enabled: status.webhook.enabled,
            provider: status.webhook.provider,
            min_severity: status.webhook.min_severity,
            urlsText: '',
          })
        }
      }
    } catch (err) {
      setError(
        err instanceof ApiError ? err.message : t('admin.loadFailed'),
      )
    } finally {
      setLoading(false)
    }
  }, [isAdmin, tab, token, user?.role, usingMock, t])

  useEffect(() => {
    void load()
  }, [load])

  async function onInvite(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setNotice(null)
    setError(null)
    try {
      await api.registerUser({
        ...invite,
        organization_id: user?.organization_id,
      })
      setNotice(t('admin.userCreated', { email: invite.email }))
      setInvite({
        email: '',
        full_name: '',
        password: '',
        role: 'soc_analyst',
      })
      await load()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t('admin.inviteFailed'))
    } finally {
      setBusy(false)
    }
  }

  async function onCreateOrg(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setNotice(null)
    setError(null)
    try {
      await api.createOrganization({
        name: newOrg.name,
        slug: newOrg.slug || undefined,
        description: newOrg.description || undefined,
      })
      setNotice(t('admin.orgCreated', { name: newOrg.name }))
      setNewOrg({ name: '', slug: '', description: '' })
      await load()
    } catch (err) {
      setError(
        err instanceof ApiError ? err.message : t('admin.createOrgFailed'),
      )
    } finally {
      setBusy(false)
    }
  }

  async function onSaveWebhook(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setNotice(null)
    setError(null)
    try {
      const payload: {
        enabled: boolean
        provider: string
        min_severity: string
        urls?: string[]
      } = {
        enabled: webhookForm.enabled,
        provider: webhookForm.provider,
        min_severity: webhookForm.min_severity,
      }
      const lines = webhookForm.urlsText
        .split('\n')
        .map((l) => l.trim())
        .filter(Boolean)
      if (lines.length > 0) payload.urls = lines
      await api.updateWebhookSettings(payload)
      setNotice(t('admin.webhookSaved'))
      setWebhookForm((f) => ({ ...f, urlsText: '' }))
      await load()
    } catch (err) {
      setError(
        err instanceof ApiError ? err.message : t('admin.webhookFailed'),
      )
    } finally {
      setBusy(false)
    }
  }

  const tabs: {
    id: Tab
    label: string
    icon: typeof Users
    adminOnly?: boolean
  }[] = [
    { id: 'overview', label: t('admin.tabOverview'), icon: Shield },
    { id: 'users', label: t('admin.tabUsers'), icon: Users },
    {
      id: 'organizations',
      label: t('admin.tabOrganizations'),
      icon: Building2,
      adminOnly: true,
    },
    { id: 'system', label: t('admin.tabSystem'), icon: HeartPulse },
    { id: 'alerts', label: t('admin.tabAlerts'), icon: Bell },
  ]

  if (!isAdmin && !loading) {
    return (
      <div className="panel rounded-xl p-8">
        <h1 className="text-lg font-semibold">{t('admin.title')}</h1>
        <p className="mt-2 text-sm text-surface-400">{t('admin.denied')}</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <div className="font-mono text-[11px] uppercase tracking-[0.2em] text-accent">
            {t('admin.eyebrow')}
          </div>
          <h1 className="mt-1 text-2xl font-semibold tracking-tight">
            {t('admin.title')}
          </h1>
          <p className="mt-1 text-sm text-surface-400">{t('admin.subtitle')}</p>
        </div>
        {user && (
          <div className="rounded-lg border border-surface-700 bg-surface-850 px-4 py-3 text-right">
            <div className="text-sm font-medium text-surface-100">
              {user.full_name}
            </div>
            <div className="font-mono text-[11px] uppercase tracking-wide text-accent">
              {roleLabel(user.role)}
            </div>
          </div>
        )}
      </header>

      <div className="flex flex-wrap gap-2">
        {tabs
          .filter((item) => !item.adminOnly || user?.role === 'super_admin')
          .map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              type="button"
              onClick={() => setTab(id)}
              className={[
                'inline-flex items-center gap-2 rounded-md px-3 py-2 text-sm transition-colors',
                tab === id
                  ? 'bg-accent/15 text-accent'
                  : 'bg-surface-800 text-surface-300 hover:text-surface-100',
              ].join(' ')}
            >
              <Icon className="h-4 w-4" />
              {label}
            </button>
          ))}
      </div>

      {error && (
        <div className="rounded-md border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-danger">
          {error}
        </div>
      )}
      {notice && (
        <div className="rounded-md border border-ok/30 bg-ok/10 px-4 py-3 text-sm text-ok">
          {notice}
        </div>
      )}

      {loading ? (
        <div className="py-16 text-center text-sm text-surface-400">
          {t('admin.loading')}
        </div>
      ) : (
        <>
          {tab === 'overview' && (
            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              <MetricCard
                label={t('admin.organization')}
                value={org?.name ?? '—'}
              />
              <MetricCard
                label={t('admin.users')}
                value={String(metrics?.users ?? users.length)}
              />
              <MetricCard
                label={t('admin.openFindings')}
                value={String(metrics?.open_vulnerabilities ?? '—')}
              />
              <MetricCard
                label={t('admin.criticalOpen')}
                value={String(metrics?.critical_open ?? '—')}
              />
              <div className="panel col-span-full rounded-xl p-5 md:col-span-2">
                <h2 className="text-sm font-semibold text-surface-100">
                  {t('admin.currentTenant')}
                </h2>
                <dl className="mt-3 grid gap-2 text-sm sm:grid-cols-2">
                  <div>
                    <dt className="text-surface-400">{t('admin.slug')}</dt>
                    <dd className="font-mono text-surface-100">
                      {org?.slug ?? '—'}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-surface-400">{t('admin.status')}</dt>
                    <dd>
                      {org?.is_active ? t('admin.active') : t('admin.inactive')}
                    </dd>
                  </div>
                  <div className="sm:col-span-2">
                    <dt className="text-surface-400">
                      {t('admin.description')}
                    </dt>
                    <dd className="text-surface-300">
                      {org?.description || t('admin.noDescription')}
                    </dd>
                  </div>
                </dl>
              </div>
              <div className="panel col-span-full rounded-xl p-5 md:col-span-2">
                <h2 className="text-sm font-semibold">
                  {t('admin.securityPosture')}
                </h2>
                <ul className="mt-3 space-y-2 text-sm text-surface-300">
                  <li>
                    {t('admin.metricAssets', {
                      count: metrics?.assets ?? '—',
                    })}
                  </li>
                  <li>
                    {t('admin.metricScans', { count: metrics?.scans ?? '—' })}
                  </li>
                  <li>
                    {t('admin.metricCde', {
                      count: metrics?.cde_assets ?? '—',
                    })}
                  </li>
                  <li>
                    {t('admin.metricExploited', {
                      count: metrics?.actively_exploited ?? '—',
                    })}
                  </li>
                </ul>
              </div>
            </div>
          )}

          {tab === 'users' && (
            <div className="grid gap-6 lg:grid-cols-[1.2fr_0.8fr]">
              <div className="panel overflow-hidden rounded-xl">
                <div className="border-b border-surface-700 px-5 py-4">
                  <h2 className="flex items-center gap-2 text-sm font-semibold">
                    <Users className="h-4 w-4 text-accent" />
                    {t('admin.usersHeading', { count: users.length })}
                  </h2>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm">
                    <thead className="bg-surface-850 font-mono text-[11px] uppercase tracking-wide text-surface-400">
                      <tr>
                        <th className="px-4 py-3">{t('admin.colName')}</th>
                        <th className="px-4 py-3">{t('admin.colEmail')}</th>
                        <th className="px-4 py-3">{t('admin.colRole')}</th>
                        <th className="px-4 py-3">{t('admin.colActive')}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {users.map((u) => (
                        <tr
                          key={u.id}
                          className="border-t border-surface-800 text-surface-200"
                        >
                          <td className="px-4 py-3">{u.full_name}</td>
                          <td className="px-4 py-3 font-mono text-xs">
                            {u.email}
                          </td>
                          <td className="px-4 py-3 capitalize">
                            {roleLabel(u.role)}
                          </td>
                          <td className="px-4 py-3">
                            {u.is_active ? t('admin.yes') : t('admin.no')}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              <form
                onSubmit={onInvite}
                className="panel space-y-3 rounded-xl p-5"
              >
                <h2 className="flex items-center gap-2 text-sm font-semibold">
                  <UserPlus className="h-4 w-4 text-accent" />
                  {t('admin.inviteUser')}
                </h2>
                <input
                  required
                  type="email"
                  placeholder={t('admin.email')}
                  value={invite.email}
                  onChange={(e) =>
                    setInvite((s) => ({ ...s, email: e.target.value }))
                  }
                  className="w-full rounded-md border border-surface-700 bg-surface-900 px-3 py-2 text-sm"
                />
                <input
                  required
                  placeholder={t('admin.fullName')}
                  value={invite.full_name}
                  onChange={(e) =>
                    setInvite((s) => ({ ...s, full_name: e.target.value }))
                  }
                  className="w-full rounded-md border border-surface-700 bg-surface-900 px-3 py-2 text-sm"
                />
                <input
                  required
                  type="password"
                  minLength={12}
                  placeholder={t('admin.tempPassword')}
                  value={invite.password}
                  onChange={(e) =>
                    setInvite((s) => ({ ...s, password: e.target.value }))
                  }
                  className="w-full rounded-md border border-surface-700 bg-surface-900 px-3 py-2 text-sm"
                />
                <select
                  value={invite.role}
                  onChange={(e) =>
                    setInvite((s) => ({ ...s, role: e.target.value }))
                  }
                  className="w-full rounded-md border border-surface-700 bg-surface-900 px-3 py-2 text-sm"
                >
                  <option value="soc_analyst">{t('admin.roleSocAnalyst')}</option>
                  <option value="pentester">{t('admin.rolePentester')}</option>
                  <option value="admin">{t('admin.roleAdmin')}</option>
                  {user?.role === 'super_admin' && (
                    <option value="super_admin">
                      {t('admin.roleSuperAdmin')}
                    </option>
                  )}
                </select>
                <button
                  type="submit"
                  disabled={busy}
                  className="w-full rounded-md bg-accent px-3 py-2 text-sm font-medium text-surface-950 disabled:opacity-50"
                >
                  {busy ? t('admin.creating') : t('admin.createUser')}
                </button>
              </form>
            </div>
          )}

          {tab === 'organizations' && user?.role === 'super_admin' && (
            <div className="grid gap-6 lg:grid-cols-[1.2fr_0.8fr]">
              <div className="panel overflow-hidden rounded-xl">
                <div className="border-b border-surface-700 px-5 py-4">
                  <h2 className="text-sm font-semibold">
                    {t('admin.orgsHeading', { count: orgs.length })}
                  </h2>
                </div>
                <ul className="divide-y divide-surface-800">
                  {orgs.map((o) => (
                    <li key={o.id} className="px-5 py-4">
                      <div className="font-medium">{o.name}</div>
                      <div className="font-mono text-xs text-surface-400">
                        {o.slug} ·{' '}
                        {o.is_active ? t('admin.active') : t('admin.inactive')}
                      </div>
                      {o.description && (
                        <p className="mt-1 text-sm text-surface-300">
                          {o.description}
                        </p>
                      )}
                    </li>
                  ))}
                </ul>
              </div>
              <form
                onSubmit={onCreateOrg}
                className="panel space-y-3 rounded-xl p-5"
              >
                <h2 className="flex items-center gap-2 text-sm font-semibold">
                  <Building2 className="h-4 w-4 text-accent" />
                  {t('admin.onboardTenant')}
                </h2>
                <input
                  required
                  placeholder={t('admin.orgName')}
                  value={newOrg.name}
                  onChange={(e) =>
                    setNewOrg((s) => ({ ...s, name: e.target.value }))
                  }
                  className="w-full rounded-md border border-surface-700 bg-surface-900 px-3 py-2 text-sm"
                />
                <input
                  placeholder={t('admin.slugOptional')}
                  value={newOrg.slug}
                  onChange={(e) =>
                    setNewOrg((s) => ({ ...s, slug: e.target.value }))
                  }
                  className="w-full rounded-md border border-surface-700 bg-surface-900 px-3 py-2 text-sm"
                />
                <textarea
                  placeholder={t('admin.descriptionPlaceholder')}
                  value={newOrg.description}
                  onChange={(e) =>
                    setNewOrg((s) => ({ ...s, description: e.target.value }))
                  }
                  rows={3}
                  className="w-full rounded-md border border-surface-700 bg-surface-900 px-3 py-2 text-sm"
                />
                <button
                  type="submit"
                  disabled={busy}
                  className="w-full rounded-md bg-accent px-3 py-2 text-sm font-medium text-surface-950 disabled:opacity-50"
                >
                  {busy ? t('admin.creating') : t('admin.createOrg')}
                </button>
              </form>
            </div>
          )}

          {tab === 'system' && (
            <div className="space-y-4">
              <SystemStatusPanel
                title={t('admin.platformDeps')}
                payload={health}
                loadingLabel={t('admin.loadingPanel', {
                  title: t('admin.platformDeps').toLowerCase(),
                })}
              />
              <SystemStatusPanel
                title={t('admin.workersTools')}
                payload={workers}
                loadingLabel={t('admin.loadingPanel', {
                  title: t('admin.workersTools').toLowerCase(),
                })}
              />
            </div>
          )}

          {tab === 'alerts' && (
            <div className="grid gap-6 lg:grid-cols-2">
              <div className="panel space-y-3 rounded-xl p-5">
                <h2 className="text-sm font-semibold">{t('admin.alertsTitle')}</h2>
                <p className="text-xs text-surface-400">{t('admin.alertsSubtitle')}</p>
                {integrations ? (
                  <ul className="space-y-2 text-sm text-surface-300">
                    <li>
                      Webhook · {integrations.webhook.provider} ·{' '}
                      {t('admin.endpointsConfigured', {
                        count: integrations.webhook.endpoints_configured,
                      })}{' '}
                      · min {integrations.webhook.min_severity}
                      {integrations.webhook.source
                        ? ` · ${t('admin.webhookSource', {
                            source: integrations.webhook.source,
                          })}`
                        : ''}
                    </li>
                    {(integrations.webhook.urls_masked || []).map((u) => (
                      <li key={u} className="font-mono text-[11px] text-surface-400">
                        {u}
                      </li>
                    ))}
                    <li>
                      {t('admin.ticketingStatus')}:{' '}
                      {String(integrations.ticketing.enabled ? 'on' : 'off')} /{' '}
                      {String(integrations.ticketing.provider)}
                    </li>
                    <li>
                      {t('admin.siemStatus')}:{' '}
                      {String(integrations.siem.enabled ? 'on' : 'off')} /{' '}
                      {String(integrations.siem.format)}
                    </li>
                  </ul>
                ) : (
                  <p className="text-sm text-surface-400">{t('admin.loading')}</p>
                )}
              </div>

              <form
                onSubmit={onSaveWebhook}
                className="panel space-y-3 rounded-xl p-5"
              >
                <h2 className="flex items-center gap-2 text-sm font-semibold">
                  <Bell className="h-4 w-4 text-accent" />
                  {t('admin.webhookSave')}
                </h2>
                <label className="flex items-center gap-2 text-xs text-surface-300">
                  <input
                    type="checkbox"
                    checked={webhookForm.enabled}
                    onChange={(e) =>
                      setWebhookForm((f) => ({
                        ...f,
                        enabled: e.target.checked,
                      }))
                    }
                  />
                  {t('admin.webhookEnabled')}
                </label>
                <label className="block space-y-1 text-xs text-surface-400">
                  {t('admin.webhookProvider')}
                  <select
                    value={webhookForm.provider}
                    onChange={(e) =>
                      setWebhookForm((f) => ({
                        ...f,
                        provider: e.target.value,
                      }))
                    }
                    className="w-full rounded-md border border-surface-700 bg-surface-900 px-3 py-2 text-sm"
                  >
                    <option value="generic">generic</option>
                    <option value="slack">slack</option>
                    <option value="teams">teams</option>
                  </select>
                </label>
                <label className="block space-y-1 text-xs text-surface-400">
                  {t('admin.webhookMinSeverity')}
                  <select
                    value={webhookForm.min_severity}
                    onChange={(e) =>
                      setWebhookForm((f) => ({
                        ...f,
                        min_severity: e.target.value,
                      }))
                    }
                    className="w-full rounded-md border border-surface-700 bg-surface-900 px-3 py-2 text-sm"
                  >
                    <option value="critical">critical</option>
                    <option value="high">high</option>
                    <option value="medium">medium</option>
                    <option value="low">low</option>
                  </select>
                </label>
                <label className="block space-y-1 text-xs text-surface-400">
                  {t('admin.webhookUrls')}
                  <textarea
                    value={webhookForm.urlsText}
                    onChange={(e) =>
                      setWebhookForm((f) => ({
                        ...f,
                        urlsText: e.target.value,
                      }))
                    }
                    rows={3}
                    placeholder="https://hooks.slack.com/..."
                    className="w-full rounded-md border border-surface-700 bg-surface-900 px-3 py-2 font-mono text-xs"
                  />
                </label>
                <p className="text-[11px] text-surface-500">
                  {t('admin.webhookUrlsHint')}
                </p>
                <button
                  type="submit"
                  disabled={busy}
                  className="w-full rounded-md bg-accent px-3 py-2 text-sm font-medium text-surface-950 disabled:opacity-50"
                >
                  {busy ? t('admin.creating') : t('admin.webhookSave')}
                </button>
              </form>
            </div>
          )}
        </>
      )}
    </div>
  )
}

function statusColor(status: string | undefined): string {
  switch (status) {
    case 'ok':
      return 'text-ok'
    case 'degraded':
      return 'text-warn'
    case 'unavailable':
    case 'error':
      return 'text-danger'
    default:
      return 'text-surface-400'
  }
}

function SystemStatusPanel({
  title,
  payload,
  loadingLabel,
}: {
  title: string
  payload: Record<string, unknown> | null
  loadingLabel: string
}) {
  if (!payload) {
    return (
      <div className="panel rounded-xl p-5 text-sm text-surface-400">
        {loadingLabel}
      </div>
    )
  }

  const overall = String(payload.status ?? 'unknown')
  const checks = (payload.checks ?? null) as Record<
    string,
    { status?: string; latency_ms?: number; detail?: string; meta?: unknown }
  > | null

  return (
    <div className="panel rounded-xl p-5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-sm font-semibold">{title}</h2>
        <span
          className={`font-mono text-[11px] uppercase tracking-wide ${statusColor(overall)}`}
        >
          {overall}
        </span>
      </div>

      {checks && (
        <div className="mt-4 grid gap-3 sm:grid-cols-2">
          {Object.entries(checks).map(([name, info]) => (
            <div
              key={name}
              className="rounded-lg border border-surface-700 bg-surface-900/60 px-3 py-3"
            >
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm capitalize text-surface-100">
                  {name}
                </span>
                <span
                  className={`font-mono text-[11px] uppercase ${statusColor(info.status)}`}
                >
                  {info.status ?? '—'}
                </span>
              </div>
              {info.latency_ms != null && (
                <div className="mt-1 font-mono text-[11px] text-surface-400">
                  {info.latency_ms} ms
                </div>
              )}
              {info.detail && (
                <div className="mt-1 text-xs text-surface-400">{info.detail}</div>
              )}
            </div>
          ))}
        </div>
      )}

      {!checks && (
        <pre className="mt-3 max-h-72 overflow-auto font-mono text-xs text-surface-300">
          {JSON.stringify(payload, null, 2)}
        </pre>
      )}
    </div>
  )
}

function MetricCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="panel rounded-xl p-4">
      <div className="font-mono text-[10px] uppercase tracking-[0.16em] text-surface-400">
        {label}
      </div>
      <div className="mt-2 truncate text-lg font-semibold text-surface-100">
        {value}
      </div>
    </div>
  )
}
