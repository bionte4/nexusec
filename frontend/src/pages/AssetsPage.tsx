import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { Link } from 'react-router-dom'
import { Plus, Search, Server } from 'lucide-react'
import {
  api,
  ApiError,
  getOrganizationId,
  setOrganizationId,
} from '../api/client'
import type {
  Asset,
  AssetCriticality,
  AssetType,
  Organization,
} from '../api/types'
import { useAuth } from '../auth/AuthContext'

const ASSET_TYPES: AssetType[] = ['ip', 'domain', 'cloud_resource']
const CRITICALITIES: AssetCriticality[] = ['critical', 'high', 'medium', 'low']

export function AssetsPage() {
  const { usingMock, token, user, isAdmin } = useAuth()
  const canWrite =
    user?.role === 'super_admin' ||
    user?.role === 'admin' ||
    user?.role === 'pentester'

  const [items, setItems] = useState<Asset[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [busy, setBusy] = useState(false)
  const [orgs, setOrgs] = useState<Organization[]>([])
  const [selectedOrg, setSelectedOrg] = useState(() => getOrganizationId() ?? '')

  const [form, setForm] = useState({
    name: '',
    asset_type: 'domain' as AssetType,
    criticality: 'medium' as AssetCriticality,
    ip_address: '',
    domain: '',
    cloud_resource_id: '',
    url: '',
    environment: 'production',
    owner: '',
    description: '',
    is_cde_scope: false,
  })

  const load = useCallback(async () => {
    if (usingMock || token === 'demo') {
      setLoading(false)
      setError('Assets require a live API session (not demo mode).')
      return
    }
    setLoading(true)
    setError(null)
    try {
      if (user?.role === 'super_admin') {
        const orgList = await api.listOrganizations({ page_size: 50 })
        setOrgs(orgList.items)
        const current = getOrganizationId()
        if (!current && orgList.items[0]) {
          setOrganizationId(orgList.items[0].id)
          setSelectedOrg(orgList.items[0].id)
        } else if (current) {
          setSelectedOrg(current)
        }
      }
      const res = await api.listAssets({ page: 1, page_size: 100, search: search || undefined })
      setItems(res.items)
      setTotal(res.total)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load assets')
      setItems([])
      setTotal(0)
    } finally {
      setLoading(false)
    }
  }, [search, token, user?.role, usingMock])

  useEffect(() => {
    void load()
  }, [load])

  function onOrgChange(orgId: string) {
    setSelectedOrg(orgId)
    setOrganizationId(orgId || null)
    void load()
  }

  async function onCreate(e: FormEvent) {
    e.preventDefault()
    if (!canWrite) return
    setBusy(true)
    setNotice(null)
    setError(null)
    try {
      if (user?.role === 'super_admin' && selectedOrg) {
        setOrganizationId(selectedOrg)
      }
      const payload = {
        name: form.name.trim(),
        asset_type: form.asset_type,
        criticality: form.criticality,
        ip_address: form.ip_address.trim() || null,
        domain: form.domain.trim() || null,
        cloud_resource_id: form.cloud_resource_id.trim() || null,
        url: form.url.trim() || null,
        environment: form.environment.trim() || null,
        owner: form.owner.trim() || null,
        description: form.description.trim() || null,
        is_cde_scope: form.is_cde_scope,
      }
      const created = await api.createAsset(payload)
      setNotice(`Asset “${created.name}” created.`)
      setForm({
        name: '',
        asset_type: 'domain',
        criticality: 'medium',
        ip_address: '',
        domain: '',
        cloud_resource_id: '',
        url: '',
        environment: 'production',
        owner: '',
        description: '',
        is_cde_scope: false,
      })
      await load()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to create asset')
    } finally {
      setBusy(false)
    }
  }

  function targetLabel(a: Asset): string {
    if (a.asset_type === 'ip') return a.ip_address ?? '—'
    if (a.asset_type === 'domain') return a.domain ?? a.url ?? '—'
    return a.cloud_resource_id ?? '—'
  }

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Assets</h1>
          <p className="mt-1 text-sm text-surface-400">
            Authorized VA/PT scope · {total} asset{total === 1 ? '' : 's'}
          </p>
        </div>
        {user?.role === 'super_admin' && orgs.length > 0 ? (
          <label className="flex flex-col gap-1 text-xs text-surface-400">
            Organization scope
            <select
              value={selectedOrg}
              onChange={(e) => onOrgChange(e.target.value)}
              className="rounded-lg border border-surface-600 bg-surface-900 px-3 py-2 text-sm text-surface-100 outline-none focus:border-accent"
            >
              {orgs.map((o) => (
                <option key={o.id} value={o.id}>
                  {o.name}
                </option>
              ))}
            </select>
          </label>
        ) : null}
      </header>

      {error ? (
        <div className="rounded-lg border border-danger/30 bg-danger/10 px-4 py-2 text-xs text-danger">
          {error}
        </div>
      ) : null}
      {notice ? (
        <div className="rounded-lg border border-accent/30 bg-accent/10 px-4 py-2 text-xs text-accent">
          {notice}
        </div>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-3">
        {canWrite ? (
          <form
            onSubmit={onCreate}
            className="panel space-y-3 rounded-xl p-5 lg:col-span-1"
          >
            <h2 className="flex items-center gap-2 text-sm font-medium">
              <Plus className="h-4 w-4 text-accent" />
              Register asset
            </h2>
            <input
              required
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              placeholder="Display name"
              className="w-full rounded-lg border border-surface-600 bg-surface-900 px-3 py-2 text-sm outline-none focus:border-accent"
            />
            <div className="grid grid-cols-2 gap-2">
              <select
                value={form.asset_type}
                onChange={(e) =>
                  setForm({ ...form, asset_type: e.target.value as AssetType })
                }
                className="rounded-lg border border-surface-600 bg-surface-900 px-3 py-2 text-sm outline-none focus:border-accent"
              >
                {ASSET_TYPES.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
              <select
                value={form.criticality}
                onChange={(e) =>
                  setForm({
                    ...form,
                    criticality: e.target.value as AssetCriticality,
                  })
                }
                className="rounded-lg border border-surface-600 bg-surface-900 px-3 py-2 text-sm outline-none focus:border-accent"
              >
                {CRITICALITIES.map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
              </select>
            </div>
            {form.asset_type === 'ip' ? (
              <input
                required
                value={form.ip_address}
                onChange={(e) => setForm({ ...form, ip_address: e.target.value })}
                placeholder="IP address"
                className="w-full rounded-lg border border-surface-600 bg-surface-900 px-3 py-2 text-sm outline-none focus:border-accent"
              />
            ) : null}
            {form.asset_type === 'domain' ? (
              <>
                <input
                  required
                  value={form.domain}
                  onChange={(e) => setForm({ ...form, domain: e.target.value })}
                  placeholder="domain.example.com"
                  className="w-full rounded-lg border border-surface-600 bg-surface-900 px-3 py-2 text-sm outline-none focus:border-accent"
                />
                <input
                  value={form.url}
                  onChange={(e) => setForm({ ...form, url: e.target.value })}
                  placeholder="https://… (optional)"
                  className="w-full rounded-lg border border-surface-600 bg-surface-900 px-3 py-2 text-sm outline-none focus:border-accent"
                />
              </>
            ) : null}
            {form.asset_type === 'cloud_resource' ? (
              <input
                required
                value={form.cloud_resource_id}
                onChange={(e) =>
                  setForm({ ...form, cloud_resource_id: e.target.value })
                }
                placeholder="Cloud resource ID"
                className="w-full rounded-lg border border-surface-600 bg-surface-900 px-3 py-2 text-sm outline-none focus:border-accent"
              />
            ) : null}
            <input
              value={form.environment}
              onChange={(e) => setForm({ ...form, environment: e.target.value })}
              placeholder="Environment"
              className="w-full rounded-lg border border-surface-600 bg-surface-900 px-3 py-2 text-sm outline-none focus:border-accent"
            />
            <input
              value={form.owner}
              onChange={(e) => setForm({ ...form, owner: e.target.value })}
              placeholder="Owner"
              className="w-full rounded-lg border border-surface-600 bg-surface-900 px-3 py-2 text-sm outline-none focus:border-accent"
            />
            <label className="flex items-center gap-2 text-xs text-surface-300">
              <input
                type="checkbox"
                checked={form.is_cde_scope}
                onChange={(e) =>
                  setForm({ ...form, is_cde_scope: e.target.checked })
                }
              />
              PCI-DSS CDE scope
            </label>
            <button
              type="submit"
              disabled={busy || !form.name.trim()}
              className="w-full rounded-lg bg-accent px-3 py-2 text-sm font-semibold text-surface-950 transition hover:bg-accent-dim disabled:opacity-50"
            >
              {busy ? 'Saving…' : 'Create asset'}
            </button>
            {!isAdmin && user?.role === 'soc_analyst' ? (
              <p className="text-[11px] text-surface-400">
                SOC analysts can view assets but cannot create them.
              </p>
            ) : null}
          </form>
        ) : (
          <div className="panel rounded-xl p-5 text-sm text-surface-400 lg:col-span-1">
            <Server className="mb-2 h-5 w-5 text-accent" />
            View-only for SOC Analyst. Ask Admin/Pentester to register scope.
          </div>
        )}

        <div className="space-y-3 lg:col-span-2">
          <div className="relative">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-surface-400" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search name, domain, hostname…"
              className="w-full rounded-lg border border-surface-600 bg-surface-900 py-2 pl-10 pr-3 text-sm outline-none focus:border-accent"
            />
          </div>

          {loading ? (
            <p className="py-12 text-center text-sm text-surface-400">Loading assets…</p>
          ) : items.length === 0 ? (
            <p className="panel rounded-xl py-12 text-center text-sm text-surface-400">
              No assets yet. Register a target to start VA/PT.
            </p>
          ) : (
            <ul className="space-y-2">
              {items.map((a) => (
                <li
                  key={a.id}
                  className="panel flex flex-wrap items-center justify-between gap-3 rounded-xl px-4 py-3"
                >
                  <div className="min-w-0">
                    <div className="truncate font-medium text-surface-100">{a.name}</div>
                    <div className="mt-0.5 font-mono text-[11px] text-surface-400">
                      {a.asset_type} · {targetLabel(a)}
                      {a.environment ? ` · ${a.environment}` : ''}
                      {a.is_cde_scope ? ' · CDE' : ''}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="rounded-md bg-surface-800 px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider text-surface-300">
                      {a.criticality}
                    </span>
                    <Link
                      to={`/vulnerabilities?asset_id=${a.id}`}
                      className="text-xs text-accent hover:underline"
                    >
                      Findings
                    </Link>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  )
}
