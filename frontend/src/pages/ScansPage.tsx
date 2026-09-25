import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { Link } from 'react-router-dom'
import { CalendarClock, Play, Plus, Radar, RefreshCw, Trash2 } from 'lucide-react'
import {
  api,
  ApiError,
  getOrganizationId,
  setOrganizationId,
} from '../api/client'
import type {
  Asset,
  Organization,
  Scan,
  ScanSchedule,
  ScannerEngine,
  ScanStatus,
  ScanType,
} from '../api/types'
import { useAuth } from '../auth/AuthContext'
import { ScanExtras } from '../components/ScanExtras'
import { useLocale } from '../i18n/locale'

const ENGINES: { id: ScannerEngine; ready: boolean; label: string; blurb: string }[] = [
  {
    id: 'nmap',
    ready: true,
    label: 'Nmap',
    blurb: 'Discovery · port / service fingerprint',
  },
  {
    id: 'nuclei',
    ready: true,
    label: 'Nuclei',
    blurb: 'VA · template-driven checks',
  },
  {
    id: 'nexusec',
    ready: true,
    label: 'NexuSec',
    blurb: 'VA · custom async scanner',
  },
  {
    id: 'openvas',
    ready: true,
    label: 'OpenVAS',
    blurb: 'VA · Greenbone GVM (mock / XML)',
  },
  { id: 'other', ready: false, label: 'Other', blurb: 'Coming soon' },
]

const SCAN_TYPES: ScanType[] = ['discovery', 'va', 'pt', 'compliance', 'custom']
const INTERVALS = [
  { minutes: 60, key: 'scans.intervalHourly' as const },
  { minutes: 360, key: 'scans.interval6h' as const },
  { minutes: 1440, key: 'scans.intervalDaily' as const },
  { minutes: 10080, key: 'scans.intervalWeekly' as const },
]

function statusClass(s: ScanStatus): string {
  switch (s) {
    case 'completed':
      return 'bg-ok/15 text-ok'
    case 'failed':
      return 'bg-danger/15 text-danger'
    case 'running':
    case 'queued':
      return 'bg-accent/15 text-accent'
    case 'cancelled':
      return 'bg-surface-700 text-surface-400'
    default:
      return 'bg-warn/15 text-warn'
  }
}

function intervalLabel(
  minutes: number,
  t: (key: (typeof INTERVALS)[number]['key']) => string,
): string {
  const hit = INTERVALS.find((i) => i.minutes === minutes)
  return hit ? t(hit.key) : `${minutes}m`
}

export function ScansPage() {
  const { usingMock, token, user } = useAuth()
  const { t } = useLocale()
  const canWrite =
    user?.role === 'super_admin' ||
    user?.role === 'admin' ||
    user?.role === 'pentester'

  const [items, setItems] = useState<Scan[]>([])
  const [schedules, setSchedules] = useState<ScanSchedule[]>([])
  const [assets, setAssets] = useState<Asset[]>([])
  const [total, setTotal] = useState(0)
  const [scheduleTotal, setScheduleTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [orgs, setOrgs] = useState<Organization[]>([])
  const [selectedOrg, setSelectedOrg] = useState(() => getOrganizationId() ?? '')

  const [form, setForm] = useState({
    name: '',
    scan_type: 'discovery' as ScanType,
    engine: 'nmap' as ScannerEngine,
    asset_id: '',
    start_immediately: true,
    config: {} as Record<string, unknown>,
  })

  const [scheduleForm, setScheduleForm] = useState({
    name: '',
    scan_type: 'discovery' as ScanType,
    engine: 'nmap' as ScannerEngine,
    asset_id: '',
    interval_minutes: 1440,
    enabled: true,
    run_immediately: false,
    config: {} as Record<string, unknown>,
  })

  type PresetId = 'discovery_nmap' | 'va_nuclei' | 'va_nexusec' | 'va_openvas'

  function applyPreset(preset: PresetId) {
    if (preset === 'discovery_nmap') {
      setForm((f) => ({
        ...f,
        name: f.name || t('scans.presetDiscoveryName'),
        scan_type: 'discovery',
        engine: 'nmap',
        config: {},
      }))
      return
    }
    if (preset === 'va_nuclei') {
      setForm((f) => ({
        ...f,
        name: f.name || t('scans.presetNucleiName'),
        scan_type: 'va',
        engine: 'nuclei',
        config: {
          severity: ['critical', 'high', 'medium'],
          tags: ['cve', 'misconfig', 'vuln'],
          exclude_tags: ['dos'],
        },
      }))
      return
    }
    if (preset === 'va_openvas') {
      setForm((f) => ({
        ...f,
        name: f.name || t('scans.presetOpenvasName'),
        scan_type: 'va',
        engine: 'openvas',
        config: { openvas_mode: 'mock' },
      }))
      return
    }
    setForm((f) => ({
      ...f,
      name: f.name || t('scans.presetNexusecName'),
      scan_type: 'va',
      engine: 'nexusec',
      config: {},
    }))
  }

  function applySchedulePreset(preset: PresetId) {
    if (preset === 'discovery_nmap') {
      setScheduleForm((f) => ({
        ...f,
        name: f.name || t('scans.presetDiscoveryName'),
        scan_type: 'discovery',
        engine: 'nmap',
        config: {},
      }))
      return
    }
    if (preset === 'va_nuclei') {
      setScheduleForm((f) => ({
        ...f,
        name: f.name || t('scans.presetNucleiName'),
        scan_type: 'va',
        engine: 'nuclei',
        config: {
          severity: ['critical', 'high', 'medium'],
          tags: ['cve', 'misconfig', 'vuln'],
          exclude_tags: ['dos'],
        },
      }))
      return
    }
    if (preset === 'va_openvas') {
      setScheduleForm((f) => ({
        ...f,
        name: f.name || t('scans.presetOpenvasName'),
        scan_type: 'va',
        engine: 'openvas',
        config: { openvas_mode: 'mock' },
      }))
      return
    }
    setScheduleForm((f) => ({
      ...f,
      name: f.name || t('scans.presetNexusecName'),
      scan_type: 'va',
      engine: 'nexusec',
      config: {},
    }))
  }

  const load = useCallback(async (opts?: { silent?: boolean }) => {
    if (usingMock || token === 'demo') {
      setLoading(false)
      setError(t('scans.liveRequired'))
      return
    }
    if (!opts?.silent) {
      setLoading(true)
      setError(null)
    }
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
      const [scanRes, assetRes, scheduleRes] = await Promise.all([
        api.listScans({ page: 1, page_size: 50 }),
        api.listAssets({ page: 1, page_size: 100 }),
        api.listScanSchedules({ page: 1, page_size: 50 }),
      ])
      setItems(scanRes.items)
      setTotal(scanRes.total)
      setSchedules(scheduleRes.items)
      setScheduleTotal(scheduleRes.total)
      setAssets(assetRes.items)
      setForm((f) =>
        f.asset_id || !assetRes.items[0]
          ? f
          : { ...f, asset_id: assetRes.items[0].id },
      )
      setScheduleForm((f) =>
        f.asset_id || !assetRes.items[0]
          ? f
          : { ...f, asset_id: assetRes.items[0].id },
      )
    } catch (err) {
      if (!opts?.silent) {
        setError(err instanceof ApiError ? err.message : t('scans.loadFailed'))
        setItems([])
        setTotal(0)
        setSchedules([])
        setScheduleTotal(0)
      }
    } finally {
      if (!opts?.silent) setLoading(false)
    }
  }, [token, user?.role, usingMock, t])

  useEffect(() => {
    void load()
  }, [load])

  const hasActiveScans = items.some(
    (s) =>
      s.status === 'queued' ||
      s.status === 'running' ||
      s.status === 'pending',
  )

  useEffect(() => {
    if (!hasActiveScans || usingMock || token === 'demo') return
    const id = window.setInterval(() => {
      void load({ silent: true })
    }, 5000)
    return () => window.clearInterval(id)
  }, [hasActiveScans, load, token, usingMock])

  function onOrgChange(orgId: string) {
    setSelectedOrg(orgId)
    setOrganizationId(orgId || null)
    setForm((f) => ({ ...f, asset_id: '' }))
    setScheduleForm((f) => ({ ...f, asset_id: '' }))
    void load()
  }

  async function onCreate(e: FormEvent) {
    e.preventDefault()
    if (!canWrite || !form.asset_id) return
    setBusy(true)
    setNotice(null)
    setError(null)
    try {
      if (user?.role === 'super_admin' && selectedOrg) {
        setOrganizationId(selectedOrg)
      }
      const res = await api.createScan({
        name: form.name.trim(),
        scan_type: form.scan_type,
        engine: form.engine,
        asset_ids: [form.asset_id],
        config: form.config,
        start_immediately: form.start_immediately,
      })
      setNotice(res.message)
      setForm((f) => ({ ...f, name: '', config: {} }))
      await load()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t('scans.createFailed'))
    } finally {
      setBusy(false)
    }
  }

  async function onCreateSchedule(e: FormEvent) {
    e.preventDefault()
    if (!canWrite || !scheduleForm.asset_id) return
    setBusy(true)
    setNotice(null)
    setError(null)
    try {
      if (user?.role === 'super_admin' && selectedOrg) {
        setOrganizationId(selectedOrg)
      }
      const created = await api.createScanSchedule({
        name: scheduleForm.name.trim(),
        scan_type: scheduleForm.scan_type,
        engine: scheduleForm.engine,
        asset_ids: [scheduleForm.asset_id],
        config: scheduleForm.config,
        interval_minutes: scheduleForm.interval_minutes,
        enabled: scheduleForm.enabled,
        run_immediately: scheduleForm.run_immediately,
      })
      setNotice(t('scans.scheduleCreated', { name: created.name }))
      setScheduleForm((f) => ({
        ...f,
        name: '',
        config: {},
        run_immediately: false,
      }))
      await load()
    } catch (err) {
      setError(
        err instanceof ApiError ? err.message : t('scans.scheduleFailed'),
      )
    } finally {
      setBusy(false)
    }
  }

  async function onToggleSchedule(schedule: ScanSchedule) {
    setBusy(true)
    setNotice(null)
    setError(null)
    try {
      await api.updateScanSchedule(schedule.id, { enabled: !schedule.enabled })
      setNotice(t('scans.scheduleUpdated'))
      await load()
    } catch (err) {
      setError(
        err instanceof ApiError ? err.message : t('scans.scheduleToggleFailed'),
      )
    } finally {
      setBusy(false)
    }
  }

  async function onDeleteSchedule(id: string) {
    setBusy(true)
    setNotice(null)
    setError(null)
    try {
      await api.deleteScanSchedule(id)
      setNotice(t('scans.scheduleDeleted'))
      await load()
    } catch (err) {
      setError(
        err instanceof ApiError ? err.message : t('scans.scheduleDeleteFailed'),
      )
    } finally {
      setBusy(false)
    }
  }

  async function onStart(id: string) {
    setBusy(true)
    setNotice(null)
    setError(null)
    try {
      const res = await api.startScan(id)
      setNotice(res.message)
      await load()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t('scans.startFailed'))
    } finally {
      setBusy(false)
    }
  }

  function assetName(id: string): string {
    return assets.find((a) => a.id === id)?.name ?? id.slice(0, 8)
  }

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">{t('scans.title')}</h1>
          <p className="mt-1 text-sm text-surface-400">
            {t('scans.subtitle', { count: total })}
          </p>
        </div>
        <div className="flex flex-wrap items-end gap-3">
          {user?.role === 'super_admin' && orgs.length > 0 ? (
            <label className="flex flex-col gap-1 text-xs text-surface-400">
              {t('common.orgScope')}
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
          <button
            type="button"
            onClick={() => void load()}
            className="inline-flex items-center gap-2 rounded-lg border border-surface-600 px-3 py-2 text-sm text-surface-200 hover:border-accent hover:text-accent"
          >
            <RefreshCw className="h-4 w-4" />
            {t('common.refresh')}
          </button>
        </div>
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

      <section className="space-y-2">
        <h2 className="text-sm font-medium text-surface-200">
          {t('scans.connectorsTitle')}
        </h2>
        <p className="text-xs text-surface-400">{t('scans.connectorsSubtitle')}</p>
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
          {ENGINES.filter((e) => e.id !== 'other').map((eng) => {
            const selected = form.engine === eng.id
            return (
              <button
                key={eng.id}
                type="button"
                disabled={!eng.ready || !canWrite}
                onClick={() => {
                  if (!eng.ready) return
                  if (eng.id === 'openvas') applyPreset('va_openvas')
                  else if (eng.id === 'nuclei') applyPreset('va_nuclei')
                  else if (eng.id === 'nexusec') applyPreset('va_nexusec')
                  else applyPreset('discovery_nmap')
                }}
                className={`rounded-xl border px-4 py-3 text-left transition ${
                  selected
                    ? 'border-accent bg-accent/10'
                    : 'border-surface-600 bg-surface-900/60 hover:border-accent/60'
                } disabled:cursor-not-allowed disabled:opacity-50`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm font-semibold text-surface-100">
                    {eng.label}
                  </span>
                  <span
                    className={`rounded-md px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-wider ${
                      eng.ready
                        ? 'bg-ok/15 text-ok'
                        : 'bg-surface-700 text-surface-400'
                    }`}
                  >
                    {eng.ready ? t('scans.connectorReady') : t('scans.connectorSoon')}
                  </span>
                </div>
                <p className="mt-1 text-[11px] text-surface-400">{eng.blurb}</p>
              </button>
            )
          })}
        </div>
      </section>

      <div className="grid gap-4 lg:grid-cols-3">
        {canWrite ? (
          <form
            onSubmit={onCreate}
            className="panel space-y-3 rounded-xl p-5 lg:col-span-1"
          >
            <h2 className="flex items-center gap-2 text-sm font-medium">
              <Plus className="h-4 w-4 text-accent" />
              {t('scans.newScan')}
            </h2>
            <div className="flex flex-wrap gap-1.5">
              <button
                type="button"
                onClick={() => applyPreset('discovery_nmap')}
                className="rounded-md border border-surface-600 px-2 py-1 text-[11px] text-surface-300 hover:border-accent hover:text-accent"
              >
                {t('scans.presetDiscovery')}
              </button>
              <button
                type="button"
                onClick={() => applyPreset('va_nuclei')}
                className="rounded-md border border-surface-600 px-2 py-1 text-[11px] text-surface-300 hover:border-accent hover:text-accent"
              >
                {t('scans.presetNuclei')}
              </button>
              <button
                type="button"
                onClick={() => applyPreset('va_nexusec')}
                className="rounded-md border border-surface-600 px-2 py-1 text-[11px] text-surface-300 hover:border-accent hover:text-accent"
              >
                {t('scans.presetNexusec')}
              </button>
              <button
                type="button"
                onClick={() => applyPreset('va_openvas')}
                className="rounded-md border border-surface-600 px-2 py-1 text-[11px] text-surface-300 hover:border-accent hover:text-accent"
              >
                {t('scans.presetOpenvas')}
              </button>
            </div>
            {hasActiveScans ? (
              <p className="font-mono text-[10px] text-accent">
                {t('scans.autoRefreshing')}
              </p>
            ) : null}
            <input
              required
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              placeholder={t('scans.scanName')}
              className="w-full rounded-lg border border-surface-600 bg-surface-900 px-3 py-2 text-sm outline-none focus:border-accent"
            />
            <select
              value={form.asset_id}
              onChange={(e) => setForm({ ...form, asset_id: e.target.value })}
              required
              className="w-full rounded-lg border border-surface-600 bg-surface-900 px-3 py-2 text-sm outline-none focus:border-accent"
            >
              <option value="">{t('scans.selectAsset')}</option>
              {assets.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name} ({a.asset_type})
                </option>
              ))}
            </select>
            {assets.length === 0 ? (
              <p className="text-[11px] text-surface-400">
                {t('scans.noAssets')}{' '}
                <Link to="/assets" className="text-accent hover:underline">
                  {t('scans.registerFirst')}
                </Link>
                .
              </p>
            ) : null}
            <div className="grid grid-cols-2 gap-2">
              <select
                value={form.engine}
                onChange={(e) =>
                  setForm({ ...form, engine: e.target.value as ScannerEngine })
                }
                className="rounded-lg border border-surface-600 bg-surface-900 px-3 py-2 text-sm outline-none focus:border-accent"
              >
                {ENGINES.map((eng) => (
                  <option key={eng.id} value={eng.id} disabled={!eng.ready}>
                    {eng.ready ? eng.id : `${eng.id} (soon)`}
                  </option>
                ))}
              </select>
              <select
                value={form.scan_type}
                onChange={(e) =>
                  setForm({ ...form, scan_type: e.target.value as ScanType })
                }
                className="rounded-lg border border-surface-600 bg-surface-900 px-3 py-2 text-sm outline-none focus:border-accent"
              >
                {SCAN_TYPES.map((st) => (
                  <option key={st} value={st}>
                    {st}
                  </option>
                ))}
              </select>
            </div>
            <label className="flex items-center gap-2 text-xs text-surface-300">
              <input
                type="checkbox"
                checked={form.start_immediately}
                onChange={(e) =>
                  setForm({ ...form, start_immediately: e.target.checked })
                }
              />
              {t('scans.startImmediately')}
            </label>
            <button
              type="submit"
              disabled={busy || !form.name.trim() || !form.asset_id}
              className="w-full rounded-lg bg-accent px-3 py-2 text-sm font-semibold text-surface-950 transition hover:bg-accent-dim disabled:opacity-50"
            >
              {busy ? t('scans.queuing') : t('scans.create')}
            </button>
          </form>
        ) : (
          <div className="panel rounded-xl p-5 text-sm text-surface-400 lg:col-span-1">
            <Radar className="mb-2 h-5 w-5 text-accent" />
            {t('scans.viewOnlyHint')}
          </div>
        )}

        <div className="space-y-2 lg:col-span-2">
          {loading ? (
            <p className="py-12 text-center text-sm text-surface-400">{t('scans.loading')}</p>
          ) : items.length === 0 ? (
            <p className="panel rounded-xl py-12 text-center text-sm text-surface-400">
              {t('scans.empty')}
            </p>
          ) : (
            <ul className="space-y-2">
              {items.map((s) => (
                <li
                  key={s.id}
                  className="panel space-y-2 rounded-xl px-4 py-3"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="min-w-0">
                      <div className="truncate font-medium text-surface-100">
                        {s.name}
                      </div>
                      <div className="mt-0.5 font-mono text-[11px] text-surface-400">
                        {s.engine} · {s.scan_type}
                        {s.asset_ids[0]
                          ? ` · ${assetName(s.asset_ids[0])}`
                          : ''}
                        {s.progress != null
                          ? ` · ${Math.round(s.progress)}%`
                          : ''}
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <span
                        className={`rounded-md px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider ${statusClass(s.status)}`}
                      >
                        {s.status}
                      </span>
                      <Link
                        to={`/vulnerabilities?scan_id=${s.id}`}
                        className="text-xs text-accent hover:underline"
                      >
                        {t('common.findings')}
                      </Link>
                      {canWrite &&
                      (s.status === 'pending' || s.status === 'failed') ? (
                        <button
                          type="button"
                          disabled={busy}
                          onClick={() => void onStart(s.id)}
                          className="inline-flex items-center gap-1 rounded-md border border-surface-600 px-2 py-1 text-xs text-surface-200 hover:border-accent hover:text-accent disabled:opacity-50"
                        >
                          <Play className="h-3 w-3" />
                          {t('scans.start')}
                        </button>
                      ) : null}
                    </div>
                  </div>
                  {s.error_message ? (
                    <p className="font-mono text-[11px] text-danger">
                      {s.error_message}
                    </p>
                  ) : null}
                  <div className="font-mono text-[10px] text-surface-500">
                    {new Date(s.created_at).toLocaleString()}
                    {s.completed_at
                      ? ` → ${new Date(s.completed_at).toLocaleString()}`
                      : ''}
                  </div>
                  <ScanExtras
                    scanId={s.id}
                    engine={s.engine}
                    status={s.status}
                    canWrite={canWrite}
                    busy={busy}
                    onNotice={setNotice}
                    onError={setError}
                    onAssetsChanged={() => void load()}
                  />
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>

      <section className="space-y-4">
        <div>
          <h2 className="flex items-center gap-2 text-lg font-semibold tracking-tight">
            <CalendarClock className="h-5 w-5 text-accent" />
            {t('scans.schedulesTitle')}
          </h2>
          <p className="mt-1 text-sm text-surface-400">
            {t('scans.schedulesSubtitle', { count: scheduleTotal })}
          </p>
        </div>

        <div className="grid gap-4 lg:grid-cols-3">
          {canWrite ? (
            <form
              onSubmit={onCreateSchedule}
              className="panel space-y-3 rounded-xl p-5 lg:col-span-1"
            >
              <h3 className="text-sm font-medium">{t('scans.newSchedule')}</h3>
              <div className="flex flex-wrap gap-1.5">
                <button
                  type="button"
                  onClick={() => applySchedulePreset('discovery_nmap')}
                  className="rounded-md border border-surface-600 px-2 py-1 text-[11px] text-surface-300 hover:border-accent hover:text-accent"
                >
                  {t('scans.presetDiscovery')}
                </button>
                <button
                  type="button"
                  onClick={() => applySchedulePreset('va_nuclei')}
                  className="rounded-md border border-surface-600 px-2 py-1 text-[11px] text-surface-300 hover:border-accent hover:text-accent"
                >
                  {t('scans.presetNuclei')}
                </button>
                <button
                  type="button"
                  onClick={() => applySchedulePreset('va_nexusec')}
                  className="rounded-md border border-surface-600 px-2 py-1 text-[11px] text-surface-300 hover:border-accent hover:text-accent"
                >
                  {t('scans.presetNexusec')}
                </button>
                <button
                  type="button"
                  onClick={() => applySchedulePreset('va_openvas')}
                  className="rounded-md border border-surface-600 px-2 py-1 text-[11px] text-surface-300 hover:border-accent hover:text-accent"
                >
                  {t('scans.presetOpenvas')}
                </button>
              </div>
              <input
                required
                value={scheduleForm.name}
                onChange={(e) =>
                  setScheduleForm({ ...scheduleForm, name: e.target.value })
                }
                placeholder={t('scans.scanName')}
                className="w-full rounded-lg border border-surface-600 bg-surface-900 px-3 py-2 text-sm outline-none focus:border-accent"
              />
              <select
                value={scheduleForm.asset_id}
                onChange={(e) =>
                  setScheduleForm({ ...scheduleForm, asset_id: e.target.value })
                }
                required
                className="w-full rounded-lg border border-surface-600 bg-surface-900 px-3 py-2 text-sm outline-none focus:border-accent"
              >
                <option value="">{t('scans.selectAsset')}</option>
                {assets.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.name} ({a.asset_type})
                  </option>
                ))}
              </select>
              <div className="grid grid-cols-2 gap-2">
                <select
                  value={scheduleForm.engine}
                  onChange={(e) =>
                    setScheduleForm({
                      ...scheduleForm,
                      engine: e.target.value as ScannerEngine,
                    })
                  }
                  className="rounded-lg border border-surface-600 bg-surface-900 px-3 py-2 text-sm outline-none focus:border-accent"
                >
                  {ENGINES.filter((e) => e.ready).map((eng) => (
                    <option key={eng.id} value={eng.id}>
                      {eng.id}
                    </option>
                  ))}
                </select>
                <select
                  value={scheduleForm.interval_minutes}
                  onChange={(e) =>
                    setScheduleForm({
                      ...scheduleForm,
                      interval_minutes: Number(e.target.value),
                    })
                  }
                  className="rounded-lg border border-surface-600 bg-surface-900 px-3 py-2 text-sm outline-none focus:border-accent"
                >
                  {INTERVALS.map((iv) => (
                    <option key={iv.minutes} value={iv.minutes}>
                      {t(iv.key)}
                    </option>
                  ))}
                </select>
              </div>
              <label className="flex items-center gap-2 text-xs text-surface-300">
                <input
                  type="checkbox"
                  checked={scheduleForm.enabled}
                  onChange={(e) =>
                    setScheduleForm({
                      ...scheduleForm,
                      enabled: e.target.checked,
                    })
                  }
                />
                {t('scans.enabled')}
              </label>
              <label className="flex items-center gap-2 text-xs text-surface-300">
                <input
                  type="checkbox"
                  checked={scheduleForm.run_immediately}
                  onChange={(e) =>
                    setScheduleForm({
                      ...scheduleForm,
                      run_immediately: e.target.checked,
                    })
                  }
                />
                {t('scans.runImmediately')}
              </label>
              <button
                type="submit"
                disabled={
                  busy || !scheduleForm.name.trim() || !scheduleForm.asset_id
                }
                className="w-full rounded-lg border border-accent/50 bg-accent/15 px-3 py-2 text-sm font-semibold text-accent transition hover:bg-accent/25 disabled:opacity-50"
              >
                {t('scans.createSchedule')}
              </button>
            </form>
          ) : (
            <div className="panel rounded-xl p-5 text-sm text-surface-400 lg:col-span-1">
              {t('scans.viewOnlyHint')}
            </div>
          )}

          <div className="space-y-2 lg:col-span-2">
            {schedules.length === 0 ? (
              <p className="panel rounded-xl py-10 text-center text-sm text-surface-400">
                {t('scans.noSchedules')}
              </p>
            ) : (
              <ul className="space-y-2">
                {schedules.map((s) => (
                  <li
                    key={s.id}
                    className="panel space-y-2 rounded-xl px-4 py-3"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="min-w-0">
                        <div className="truncate font-medium text-surface-100">
                          {s.name}
                        </div>
                        <div className="mt-0.5 font-mono text-[11px] text-surface-400">
                          {s.engine} · {intervalLabel(s.interval_minutes, t)}
                          {s.asset_ids[0]
                            ? ` · ${assetName(s.asset_ids[0])}`
                            : ''}
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <span
                          className={`rounded-md px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider ${
                            s.enabled
                              ? 'bg-ok/15 text-ok'
                              : 'bg-surface-700 text-surface-400'
                          }`}
                        >
                          {s.enabled ? t('scans.enabled') : t('scans.pause')}
                        </span>
                        {canWrite ? (
                          <>
                            <button
                              type="button"
                              disabled={busy}
                              onClick={() => void onToggleSchedule(s)}
                              className="rounded-md border border-surface-600 px-2 py-1 text-xs text-surface-200 hover:border-accent hover:text-accent disabled:opacity-50"
                            >
                              {s.enabled
                                ? t('scans.pause')
                                : t('scans.resume')}
                            </button>
                            <button
                              type="button"
                              disabled={busy}
                              onClick={() => void onDeleteSchedule(s.id)}
                              className="inline-flex items-center gap-1 rounded-md border border-danger/40 px-2 py-1 text-xs text-danger hover:bg-danger/10 disabled:opacity-50"
                            >
                              <Trash2 className="h-3 w-3" />
                              {t('scans.delete')}
                            </button>
                          </>
                        ) : null}
                      </div>
                    </div>
                    <div className="font-mono text-[10px] text-surface-500">
                      {t('scans.nextRun')}:{' '}
                      {new Date(s.next_run_at).toLocaleString()}
                      {s.last_run_at
                        ? ` · ${t('scans.lastRun')}: ${new Date(s.last_run_at).toLocaleString()}`
                        : ''}
                      {s.last_scan_id ? (
                        <>
                          {' · '}
                          <Link
                            to={`/vulnerabilities?scan_id=${s.last_scan_id}`}
                            className="text-accent hover:underline"
                          >
                            {t('common.findings')}
                          </Link>
                        </>
                      ) : null}
                    </div>
                    {s.last_error ? (
                      <p className="font-mono text-[11px] text-danger">
                        {s.last_error}
                      </p>
                    ) : null}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      </section>
    </div>
  )
}
