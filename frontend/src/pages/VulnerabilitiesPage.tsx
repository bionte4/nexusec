import { useEffect, useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { Download, Filter, Search, X } from 'lucide-react'
import { api, ApiError } from '../api/client'
import type {
  FindingStatus,
  Severity,
  Vulnerability,
} from '../api/types'
import { useAuth } from '../auth/AuthContext'
import { useLocale } from '../i18n/locale'
import { SeverityBadge, StatusBadge } from '../components/Badges'
import { MOCK_VULNS } from '../data/mock'

const SEVERITIES: Severity[] = [
  'critical',
  'high',
  'medium',
  'low',
  'info',
  'unknown',
]
const STATUSES: FindingStatus[] = [
  'open',
  'in_progress',
  'false_positive',
  'resolved',
  'confirmed',
  'accepted_risk',
  'remediated',
  'reopened',
]
const COMPLIANCE_TAGS = ['PCI-DSS', 'ISO-27001', 'GDPR'] as const

function complianceKeys(v: Vulnerability): string[] {
  return Object.keys(v.compliance_metadata ?? {})
}

function csvEscape(value: string): string {
  if (/[",\n]/.test(value)) return `"${value.replaceAll('"', '""')}"`
  return value
}

function downloadText(filename: string, content: string, mime: string) {
  const blob = new Blob([content], { type: mime })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

export function VulnerabilitiesPage() {
  const { usingMock, setUsingMock, token } = useAuth()
  const { t } = useLocale()
  const [searchParams, setSearchParams] = useSearchParams()
  const filterAssetId = searchParams.get('asset_id') || ''
  const filterScanId = searchParams.get('scan_id') || ''
  const severityParam = (searchParams.get('severity') || '') as Severity | ''
  const statusParam = (searchParams.get('status') || '') as FindingStatus | ''
  const overdueParam =
    searchParams.get('overdue') === '1' || searchParams.get('overdue') === 'true'

  const [items, setItems] = useState<Vulnerability[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const [severity, setSeverity] = useState<Severity | ''>(
    severityParam && SEVERITIES.includes(severityParam) ? severityParam : '',
  )
  const [status, setStatus] = useState<FindingStatus | ''>(
    statusParam && STATUSES.includes(statusParam) ? statusParam : '',
  )
  const [assetQuery, setAssetQuery] = useState('')
  const [compliance, setCompliance] = useState<string>('')
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [bulkStatus, setBulkStatus] = useState<FindingStatus>('in_progress')
  const [bulkOwner, setBulkOwner] = useState('')

  useEffect(() => {
    if (severityParam && SEVERITIES.includes(severityParam)) {
      setSeverity(severityParam)
    } else if (!severityParam) {
      setSeverity('')
    }
  }, [severityParam])

  useEffect(() => {
    if (statusParam && STATUSES.includes(statusParam)) {
      setStatus(statusParam)
    } else if (!statusParam) {
      setStatus('')
    }
  }, [statusParam])
  useEffect(() => {
    let cancelled = false

    async function load() {
      setLoading(true)
      setError(null)

      if (usingMock || token === 'demo') {
        if (!cancelled) {
          setItems(MOCK_VULNS)
          setTotal(MOCK_VULNS.length)
          setUsingMock(true)
          setLoading(false)
        }
        return
      }

      try {
        const res = await api.listVulnerabilities({
          page: 1,
          page_size: 100,
          severity: severity || undefined,
          status: status || undefined,
          search: search || undefined,
          asset_id: filterAssetId || undefined,
          scan_id: filterScanId || undefined,
          overdue: overdueParam || undefined,
        })
        if (!cancelled) {
          setItems(res.items)
          setTotal(res.total)
          setUsingMock(false)
          setSelected(new Set())
        }
      } catch (err) {
        if (!cancelled) {
          setItems(MOCK_VULNS)
          setTotal(MOCK_VULNS.length)
          setUsingMock(true)
          setError(
            err instanceof ApiError
              ? t('vulns.apiUnavailable', { status: err.status })
              : t('dashboard.apiUnavailableGeneric'),
          )
        }
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    void load()
    return () => {
      cancelled = true
    }
  }, [
    severity,
    status,
    search,
    filterAssetId,
    filterScanId,
    overdueParam,
    usingMock,
    token,
    setUsingMock,
    t,
  ])

  const filtered = useMemo(() => {
    return items.filter((v) => {
      if (filterAssetId && v.asset_id !== filterAssetId) return false
      if (filterScanId && v.scan_id !== filterScanId) return false
      if (severity && v.severity !== severity) return false
      if (status && v.status !== status) return false
      if (
        assetQuery &&
        !v.asset_id.toLowerCase().includes(assetQuery.toLowerCase()) &&
        !(v.affected_component ?? '')
          .toLowerCase()
          .includes(assetQuery.toLowerCase())
      ) {
        return false
      }
      if (compliance && !complianceKeys(v).includes(compliance)) return false
      if (search) {
        const q = search.toLowerCase()
        const hay = [
          v.title,
          v.description ?? '',
          v.cve_id ?? '',
          v.cwe_id ?? '',
        ]
          .join(' ')
          .toLowerCase()
        if (!hay.includes(q)) return false
      }
      return true
    })
  }, [
    items,
    severity,
    status,
    assetQuery,
    compliance,
    search,
    filterAssetId,
    filterScanId,
  ])

  function clearScopeFilters() {
    const next = new URLSearchParams(searchParams)
    next.delete('asset_id')
    next.delete('scan_id')
    next.delete('severity')
    next.delete('status')
    setSearchParams(next, { replace: true })
    setSeverity('')
    setStatus('')
  }

  function onSeverityChange(next: Severity | '') {
    setSeverity(next)
    const params = new URLSearchParams(searchParams)
    if (next) params.set('severity', next)
    else params.delete('severity')
    setSearchParams(params, { replace: true })
  }

  function onStatusChange(next: FindingStatus | '') {
    setStatus(next)
    const params = new URLSearchParams(searchParams)
    if (next) params.set('status', next)
    else params.delete('status')
    setSearchParams(params, { replace: true })
  }
  function toggleOne(id: string) {
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  function toggleAll() {
    if (selected.size === filtered.length) {
      setSelected(new Set())
      return
    }
    setSelected(new Set(filtered.map((v) => v.id)))
  }

  async function applyBulkStatus() {
    if (selected.size === 0) return
    setBusy(true)
    setNotice(null)
    setError(null)
    try {
      if (usingMock || token === 'demo') {
        setItems((prev) =>
          prev.map((v) =>
            selected.has(v.id) ? { ...v, status: bulkStatus } : v,
          ),
        )
        setNotice(t('vulns.bulkUpdated', { count: selected.size }))
      } else {
        const ids = [...selected]
        await Promise.all(
          ids.map((id) => api.updateVulnerability(id, { status: bulkStatus })),
        )
        setItems((prev) =>
          prev.map((v) =>
            selected.has(v.id) ? { ...v, status: bulkStatus } : v,
          ),
        )
        setNotice(t('vulns.bulkUpdated', { count: ids.length }))
      }
      setSelected(new Set())
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t('vulns.bulkFailed'))
    } finally {
      setBusy(false)
    }
  }

  async function applyBulkOwner() {
    if (selected.size === 0 || !bulkOwner.trim()) return
    setBusy(true)
    setNotice(null)
    setError(null)
    const label = bulkOwner.trim()
    try {
      if (usingMock || token === 'demo') {
        setItems((prev) =>
          prev.map((v) =>
            selected.has(v.id)
              ? { ...v, remediation_owner_label: label }
              : v,
          ),
        )
        setNotice(t('vulns.bulkOwnerUpdated', { count: selected.size }))
      } else {
        const ids = [...selected]
        await Promise.all(ids.map((id) => api.assignOwner(id, label)))
        setItems((prev) =>
          prev.map((v) =>
            selected.has(v.id)
              ? { ...v, remediation_owner_label: label }
              : v,
          ),
        )
        setNotice(t('vulns.bulkOwnerUpdated', { count: ids.length }))
      }
      setSelected(new Set())
      setBulkOwner('')
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t('vulns.bulkFailed'))
    } finally {
      setBusy(false)
    }
  }

  function exportCsv() {
    const header = [
      'id',
      'title',
      'severity',
      'status',
      'cve_id',
      'cwe_id',
      'asset_id',
      'scan_id',
      'cvss_score',
      'owner',
      'source_tool',
      'compliance',
    ]
    const lines = [header.join(',')]
    for (const v of filtered) {
      lines.push(
        [
          v.id,
          csvEscape(v.title),
          v.severity,
          v.status,
          v.cve_id ?? '',
          v.cwe_id ?? '',
          v.asset_id,
          v.scan_id,
          v.cvss_score?.toFixed(1) ?? '',
          csvEscape(v.remediation_owner_label ?? ''),
          v.source_tool ?? '',
          csvEscape(complianceKeys(v).join('|')),
        ].join(','),
      )
    }
    downloadText(
      `nexusec-findings-${new Date().toISOString().slice(0, 10)}.csv`,
      lines.join('\n'),
      'text/csv;charset=utf-8',
    )
    setNotice(t('vulns.csvExported', { count: filtered.length }))
  }

  async function exportReport(
    kind: 'iso27001' | 'pci-dss' | 'gdpr' | 'nist-csf',
    format: 'json' | 'pdf' = 'json',
  ) {
    setBusy(true)
    setNotice(null)
    setError(null)
    try {
      if (usingMock || token === 'demo') {
        setError(t('vulns.reportLiveRequired'))
        return
      }
      if (format === 'pdf') {
        await api.downloadCompliancePdf(kind)
        setNotice(t('vulns.reportPdfExported', { kind }))
      } else {
        const report = await api.getComplianceReport(kind)
        downloadText(
          `nexusec-${kind}-${new Date().toISOString().slice(0, 10)}.json`,
          JSON.stringify(report, null, 2),
          'application/json',
        )
        setNotice(t('vulns.reportExported', { kind }))
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t('vulns.reportFailed'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-accent">
            {t('vulns.eyebrow')}
          </p>
          <h1 className="mt-1 text-2xl font-semibold tracking-tight">
            {t('vulns.title')}
          </h1>
          <p className="mt-1 text-sm text-surface-400">{t('vulns.subtitle')}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={exportCsv}
            disabled={filtered.length === 0}
            className="inline-flex items-center gap-1.5 rounded-lg border border-surface-600 px-3 py-2 text-xs text-surface-200 hover:border-accent hover:text-accent disabled:opacity-50"
          >
            <Download className="h-3.5 w-3.5" />
            {t('vulns.exportCsv')}
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() => void exportReport('iso27001')}
            className="rounded-lg border border-surface-600 px-3 py-2 text-xs text-surface-200 hover:border-accent hover:text-accent disabled:opacity-50"
          >
            ISO
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() => void exportReport('iso27001', 'pdf')}
            className="rounded-lg border border-surface-600 px-3 py-2 text-xs text-surface-200 hover:border-accent hover:text-accent disabled:opacity-50"
          >
            ISO PDF
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() => void exportReport('pci-dss')}
            className="rounded-lg border border-surface-600 px-3 py-2 text-xs text-surface-200 hover:border-accent hover:text-accent disabled:opacity-50"
          >
            PCI-DSS
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() => void exportReport('pci-dss', 'pdf')}
            className="rounded-lg border border-surface-600 px-3 py-2 text-xs text-surface-200 hover:border-accent hover:text-accent disabled:opacity-50"
          >
            PCI PDF
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() => void exportReport('gdpr')}
            className="rounded-lg border border-surface-600 px-3 py-2 text-xs text-surface-200 hover:border-accent hover:text-accent disabled:opacity-50"
          >
            GDPR
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() => void exportReport('gdpr', 'pdf')}
            className="rounded-lg border border-surface-600 px-3 py-2 text-xs text-surface-200 hover:border-accent hover:text-accent disabled:opacity-50"
          >
            GDPR PDF
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() => void exportReport('nist-csf')}
            className="rounded-lg border border-surface-600 px-3 py-2 text-xs text-surface-200 hover:border-accent hover:text-accent disabled:opacity-50"
          >
            NIST
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() => void exportReport('nist-csf', 'pdf')}
            className="rounded-lg border border-surface-600 px-3 py-2 text-xs text-surface-200 hover:border-accent hover:text-accent disabled:opacity-50"
          >
            NIST PDF
          </button>
        </div>
      </header>

      {filterAssetId || filterScanId || severityParam || statusParam ? (
        <div className="flex flex-wrap items-center gap-2 rounded-lg border border-accent/30 bg-accent/10 px-4 py-2 text-xs text-accent">
          <span>
            {filterScanId
              ? t('vulns.scopedScan', { id: filterScanId.slice(0, 8) })
              : filterAssetId
                ? t('vulns.scopedAsset', { id: filterAssetId.slice(0, 8) })
                : severityParam
                  ? t('vulns.scopedSeverity', { severity: severityParam })
                  : `${t('vulns.status')}: ${statusParam}`}
          </span>          <button
            type="button"
            onClick={clearScopeFilters}
            className="inline-flex items-center gap-1 rounded-md border border-accent/40 px-2 py-0.5 text-[11px] hover:bg-accent/20"
          >
            <X className="h-3 w-3" />
            {t('vulns.clearScope')}
          </button>
        </div>
      ) : null}

      {error ? (
        <div className="rounded-lg border border-warn/30 bg-warn/10 px-4 py-2 text-xs text-warn">
          {error}
        </div>
      ) : null}
      {notice ? (
        <div className="rounded-lg border border-accent/30 bg-accent/10 px-4 py-2 text-xs text-accent">
          {notice}
        </div>
      ) : null}

      <div className="panel rounded-xl p-4">
        <div className="mb-3 flex items-center gap-2 text-xs text-surface-400">
          <Filter className="h-3.5 w-3.5" />
          {t('vulns.filters')}
        </div>
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-5">
          <label className="space-y-1">
            <span className="font-mono text-[10px] uppercase tracking-wider text-surface-400">
              {t('vulns.severity')}
            </span>
            <select
              value={severity}
              onChange={(e) => onSeverityChange(e.target.value as Severity | '')}
              className="w-full rounded-lg border border-surface-600 bg-surface-900 px-3 py-2 text-sm outline-none focus:border-accent"
            >
              <option value="">{t('vulns.all')}</option>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </label>
          <label className="space-y-1">
            <span className="font-mono text-[10px] uppercase tracking-wider text-surface-400">
              {t('vulns.status')}
            </span>
            <select
              value={status}
              onChange={(e) =>
                onStatusChange(e.target.value as FindingStatus | '')
              }
              className="w-full rounded-lg border border-surface-600 bg-surface-900 px-3 py-2 text-sm outline-none focus:border-accent"
            >
              <option value="">{t('vulns.all')}</option>
              {STATUSES.map((s) => (
                <option key={s} value={s}>
                  {s.replaceAll('_', ' ')}
                </option>
              ))}
            </select>
          </label>
          <label className="space-y-1">
            <span className="font-mono text-[10px] uppercase tracking-wider text-surface-400">
              {t('vulns.assetComponent')}
            </span>
            <input
              value={assetQuery}
              onChange={(e) => setAssetQuery(e.target.value)}
              placeholder={t('vulns.assetPlaceholder')}
              className="w-full rounded-lg border border-surface-600 bg-surface-900 px-3 py-2 text-sm outline-none focus:border-accent"
            />
          </label>
          <label className="space-y-1">
            <span className="font-mono text-[10px] uppercase tracking-wider text-surface-400">
              {t('vulns.complianceTag')}
            </span>
            <select
              value={compliance}
              onChange={(e) => setCompliance(e.target.value)}
              className="w-full rounded-lg border border-surface-600 bg-surface-900 px-3 py-2 text-sm outline-none focus:border-accent"
            >
              <option value="">{t('vulns.all')}</option>
              {COMPLIANCE_TAGS.map((tag) => (
                <option key={tag} value={tag}>
                  {tag}
                </option>
              ))}
            </select>
          </label>
          <label className="space-y-1">
            <span className="font-mono text-[10px] uppercase tracking-wider text-surface-400">
              {t('vulns.search')}
            </span>
            <div className="relative">
              <Search className="pointer-events-none absolute top-2.5 left-3 h-4 w-4 text-surface-400" />
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder={t('vulns.searchPlaceholder')}
                className="w-full rounded-lg border border-surface-600 bg-surface-900 py-2 pr-3 pl-9 text-sm outline-none focus:border-accent"
              />
            </div>
          </label>
        </div>
      </div>

      {selected.size > 0 ? (
        <div className="panel flex flex-wrap items-end gap-3 rounded-xl p-4">
          <div className="text-xs text-surface-300">
            {t('vulns.selected', { count: selected.size })}
          </div>
          <label className="space-y-1">
            <span className="font-mono text-[10px] uppercase tracking-wider text-surface-400">
              {t('vulns.bulkStatus')}
            </span>
            <select
              value={bulkStatus}
              onChange={(e) => setBulkStatus(e.target.value as FindingStatus)}
              className="rounded-lg border border-surface-600 bg-surface-900 px-3 py-2 text-sm outline-none focus:border-accent"
            >
              {STATUSES.map((s) => (
                <option key={s} value={s}>
                  {s.replaceAll('_', ' ')}
                </option>
              ))}
            </select>
          </label>
          <button
            type="button"
            disabled={busy}
            onClick={() => void applyBulkStatus()}
            className="rounded-lg bg-accent px-3 py-2 text-xs font-semibold text-surface-950 disabled:opacity-50"
          >
            {t('vulns.applyStatus')}
          </button>
          <label className="space-y-1">
            <span className="font-mono text-[10px] uppercase tracking-wider text-surface-400">
              {t('vulns.bulkOwner')}
            </span>
            <input
              value={bulkOwner}
              onChange={(e) => setBulkOwner(e.target.value)}
              placeholder={t('vulns.ownerPlaceholder')}
              className="rounded-lg border border-surface-600 bg-surface-900 px-3 py-2 text-sm outline-none focus:border-accent"
            />
          </label>
          <button
            type="button"
            disabled={busy || !bulkOwner.trim()}
            onClick={() => void applyBulkOwner()}
            className="rounded-lg border border-surface-600 px-3 py-2 text-xs text-surface-200 hover:border-accent hover:text-accent disabled:opacity-50"
          >
            {t('vulns.applyOwner')}
          </button>
        </div>
      ) : null}

      <div className="panel overflow-hidden rounded-xl">
        <div className="flex items-center justify-between border-b border-surface-700 px-4 py-3">
          <span className="text-sm text-surface-300">
            {usingMock
              ? t('vulns.showing', { count: filtered.length })
              : t('vulns.showingOf', { count: filtered.length, total })}
          </span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[920px] text-left text-sm">
            <thead className="bg-surface-900/80 font-mono text-[10px] uppercase tracking-wider text-surface-400">
              <tr>
                <th className="px-4 py-3">
                  <input
                    type="checkbox"
                    checked={
                      filtered.length > 0 && selected.size === filtered.length
                    }
                    onChange={toggleAll}
                    aria-label={t('vulns.selectAll')}
                  />
                </th>
                <th className="px-4 py-3 font-medium">{t('vulns.colSeverity')}</th>
                <th className="px-4 py-3 font-medium">{t('vulns.colTitle')}</th>
                <th className="px-4 py-3 font-medium">{t('vulns.colStatus')}</th>
                <th className="px-4 py-3 font-medium">{t('vulns.colAsset')}</th>
                <th className="px-4 py-3 font-medium">
                  {t('vulns.colCompliance')}
                </th>
                <th className="px-4 py-3 font-medium">{t('vulns.colOwner')}</th>
                <th className="px-4 py-3 font-medium">{t('vulns.colCvss')}</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td
                    colSpan={8}
                    className="px-4 py-10 text-center text-surface-400"
                  >
                    {t('vulns.loading')}
                  </td>
                </tr>
              ) : filtered.length === 0 ? (
                <tr>
                  <td
                    colSpan={8}
                    className="px-4 py-10 text-center text-surface-400"
                  >
                    {t('vulns.empty')}
                  </td>
                </tr>
              ) : (
                filtered.map((v) => (
                  <tr
                    key={v.id}
                    className="border-t border-surface-800 transition-colors hover:bg-surface-800/40"
                  >
                    <td className="px-4 py-3">
                      <input
                        type="checkbox"
                        checked={selected.has(v.id)}
                        onChange={() => toggleOne(v.id)}
                        aria-label={v.title}
                      />
                    </td>
                    <td className="px-4 py-3">
                      <SeverityBadge severity={v.severity} />
                    </td>
                    <td className="px-4 py-3">
                      <Link
                        to={`/vulnerabilities/${v.id}`}
                        className="font-medium text-surface-100 hover:text-accent"
                      >
                        {v.title}
                      </Link>
                      <div className="mt-0.5 font-mono text-[10px] text-surface-400">
                        {[v.cve_id, v.cwe_id].filter(Boolean).join(' · ') ||
                          v.fingerprint.slice(0, 16)}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <StatusBadge status={v.status} />
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-surface-300">
                      {v.affected_component ?? v.asset_id.slice(0, 8)}
                      {v.port != null ? `:${v.port}` : ''}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        {complianceKeys(v).map((k) => (
                          <span
                            key={k}
                            className="rounded bg-surface-700 px-1.5 py-0.5 font-mono text-[10px] text-surface-300"
                          >
                            {k}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-xs text-surface-300">
                      {v.remediation_owner_label ?? '—'}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs tabular-nums">
                      {v.cvss_score?.toFixed(1) ?? '—'}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
