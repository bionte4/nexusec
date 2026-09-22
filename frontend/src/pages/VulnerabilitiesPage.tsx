import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { Filter, Search } from 'lucide-react'
import { api, ApiError } from '../api/client'
import type {
  FindingStatus,
  Severity,
  Vulnerability,
} from '../api/types'
import { useAuth } from '../auth/AuthContext'
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

export function VulnerabilitiesPage() {
  const { usingMock, setUsingMock, token } = useAuth()
  const [items, setItems] = useState<Vulnerability[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const [severity, setSeverity] = useState<Severity | ''>('')
  const [status, setStatus] = useState<FindingStatus | ''>('')
  const [assetQuery, setAssetQuery] = useState('')
  const [compliance, setCompliance] = useState<string>('')
  const [search, setSearch] = useState('')

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
        })
        if (!cancelled) {
          setItems(res.items)
          setTotal(res.total)
          setUsingMock(false)
        }
      } catch (err) {
        if (!cancelled) {
          setItems(MOCK_VULNS)
          setTotal(MOCK_VULNS.length)
          setUsingMock(true)
          setError(
            err instanceof ApiError
              ? `API unavailable (${err.status}) — showing demo data`
              : 'API unavailable — showing demo data',
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
  }, [severity, status, search, usingMock, token, setUsingMock])

  const filtered = useMemo(() => {
    return items.filter((v) => {
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
  }, [items, severity, status, assetQuery, compliance, search])

  return (
    <div className="space-y-6">
      <header>
        <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-accent">
          Remediation
        </p>
        <h1 className="mt-1 text-2xl font-semibold tracking-tight">
          Vulnerability management
        </h1>
        <p className="mt-1 text-sm text-surface-400">
          Filter by severity, status, asset, and compliance taxonomy.
        </p>
      </header>

      {error ? (
        <div className="rounded-lg border border-warn/30 bg-warn/10 px-4 py-2 text-xs text-warn">
          {error}
        </div>
      ) : null}

      <div className="panel rounded-xl p-4">
        <div className="mb-3 flex items-center gap-2 text-xs text-surface-400">
          <Filter className="h-3.5 w-3.5" />
          Filters
        </div>
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-5">
          <label className="space-y-1">
            <span className="font-mono text-[10px] uppercase tracking-wider text-surface-400">
              Severity
            </span>
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value as Severity | '')}
              className="w-full rounded-lg border border-surface-600 bg-surface-900 px-3 py-2 text-sm outline-none focus:border-accent"
            >
              <option value="">All</option>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </label>
          <label className="space-y-1">
            <span className="font-mono text-[10px] uppercase tracking-wider text-surface-400">
              Status
            </span>
            <select
              value={status}
              onChange={(e) => setStatus(e.target.value as FindingStatus | '')}
              className="w-full rounded-lg border border-surface-600 bg-surface-900 px-3 py-2 text-sm outline-none focus:border-accent"
            >
              <option value="">All</option>
              {STATUSES.map((s) => (
                <option key={s} value={s}>
                  {s.replaceAll('_', ' ')}
                </option>
              ))}
            </select>
          </label>
          <label className="space-y-1">
            <span className="font-mono text-[10px] uppercase tracking-wider text-surface-400">
              Asset / component
            </span>
            <input
              value={assetQuery}
              onChange={(e) => setAssetQuery(e.target.value)}
              placeholder="asset id or component"
              className="w-full rounded-lg border border-surface-600 bg-surface-900 px-3 py-2 text-sm outline-none focus:border-accent"
            />
          </label>
          <label className="space-y-1">
            <span className="font-mono text-[10px] uppercase tracking-wider text-surface-400">
              Compliance tag
            </span>
            <select
              value={compliance}
              onChange={(e) => setCompliance(e.target.value)}
              className="w-full rounded-lg border border-surface-600 bg-surface-900 px-3 py-2 text-sm outline-none focus:border-accent"
            >
              <option value="">All</option>
              {COMPLIANCE_TAGS.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </label>
          <label className="space-y-1">
            <span className="font-mono text-[10px] uppercase tracking-wider text-surface-400">
              Search
            </span>
            <div className="relative">
              <Search className="pointer-events-none absolute top-2.5 left-3 h-4 w-4 text-surface-400" />
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="title, CVE, CWE…"
                className="w-full rounded-lg border border-surface-600 bg-surface-900 py-2 pr-3 pl-9 text-sm outline-none focus:border-accent"
              />
            </div>
          </label>
        </div>
      </div>

      <div className="panel overflow-hidden rounded-xl">
        <div className="flex items-center justify-between border-b border-surface-700 px-4 py-3">
          <span className="text-sm text-surface-300">
            Showing {filtered.length}
            {!usingMock ? ` of ${total}` : ''} findings
          </span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[880px] text-left text-sm">
            <thead className="bg-surface-900/80 font-mono text-[10px] uppercase tracking-wider text-surface-400">
              <tr>
                <th className="px-4 py-3 font-medium">Severity</th>
                <th className="px-4 py-3 font-medium">Title</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium">Asset</th>
                <th className="px-4 py-3 font-medium">Compliance</th>
                <th className="px-4 py-3 font-medium">Owner</th>
                <th className="px-4 py-3 font-medium">CVSS</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td
                    colSpan={7}
                    className="px-4 py-10 text-center text-surface-400"
                  >
                    Loading…
                  </td>
                </tr>
              ) : filtered.length === 0 ? (
                <tr>
                  <td
                    colSpan={7}
                    className="px-4 py-10 text-center text-surface-400"
                  >
                    No vulnerabilities match filters
                  </td>
                </tr>
              ) : (
                filtered.map((v) => (
                  <tr
                    key={v.id}
                    className="border-t border-surface-800 transition-colors hover:bg-surface-800/40"
                  >
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
