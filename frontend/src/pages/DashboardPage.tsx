import { useEffect, useState } from 'react'
import {
  AlertTriangle,
  CheckCircle2,
  Server,
  ShieldAlert,
} from 'lucide-react'
import { api, ApiError } from '../api/client'
import type { DashboardOverview } from '../api/types'
import { useAuth } from '../auth/AuthContext'
import { SummaryCard } from '../components/SummaryCard'
import { TrendChart } from '../components/TrendChart'
import { MOCK_DASHBOARD } from '../data/mock'
import { useLocale } from '../i18n/locale'

function complianceScoreKey(data: DashboardOverview): 'compliant' | 'atRisk' | 'partial' | 'unknown' {
  const openCritHigh =
    data.active_by_severity.critical + data.active_by_severity.high
  const cdeAssets = data.asset_risk_posture.filter((a) => a.is_cde_scope).length
  if (openCritHigh === 0 && data.total_assets > 0) return 'compliant'
  if (cdeAssets > 0 && openCritHigh > 5) return 'atRisk'
  if (openCritHigh > 0) return 'partial'
  return 'unknown'
}

export function DashboardPage() {
  const { usingMock, setUsingMock, token } = useAuth()
  const { t } = useLocale()
  const [data, setData] = useState<DashboardOverview | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false

    async function load() {
      setLoading(true)
      setError(null)
      if (usingMock || token === 'demo') {
        if (!cancelled) {
          setData(MOCK_DASHBOARD)
          setUsingMock(true)
          setLoading(false)
        }
        return
      }
      try {
        const overview = await api.dashboardOverview(30)
        if (!cancelled) {
          setData(overview)
          setUsingMock(false)
        }
      } catch (err) {
        if (!cancelled) {
          setData(MOCK_DASHBOARD)
          setUsingMock(true)
          setError(
            err instanceof ApiError
              ? t('dashboard.apiUnavailable', { status: err.status })
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
  }, [usingMock, token, setUsingMock, t])

  if (loading || !data) {
    return (
      <div className="flex h-64 items-center justify-center text-sm text-surface-400">
        {t('dashboard.loading')}
      </div>
    )
  }

  const sev = data.active_by_severity
  const complianceKey = complianceScoreKey(data)
  const complianceMap = {
    compliant: t('dashboard.compliant'),
    atRisk: t('dashboard.atRisk'),
    partial: t('dashboard.partial'),
    unknown: t('dashboard.unknown'),
  } as const
  const compliance = complianceMap[complianceKey]

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-accent">
            {t('dashboard.eyebrow')}
          </p>
          <h1 className="mt-1 text-2xl font-semibold tracking-tight">
            {t('dashboard.title')}
          </h1>
          <p className="mt-1 text-sm text-surface-400">
            {t('dashboard.subtitle')}
          </p>
        </div>
        <div className="font-mono text-[11px] text-surface-400">
          {t('dashboard.generated', { when: new Date(data.generated_at).toLocaleString() })}
        </div>
      </header>

      {error ? (
        <div className="rounded-lg border border-warn/30 bg-warn/10 px-4 py-2 text-xs text-warn">
          {error}
        </div>
      ) : null}

      <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <SummaryCard
          label={t('dashboard.totalAssets')}
          value={data.total_assets}
          hint={t('dashboard.withActive', { count: data.assets_with_active_findings })}
          icon={Server}
          tone="accent"
        />
        <SummaryCard
          label={t('dashboard.openCritical')}
          value={sev.critical}
          hint={t('dashboard.immediateTriage')}
          icon={ShieldAlert}
          tone="danger"
        />
        <SummaryCard
          label={t('dashboard.openHigh')}
          value={sev.high}
          hint={t('dashboard.activeTotal', { count: sev.total })}
          icon={AlertTriangle}
          tone="warn"
        />
        <SummaryCard
          label={t('dashboard.compliance')}
          value={compliance}
          hint={t('dashboard.complianceHint')}
          icon={CheckCircle2}
          tone={complianceKey === 'compliant' ? 'ok' : 'warn'}
        />
      </section>

      <section className="grid gap-4 lg:grid-cols-3">
        <div className="panel rounded-xl p-5 lg:col-span-2">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="text-sm font-medium">{t('dashboard.trends')}</h2>
            <span className="font-mono text-[11px] text-surface-400">
              {t('dashboard.lastDays', { count: data.trend.length })}
            </span>
          </div>
          <TrendChart data={data.trend} />
        </div>

        <div className="panel rounded-xl p-5">
          <h2 className="mb-4 text-sm font-medium">{t('dashboard.severityMix')}</h2>
          <ul className="space-y-3">
            {(
              [
                ['critical', sev.critical, 'bg-danger'],
                ['high', sev.high, 'bg-warn'],
                ['medium', sev.medium, 'bg-amber-400'],
                ['low', sev.low, 'bg-accent'],
                ['info', sev.info, 'bg-surface-400'],
              ] as const
            ).map(([label, count, bar]) => {
              const pct = sev.total ? Math.round((count / sev.total) * 100) : 0
              return (
                <li key={label}>
                  <div className="mb-1 flex justify-between font-mono text-[11px]">
                    <span className="uppercase tracking-wider text-surface-400">
                      {label}
                    </span>
                    <span className="text-surface-100">
                      {count} · {pct}%
                    </span>
                  </div>
                  <div className="h-1.5 overflow-hidden rounded-full bg-surface-800">
                    <div
                      className={`h-full rounded-full ${bar} transition-all duration-700`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </li>
              )
            })}
          </ul>

          <h2 className="mb-3 mt-8 text-sm font-medium">{t('dashboard.topRisk')}</h2>
          <ul className="space-y-2">
            {data.asset_risk_posture.slice(0, 5).map((a) => (
              <li
                key={a.asset_id}
                className="flex items-center justify-between rounded-lg bg-surface-900/60 px-3 py-2"
              >
                <div>
                  <div className="text-sm">{a.asset_name}</div>
                  <div className="font-mono text-[10px] text-surface-400">
                    {a.asset_type}
                    {a.is_cde_scope ? ' · CDE' : ''}
                  </div>
                </div>
                <div className="font-mono text-sm text-warn">
                  {a.risk_score.toFixed(0)}
                </div>
              </li>
            ))}
            {data.asset_risk_posture.length === 0 ? (
              <li className="text-xs text-surface-400">{t('dashboard.noRiskData')}</li>
            ) : null}
          </ul>
        </div>
      </section>
    </div>
  )
}
