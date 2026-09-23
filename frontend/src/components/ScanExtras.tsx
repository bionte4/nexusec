import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api, ApiError } from '../api/client'
import { useLocale } from '../i18n/locale'

type Evidence = Awaited<ReturnType<typeof api.getScanEvidence>>
type Diff = Awaited<ReturnType<typeof api.getScanDiff>>
type Discovery = Awaited<ReturnType<typeof api.getDiscoveredHosts>>

interface Props {
  scanId: string
  engine: string
  status: string
  canWrite: boolean
  busy: boolean
  onNotice: (msg: string) => void
  onError: (msg: string) => void
  onAssetsChanged?: () => void
}

export function ScanExtras({
  scanId,
  engine,
  status,
  canWrite,
  busy,
  onNotice,
  onError,
  onAssetsChanged,
}: Props) {
  const { t } = useLocale()
  const [evidence, setEvidence] = useState<Evidence | null>(null)
  const [diff, setDiff] = useState<Diff | null>(null)
  const [discovery, setDiscovery] = useState<Discovery | null>(null)
  const [selectedHosts, setSelectedHosts] = useState<Set<number>>(new Set())
  const [loading, setLoading] = useState(false)

  async function toggleEvidence() {
    if (evidence) {
      setEvidence(null)
      return
    }
    setLoading(true)
    try {
      setEvidence(await api.getScanEvidence(scanId))
    } catch (err) {
      onError(err instanceof ApiError ? err.message : t('scans.loadFailed'))
    } finally {
      setLoading(false)
    }
  }

  async function toggleDiff() {
    if (diff) {
      setDiff(null)
      return
    }
    setLoading(true)
    try {
      setDiff(await api.getScanDiff(scanId))
    } catch (err) {
      onError(err instanceof ApiError ? err.message : t('scans.diffFailed'))
    } finally {
      setLoading(false)
    }
  }

  async function toggleDiscovery() {
    if (discovery) {
      setDiscovery(null)
      return
    }
    setLoading(true)
    try {
      const res = await api.getDiscoveredHosts(scanId)
      setDiscovery(res)
      setSelectedHosts(
        new Set(
          res.hosts
            .map((h, i) => (!h.already_known ? i : -1))
            .filter((i) => i >= 0),
        ),
      )
    } catch (err) {
      onError(
        err instanceof ApiError ? err.message : t('scans.discoveredFailed'),
      )
    } finally {
      setLoading(false)
    }
  }

  async function acceptHosts() {
    if (!discovery || selectedHosts.size === 0) return
    setLoading(true)
    try {
      const hosts = [...selectedHosts].map((i) => {
        const h = discovery.hosts[i]
        return {
          ip_address: h.ip_address,
          hostname: h.hostname,
          name: String(h.suggested_asset.name ?? h.hostname ?? h.ip_address),
        }
      })
      const res = await api.acceptDiscoveredHosts(scanId, hosts)
      onNotice(t('scans.discoveredAccepted', { count: res.created_count }))
      setDiscovery(null)
      onAssetsChanged?.()
    } catch (err) {
      onError(
        err instanceof ApiError ? err.message : t('scans.discoveredFailed'),
      )
    } finally {
      setLoading(false)
    }
  }

  const showDiscovery = engine === 'nmap' && status === 'completed'

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          disabled={busy || loading}
          onClick={() => void toggleEvidence()}
          className="rounded-md border border-surface-600 px-2 py-1 text-[11px] text-surface-300 hover:border-accent hover:text-accent disabled:opacity-50"
        >
          {evidence ? t('scans.hideEvidence') : t('scans.evidence')}
        </button>
        {(status === 'completed' || status === 'failed') && (
          <button
            type="button"
            disabled={busy || loading}
            onClick={() => void toggleDiff()}
            className="rounded-md border border-surface-600 px-2 py-1 text-[11px] text-surface-300 hover:border-accent hover:text-accent disabled:opacity-50"
          >
            {diff ? t('scans.hideDiff') : t('scans.diff')}
          </button>
        )}
        {showDiscovery ? (
          <button
            type="button"
            disabled={busy || loading}
            onClick={() => void toggleDiscovery()}
            className="rounded-md border border-surface-600 px-2 py-1 text-[11px] text-surface-300 hover:border-accent hover:text-accent disabled:opacity-50"
          >
            {discovery ? t('scans.hideDiscovered') : t('scans.discovered')}
          </button>
        ) : null}
      </div>

      {evidence ? (
        <div className="space-y-2 rounded-lg border border-surface-700 bg-surface-900/60 p-3 text-[11px]">
          {evidence.command ? (
            <div>
              <div className="font-mono uppercase tracking-wider text-surface-500">
                {t('scans.command')}
              </div>
              <pre className="mt-1 max-h-24 overflow-auto whitespace-pre-wrap text-surface-300">
                {evidence.command.join(' ')}
              </pre>
            </div>
          ) : null}
          {evidence.ingest ? (
            <div>
              <div className="font-mono uppercase tracking-wider text-surface-500">
                {t('scans.ingest')}
              </div>
              <pre className="mt-1 overflow-auto text-surface-300">
                {JSON.stringify(evidence.ingest)}
              </pre>
            </div>
          ) : null}
          {evidence.stderr ? (
            <div>
              <div className="font-mono uppercase tracking-wider text-surface-500">
                {t('scans.stderr')}
              </div>
              <pre className="mt-1 max-h-32 overflow-auto whitespace-pre-wrap text-danger">
                {evidence.stderr}
              </pre>
            </div>
          ) : null}
          {evidence.stdout_preview ? (
            <div>
              <div className="font-mono uppercase tracking-wider text-surface-500">
                {t('scans.stdout')}
                {evidence.stdout_truncated
                  ? ` (${evidence.stdout_chars} chars)`
                  : ''}
              </div>
              <pre className="mt-1 max-h-48 overflow-auto whitespace-pre-wrap text-surface-300">
                {evidence.stdout_preview}
              </pre>
            </div>
          ) : null}
        </div>
      ) : null}

      {diff ? (
        <div className="space-y-2 rounded-lg border border-surface-700 bg-surface-900/60 p-3 text-[11px]">
          <div className="text-surface-300">
            {t('scans.diffSummary', {
              newCount: diff.counts.new,
              resolvedCount: diff.counts.resolved,
              unchanged: diff.counts.unchanged,
            })}
          </div>
          {diff.new.slice(0, 8).map((item) => (
            <div key={String(item.fingerprint)} className="text-ok">
              + {String(item.title)}
              {item.vulnerability_id ? (
                <>
                  {' · '}
                  <Link
                    to={`/vulnerabilities/${item.vulnerability_id}`}
                    className="text-accent hover:underline"
                  >
                    {t('common.findings')}
                  </Link>
                </>
              ) : null}
            </div>
          ))}
          {diff.resolved.slice(0, 8).map((item) => (
            <div key={String(item.fingerprint)} className="text-surface-400">
              − {String(item.title)}
            </div>
          ))}
        </div>
      ) : null}

      {discovery ? (
        <div className="space-y-2 rounded-lg border border-surface-700 bg-surface-900/60 p-3 text-[11px]">
          <div className="text-surface-300">
            {discovery.new_count} {t('scans.newHost')} / {discovery.total}
          </div>
          <ul className="max-h-48 space-y-1 overflow-auto">
            {discovery.hosts.map((h, i) => (
              <li key={`${h.ip_address}-${h.hostname}-${i}`} className="flex gap-2">
                {!h.already_known && canWrite ? (
                  <input
                    type="checkbox"
                    checked={selectedHosts.has(i)}
                    onChange={() => {
                      setSelectedHosts((prev) => {
                        const next = new Set(prev)
                        if (next.has(i)) next.delete(i)
                        else next.add(i)
                        return next
                      })
                    }}
                  />
                ) : (
                  <span className="w-4" />
                )}
                <span className="font-mono text-surface-200">
                  {h.ip_address || h.hostname}
                  {h.hostname && h.ip_address ? ` (${h.hostname})` : ''}
                </span>
                <span className="text-surface-500">
                  {h.already_known ? t('scans.alreadyKnown') : t('scans.newHost')}
                </span>
              </li>
            ))}
          </ul>
          {canWrite && selectedHosts.size > 0 ? (
            <button
              type="button"
              disabled={busy || loading}
              onClick={() => void acceptHosts()}
              className="rounded-md bg-accent px-2 py-1 text-[11px] font-semibold text-surface-950 disabled:opacity-50"
            >
              {t('scans.acceptSelected')}
            </button>
          ) : null}
        </div>
      ) : null}
    </div>
  )
}
