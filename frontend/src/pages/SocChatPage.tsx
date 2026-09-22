import { useState, type FormEvent } from 'react'
import { MessageSquareText, Send } from 'lucide-react'
import { api, ApiError } from '../api/client'
import type { SocChatResponse } from '../api/types'
import { useAuth } from '../auth/AuthContext'
import { useLocale } from '../i18n/locale'

const SUGGESTIONS = [
  'Which assets currently violate PCI-DSS requirements?',
  'Summarize critical vulnerabilities this week',
  'Show KEV actively exploited findings',
  'List recent scans and asset inventory',
]

const DEMO_ANSWER = `### NexuSec SOC summary (demo)

**Active findings:** 12 (critical=2, high=5, medium=4, low=1).

**PCI-DSS CDE:** 3 CDE asset(s) with active findings on payment segment hosts.

**Recommended actions:**
1. Prioritize remediation on CDE-scoped assets (PCI-DSS Req 11).
2. Assign owners to critical findings and re-scan after patches.

_Demo mode — connect the API for live RAG answers._`

export function SocChatPage() {
  const { usingMock, token } = useAuth()
  const { t } = useLocale()
  const [query, setQuery] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<SocChatResponse | null>(null)

  async function submit(q: string) {
    const trimmed = q.trim()
    if (trimmed.length < 3) return
    setLoading(true)
    setError(null)
    try {
      if (usingMock || token === 'demo') {
        setResult({
          answer: DEMO_ANSWER,
          provider: 'mock',
          model: 'demo',
          intent: { pci_dss: /pci/i.test(trimmed), critical: /critical/i.test(trimmed) },
          stats: { active_findings_total: 12 },
          sources: [
            { type: 'vulnerability', title: 'Weak TLS on payment DB', severity: 'high' },
            { type: 'asset', name: 'pos-db', tag: 'cde' },
          ],
          context_chars: 420,
        })
      } else {
        const resp = await api.socChat(trimmed)
        setResult(resp)
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t('soc.failed'))
    } finally {
      setLoading(false)
    }
  }

  function onSubmit(e: FormEvent) {
    e.preventDefault()
    void submit(query)
  }

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <header className="space-y-2">
        <div className="flex items-center gap-2 text-accent">
          <MessageSquareText className="h-5 w-5" />
          <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-surface-400">
            {t('soc.eyebrow')}
          </span>
        </div>
        <h1 className="text-2xl font-semibold tracking-tight">{t('soc.title')}</h1>
        <p className="text-sm text-surface-400">
          {t('soc.subtitle')}
        </p>
      </header>

      <div className="flex flex-wrap gap-2">
        {SUGGESTIONS.map((s) => (
          <button
            key={s}
            type="button"
            disabled={loading}
            onClick={() => {
              setQuery(s)
              void submit(s)
            }}
            className="rounded-lg border border-surface-700 bg-surface-900/60 px-3 py-1.5 text-left text-xs text-surface-300 transition hover:border-accent hover:text-accent disabled:opacity-50"
          >
            {s}
          </button>
        ))}
      </div>

      <form onSubmit={onSubmit} className="flex gap-2">
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={t('soc.placeholder')}
          className="flex-1 rounded-lg border border-surface-600 bg-surface-900 px-3 py-2.5 text-sm outline-none focus:border-accent"
        />
        <button
          type="submit"
          disabled={loading || query.trim().length < 3}
          className="inline-flex items-center gap-2 rounded-lg bg-accent px-4 py-2 text-sm font-semibold text-surface-950 transition hover:bg-accent-dim disabled:opacity-50"
        >
          <Send className="h-4 w-4" />
          {loading ? '…' : t('soc.send')}
        </button>
      </form>

      {error ? (
        <div className="rounded-lg border border-crit/30 bg-crit/10 px-4 py-2 text-xs text-crit">
          {error}
        </div>
      ) : null}

      {result ? (
        <section className="panel space-y-4 rounded-xl p-5">
          <div className="flex flex-wrap items-center gap-2 font-mono text-[10px] uppercase tracking-wider text-surface-400">
            <span>
              {result.provider}/{result.model}
            </span>
            <span>· {result.context_chars} ctx chars</span>
            {Object.entries(result.intent)
              .filter(([, v]) => v)
              .map(([k]) => (
                <span key={k} className="rounded bg-surface-800 px-1.5 py-0.5 text-accent">
                  {k}
                </span>
              ))}
          </div>
          <div className="whitespace-pre-wrap text-sm leading-relaxed text-surface-200">
            {result.answer}
          </div>
          {result.sources.length > 0 ? (
            <div className="border-t border-surface-700 pt-3">
              <h3 className="mb-2 font-mono text-[10px] uppercase tracking-wider text-surface-400">
                {t('soc.sources')}
              </h3>
              <ul className="space-y-1 font-mono text-[11px] text-surface-400">
                {result.sources.slice(0, 12).map((s, i) => (
                  <li key={`${s.id ?? s.title ?? s.name ?? i}`}>
                    [{String(s.type)}] {String(s.title ?? s.name ?? s.id ?? '—')}
                    {s.severity ? ` · ${String(s.severity)}` : ''}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </section>
      ) : null}
    </div>
  )
}
