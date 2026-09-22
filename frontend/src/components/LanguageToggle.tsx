import type { Locale } from '../i18n/messages'
import { useLocale } from '../i18n/locale'

export function LanguageToggle({ compact = false }: { compact?: boolean }) {
  const { locale, setLocale, t } = useLocale()

  const options: { id: Locale; label: string }[] = [
    { id: 'en', label: 'EN' },
    { id: 'id', label: 'ID' },
  ]

  return (
    <div className={compact ? 'space-y-1' : 'space-y-1.5'}>
      {!compact ? (
        <div className="px-2 font-mono text-[10px] uppercase tracking-wider text-surface-400">
          {t('common.language')}
        </div>
      ) : null}
      <div
        className="flex rounded-md border border-surface-700 bg-surface-900/60 p-0.5"
        role="group"
        aria-label={t('common.language')}
      >
        {options.map((opt) => {
          const active = locale === opt.id
          return (
            <button
              key={opt.id}
              type="button"
              onClick={() => setLocale(opt.id)}
              className={[
                'flex-1 rounded px-2 py-1.5 font-mono text-[11px] font-semibold tracking-wide transition-colors',
                active
                  ? 'bg-accent/15 text-accent'
                  : 'text-surface-400 hover:text-surface-100',
              ].join(' ')}
              aria-pressed={active}
            >
              {opt.label}
            </button>
          )
        })}
      </div>
    </div>
  )
}
