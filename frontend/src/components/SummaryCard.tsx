import type { LucideIcon } from 'lucide-react'

interface SummaryCardProps {
  label: string
  value: string | number
  hint?: string
  icon: LucideIcon
  tone?: 'default' | 'danger' | 'warn' | 'ok' | 'accent'
}

const toneMap = {
  default: 'text-surface-100 bg-surface-700/60',
  danger: 'text-danger bg-danger/12',
  warn: 'text-warn bg-warn/12',
  ok: 'text-ok bg-ok/12',
  accent: 'text-accent bg-accent/12',
}

export function SummaryCard({
  label,
  value,
  hint,
  icon: Icon,
  tone = 'default',
}: SummaryCardProps) {
  return (
    <div className="panel rounded-xl p-5 transition-transform duration-300 hover:-translate-y-0.5">
      <div className="mb-4 flex items-start justify-between gap-3">
        <div className="font-mono text-[11px] uppercase tracking-[0.16em] text-surface-400">
          {label}
        </div>
        <div
          className={`flex h-9 w-9 items-center justify-center rounded-lg ${toneMap[tone]}`}
        >
          <Icon className="h-4.5 w-4.5" size={18} />
        </div>
      </div>
      <div className="text-3xl font-semibold tracking-tight tabular-nums">
        {value}
      </div>
      {hint ? (
        <p className="mt-2 text-xs text-surface-400">{hint}</p>
      ) : null}
    </div>
  )
}
