import type { FindingStatus, Severity } from '../api/types'

const severityStyles: Record<Severity, string> = {
  critical: 'bg-danger/15 text-danger border-danger/30',
  high: 'bg-warn/15 text-warn border-warn/30',
  medium: 'bg-amber-500/10 text-amber-300 border-amber-500/25',
  low: 'bg-accent/10 text-accent border-accent/25',
  info: 'bg-surface-700 text-surface-300 border-surface-600',
  unknown: 'bg-surface-800 text-surface-400 border-surface-600',
}

const statusStyles: Record<FindingStatus, string> = {
  open: 'bg-danger/10 text-danger',
  in_progress: 'bg-warn/10 text-warn',
  false_positive: 'bg-surface-700 text-surface-300',
  resolved: 'bg-ok/10 text-ok',
  confirmed: 'bg-accent/10 text-accent',
  accepted_risk: 'bg-surface-700 text-surface-300',
  remediated: 'bg-ok/10 text-ok',
  reopened: 'bg-danger/10 text-danger',
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-flex items-center rounded border px-2 py-0.5 font-mono text-[11px] uppercase tracking-wider ${severityStyles[severity]}`}
    >
      {severity}
    </span>
  )
}

export function StatusBadge({ status }: { status: FindingStatus }) {
  return (
    <span
      className={`inline-flex items-center rounded px-2 py-0.5 font-mono text-[11px] tracking-wide ${statusStyles[status]}`}
    >
      {status.replaceAll('_', ' ')}
    </span>
  )
}
