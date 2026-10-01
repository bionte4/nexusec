/** Detect silent mock/template AI output so the UI can warn operators. */

export function isMockAiProvider(
  provider?: string | null,
  model?: string | null,
): boolean {
  const p = (provider || '').toLowerCase()
  const m = (model || '').toLowerCase()
  if (!p && !m) return false
  if (p === 'mock' || p.includes('mock')) return true
  if (m.includes('template') || m.includes('heuristic') || m.includes('mock')) {
    return true
  }
  return false
}

export function isMockRemediationText(text?: string | null): boolean {
  if (!text) return false
  const lower = text.toLowerCase()
  return (
    lower.includes('mock/template') ||
    lower.includes('(mock/template') ||
    lower.includes('ai remediation (mock') ||
    lower.includes('nexusec ai remediation (mock')
  )
}

export function isSyntheticScannerFinding(input: {
  description?: string | null
  title?: string | null
  source_tool?: string | null
  evidence?: unknown
  threat_intel_metadata?: Record<string, unknown> | null
}): boolean {
  const blob = [
    input.description ?? '',
    input.title ?? '',
    typeof input.evidence === 'string' ? input.evidence : JSON.stringify(input.evidence ?? ''),
    JSON.stringify(input.threat_intel_metadata ?? {}),
  ]
    .join(' ')
    .toLowerCase()
  if (blob.includes('nexusec_mock') || blob.includes('zap mock')) return true
  if (
    (input.source_tool || '').toLowerCase() === 'zap' &&
    (blob.includes('synthetic') || blob.includes('mock connector'))
  ) {
    return true
  }
  return false
}
