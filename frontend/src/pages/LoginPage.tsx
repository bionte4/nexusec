import { useState, type FormEvent } from 'react'
import { Navigate, useNavigate } from 'react-router-dom'
import { ShieldCheck } from 'lucide-react'
import { useAuth } from '../auth/AuthContext'
import { ApiError } from '../api/client'

export function LoginPage() {
  const { token, login, enterDemo } = useAuth()
  const navigate = useNavigate()
  const [email, setEmail] = useState('admin@example.com')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  if (token) return <Navigate to="/" replace />

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await login(email, password)
      navigate('/')
    } catch (err) {
      if (err instanceof ApiError) setError(err.message)
      else setError('Unable to reach API. Use demo mode or start the backend.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="grid-noise flex min-h-screen items-center justify-center px-4">
      <div className="panel w-full max-w-md rounded-2xl p-8">
        <div className="mb-8 flex items-center gap-3">
          <div className="flex h-11 w-11 items-center justify-center rounded-lg bg-accent/15 text-accent">
            <ShieldCheck className="h-6 w-6" />
          </div>
          <div>
            <h1 className="text-xl font-semibold tracking-tight">NexuSec</h1>
            <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-surface-400">
              Sign in to SOC Console
            </p>
          </div>
        </div>

        <form onSubmit={onSubmit} className="space-y-4">
          <label className="block space-y-1.5">
            <span className="text-xs text-surface-400">Email</span>
            <input
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full rounded-lg border border-surface-600 bg-surface-900 px-3 py-2.5 text-sm outline-none focus:border-accent"
            />
          </label>
          <label className="block space-y-1.5">
            <span className="text-xs text-surface-400">Password</span>
            <input
              type="password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full rounded-lg border border-surface-600 bg-surface-900 px-3 py-2.5 text-sm outline-none focus:border-accent"
            />
          </label>
          {error ? (
            <p className="rounded-md bg-danger/10 px-3 py-2 text-xs text-danger">
              {error}
            </p>
          ) : null}
          <button
            type="submit"
            disabled={busy}
            className="w-full rounded-lg bg-accent px-4 py-2.5 text-sm font-semibold text-surface-950 transition hover:bg-accent-dim disabled:opacity-60"
          >
            {busy ? 'Signing in…' : 'Sign in'}
          </button>
        </form>

        <div className="my-6 h-px bg-surface-700" />
        <button
          type="button"
          onClick={() => {
            enterDemo()
            navigate('/')
          }}
          className="w-full rounded-lg border border-surface-600 px-4 py-2.5 text-sm text-surface-300 transition hover:border-accent hover:text-accent"
        >
          Continue with demo data
        </button>
      </div>
    </div>
  )
}
