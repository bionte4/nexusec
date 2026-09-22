import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import {
  Activity,
  LayoutDashboard,
  LogOut,
  MessageSquareText,
  Settings2,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react'
import { useAuth } from '../auth/AuthContext'

const nav = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/vulnerabilities', label: 'Vulnerabilities', icon: ShieldAlert },
  { to: '/soc-chat', label: 'SOC Chat', icon: MessageSquareText },
  { to: '/admin', label: 'Administration', icon: Settings2, adminOnly: true },
]

export function AppShell() {
  const { logout, usingMock, isAdmin, user } = useAuth()
  const navigate = useNavigate()

  const items = nav.filter((item) => !item.adminOnly || isAdmin)

  return (
    <div className="grid-noise min-h-screen">
      <div className="mx-auto flex min-h-screen max-w-[1440px]">
        <aside className="panel sticky top-0 flex h-screen w-60 shrink-0 flex-col border-y-0 border-l-0 px-4 py-6">
          <div className="mb-8 flex items-center gap-3 px-2">
            <div className="flex h-9 w-9 items-center justify-center rounded-md bg-accent/15 text-accent">
              <ShieldCheck className="h-5 w-5" strokeWidth={2.25} />
            </div>
            <div>
              <div className="text-sm font-semibold tracking-wide text-surface-100">
                NexuSec
              </div>
              <div className="font-mono text-[10px] uppercase tracking-[0.18em] text-surface-400">
                SOC Console
              </div>
            </div>
          </div>

          <nav className="flex flex-1 flex-col gap-1">
            {items.map(({ to, label, icon: Icon, end }) => (
              <NavLink
                key={to}
                to={to}
                end={end}
                className={({ isActive }) =>
                  [
                    'flex items-center gap-3 rounded-md px-3 py-2.5 text-sm transition-colors',
                    isActive
                      ? 'bg-accent/12 text-accent'
                      : 'text-surface-300 hover:bg-surface-800 hover:text-surface-100',
                  ].join(' ')
                }
              >
                <Icon className="h-4 w-4 shrink-0" />
                {label}
              </NavLink>
            ))}
          </nav>

          <div className="mt-auto space-y-3 border-t border-surface-700 pt-4">
            {user && (
              <div className="px-2 text-xs text-surface-400">
                <div className="truncate text-surface-200">{user.full_name}</div>
                <div className="font-mono uppercase tracking-wide text-[10px] text-accent">
                  {user.role.replaceAll('_', ' ')}
                </div>
              </div>
            )}
            {usingMock && (
              <div className="flex items-center gap-2 rounded-md bg-warn/10 px-3 py-2 font-mono text-[11px] text-warn">
                <Activity className="h-3.5 w-3.5" />
                Demo data mode
              </div>
            )}
            <button
              type="button"
              onClick={() => {
                logout()
                navigate('/login')
              }}
              className="flex w-full items-center gap-2 rounded-md px-3 py-2 text-sm text-surface-400 transition-colors hover:bg-surface-800 hover:text-surface-100"
            >
              <LogOut className="h-4 w-4" />
              Sign out
            </button>
          </div>
        </aside>

        <main className="flex-1 overflow-auto px-6 py-6 md:px-8">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
