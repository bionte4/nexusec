import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'
import { api, getToken, setOrganizationId, setToken } from '../api/client'
import type { AuthUser } from '../api/types'

function syncOrganizationId(user: AuthUser | null): void {
  setOrganizationId(user?.organization_id ?? null)
}

interface AuthState {
  token: string | null
  user: AuthUser | null
  usingMock: boolean
  isAdmin: boolean
  login: (email: string, password: string) => Promise<void>
  enterDemo: () => void
  logout: () => void
  setUsingMock: (v: boolean) => void
  refreshUser: () => Promise<void>
}

const AuthContext = createContext<AuthState | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setTokenState] = useState<string | null>(() => getToken())
  const [user, setUser] = useState<AuthUser | null>(null)
  const [usingMock, setUsingMock] = useState(false)

  const refreshUser = useCallback(async () => {
    const t = getToken()
    if (!t || t === 'demo') {
      setUser(null)
      return
    }
    try {
      const me = await api.me()
      setUser(me)
      syncOrganizationId(me)
      if (me.role === 'super_admin' && !me.organization_id) {
        try {
          const orgs = await api.listOrganizations({ page_size: 1 })
          if (orgs.items[0]) setOrganizationId(orgs.items[0].id)
        } catch {
          /* keep null — create will prompt for scope */
        }
      }
    } catch {
      setUser(null)
      syncOrganizationId(null)
    }
  }, [])

  useEffect(() => {
    if (token && token !== 'demo') void refreshUser()
    else {
      setUser(null)
      syncOrganizationId(null)
    }
  }, [token, refreshUser])

  const login = useCallback(async (email: string, password: string) => {
    const res = await api.login(email, password)
    setToken(res.access_token)
    setTokenState(res.access_token)
    setUsingMock(false)
    let next: AuthUser | null = res.user ?? null
    if (!next) {
      try {
        next = await api.me()
      } catch {
        next = null
      }
    }
    setUser(next)
    syncOrganizationId(next)
    if (next?.role === 'super_admin' && !next.organization_id) {
      try {
        const orgs = await api.listOrganizations({ page_size: 1 })
        if (orgs.items[0]) setOrganizationId(orgs.items[0].id)
      } catch {
        /* ignore */
      }
    }
  }, [])

  const enterDemo = useCallback(() => {
    setToken(null)
    setTokenState('demo')
    syncOrganizationId(null)
    setUser({
      id: 'demo',
      email: 'demo@nexusec.local',
      full_name: 'Demo Analyst',
      role: 'soc_analyst',
      organization_id: null,
      is_active: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    })
    setUsingMock(true)
  }, [])

  const logout = useCallback(() => {
    setToken(null)
    setTokenState(null)
    setUser(null)
    syncOrganizationId(null)
    setUsingMock(false)
  }, [])

  const isAdmin =
    user?.role === 'admin' || user?.role === 'super_admin'

  const value = useMemo(
    () => ({
      token,
      user,
      usingMock,
      isAdmin,
      login,
      enterDemo,
      logout,
      setUsingMock,
      refreshUser,
    }),
    [token, user, usingMock, isAdmin, login, enterDemo, logout, refreshUser],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
