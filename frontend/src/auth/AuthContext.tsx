import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'
import { api, getToken, setToken } from '../api/client'
import type { AuthUser } from '../api/types'

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
    } catch {
      setUser(null)
    }
  }, [])

  useEffect(() => {
    if (token && token !== 'demo') void refreshUser()
    else setUser(null)
  }, [token, refreshUser])

  const login = useCallback(async (email: string, password: string) => {
    const res = await api.login(email, password)
    setToken(res.access_token)
    setTokenState(res.access_token)
    setUsingMock(false)
    if (res.user) setUser(res.user)
    else {
      try {
        setUser(await api.me())
      } catch {
        setUser(null)
      }
    }
  }, [])

  const enterDemo = useCallback(() => {
    setToken(null)
    setTokenState('demo')
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
