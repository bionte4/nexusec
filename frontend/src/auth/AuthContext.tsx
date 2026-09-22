import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from 'react'
import { api, getToken, setToken } from '../api/client'

interface AuthState {
  token: string | null
  usingMock: boolean
  login: (email: string, password: string) => Promise<void>
  enterDemo: () => void
  logout: () => void
  setUsingMock: (v: boolean) => void
}

const AuthContext = createContext<AuthState | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setTokenState] = useState<string | null>(() => getToken())
  const [usingMock, setUsingMock] = useState(false)

  const login = useCallback(async (email: string, password: string) => {
    const res = await api.login(email, password)
    setToken(res.access_token)
    setTokenState(res.access_token)
    setUsingMock(false)
  }, [])

  const enterDemo = useCallback(() => {
    setToken(null)
    setTokenState('demo')
    setUsingMock(true)
  }, [])

  const logout = useCallback(() => {
    setToken(null)
    setTokenState(null)
    setUsingMock(false)
  }, [])

  const value = useMemo(
    () => ({
      token,
      usingMock,
      login,
      enterDemo,
      logout,
      setUsingMock,
    }),
    [token, usingMock, login, enterDemo, logout],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
