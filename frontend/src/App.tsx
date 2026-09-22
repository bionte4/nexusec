import type { ReactNode } from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'
import { AuthProvider, useAuth } from './auth/AuthContext'
import { AppShell } from './components/AppShell'
import { DashboardPage } from './pages/DashboardPage'
import { LoginPage } from './pages/LoginPage'
import { SocChatPage } from './pages/SocChatPage'
import { VulnerabilitiesPage } from './pages/VulnerabilitiesPage'
import { VulnerabilityDetailPage } from './pages/VulnerabilityDetailPage'

function Protected({ children }: { children: ReactNode }) {
  const { token } = useAuth()
  if (!token) return <Navigate to="/login" replace />
  return children
}

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route
          element={
            <Protected>
              <AppShell />
            </Protected>
          }
        >
          <Route index element={<DashboardPage />} />
          <Route path="vulnerabilities" element={<VulnerabilitiesPage />} />
          <Route
            path="vulnerabilities/:id"
            element={<VulnerabilityDetailPage />}
          />
          <Route path="soc-chat" element={<SocChatPage />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AuthProvider>
  )
}
