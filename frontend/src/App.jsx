import { useState } from 'react';
import { ShieldCheck } from 'lucide-react';
import { useAuth } from './context/AuthContext.jsx';
import { TopNav } from './components/ui.jsx';
import AuthPage from './pages/AuthPage.jsx';
import VaultPage from './pages/VaultPage.jsx';
import ProfileSecurityPage from './pages/ProfileSecurityPage.jsx';
import AdminSecurityPage from './pages/AdminSecurityPage.jsx';

export default function App() {
  const { user, loading, logout, isAdmin } = useAuth();
  const [view, setView] = useState('vault');

  if (loading) {
    return (
      <div className="splash" role="status">
        <ShieldCheck size={24} aria-hidden="true" />
        <p>Verificando sesión segura…</p>
      </div>
    );
  }

  if (!user) {
    return <AuthPage />;
  }

  const currentView = view === 'admin' && !isAdmin ? 'vault' : view;

  return (
    <div className="app-shell">
      <TopNav
        user={user}
        isAdmin={isAdmin}
        currentView={currentView}
        onSelectView={setView}
        onLogout={logout}
      />

      <main className="workspace">
        {currentView === 'vault' && <VaultPage />}
        {currentView === 'profile' && <ProfileSecurityPage />}
        {currentView === 'admin' && <AdminSecurityPage />}
      </main>
    </div>
  );
}
