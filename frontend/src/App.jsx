import { useState } from 'react';
import { LogOut, ShieldCheck, ShieldHalf, User, Vault } from 'lucide-react';
import { useAuth } from './context/AuthContext.jsx';
import { BrandMark } from './components/ui.jsx';
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

  const navTab = (id, label, Icon) => (
    <button
      type="button"
      className={currentView === id ? 'topnav-item active' : 'topnav-item'}
      onClick={() => setView(id)}
      aria-current={currentView === id ? 'page' : undefined}
    >
      <Icon size={15} aria-hidden="true" />
      <span>{label}</span>
    </button>
  );

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="topbar-inner">
          <div className="topbar-left">
            <BrandMark />
            <nav className="topnav" aria-label="Navegación principal">
              {navTab('vault', 'Bóveda', Vault)}
              {navTab('profile', 'Perfil y seguridad', User)}
              {isAdmin && navTab('admin', 'Centro de seguridad', ShieldHalf)}
            </nav>
          </div>

          <div className="topbar-right">
            <span className="crypto-status" title="Cifrado autenticado activo">
              <span className="status-dot" aria-hidden="true" />
              AES-256-GCM · Activo
            </span>
            <div className="user-pill">
              <span className="user-name">{user.fullName}</span>
              <span className="role-badge">{user.role}</span>
            </div>
            <button type="button" className="btn btn-secondary btn-sm" onClick={logout}>
              <LogOut size={14} aria-hidden="true" /> Cerrar sesión
            </button>
          </div>
        </div>
      </header>

      <main className="workspace">
        {currentView === 'vault' && <VaultPage />}
        {currentView === 'profile' && <ProfileSecurityPage />}
        {currentView === 'admin' && <AdminSecurityPage />}
      </main>
    </div>
  );
}
