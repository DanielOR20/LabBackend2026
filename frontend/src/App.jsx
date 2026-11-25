import { useState } from 'react';
import { LogOut, ShieldCheck, ShieldHalf, UserCircle, Vault } from 'lucide-react';
import { useAuth } from './context/AuthContext.jsx';
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
        <ShieldCheck size={32} aria-hidden="true" />
        <p>Verificando sesión segura…</p>
      </div>
    );
  }

  if (!user) {
    return <AuthPage />;
  }

  const currentView = view === 'admin' && !isAdmin ? 'vault' : view;

  const navItem = (id, label, Icon) => (
    <button
      type="button"
      className={currentView === id ? 'nav-item active' : 'nav-item'}
      onClick={() => setView(id)}
      aria-current={currentView === id ? 'page' : undefined}
    >
      <Icon size={18} aria-hidden="true" />
      <span>{label}</span>
    </button>
  );

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand-mark">
          <ShieldCheck size={24} aria-hidden="true" />
          <span>SecureVault</span>
        </div>
        <nav className="nav" aria-label="Navegación principal">
          {navItem('vault', 'Bóveda', Vault)}
          {navItem('profile', 'Perfil y seguridad', UserCircle)}
          {isAdmin && navItem('admin', 'Centro de seguridad', ShieldHalf)}
        </nav>
        <div className="sidebar-foot">
          <span className="enc-indicator">
            <span className="enc-dot" aria-hidden="true" /> Cifrado activo
          </span>
        </div>
      </aside>

      <div className="main">
        <header className="topbar">
          <div className="topbar-user">
            <strong>{user.fullName}</strong>
            <span>{user.companyName}</span>
          </div>
          <button type="button" className="btn btn-topbar" onClick={logout}>
            <LogOut size={16} aria-hidden="true" /> Cerrar sesión
          </button>
        </header>
        <div className="workspace">
          {currentView === 'vault' && <VaultPage />}
          {currentView === 'profile' && <ProfileSecurityPage />}
          {currentView === 'admin' && <AdminSecurityPage />}
        </div>
      </div>
    </div>
  );
}
