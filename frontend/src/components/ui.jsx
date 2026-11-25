import { useEffect } from 'react';
import { AlertTriangle, CheckCircle2, Info, LogOut, ShieldCheck, ShieldHalf, User, Vault, X } from 'lucide-react';

export function BrandMark() {
  return (
    <span className="brand-mark">
      <span className="brand-icon" aria-hidden="true">
        <ShieldCheck size={16} />
      </span>
      <span>SecureVault</span>
    </span>
  );
}

const NAV_TABS = [
  { id: 'vault', label: 'Bóveda', shortLabel: 'Bóveda', Icon: Vault },
  { id: 'profile', label: 'Perfil y seguridad', shortLabel: 'Perfil', Icon: User },
  { id: 'admin', label: 'Centro de seguridad', shortLabel: 'Seguridad', Icon: ShieldHalf, adminOnly: true }
];

export function TopNav({ user, isAdmin, currentView, onSelectView, onLogout }) {
  const visibleTabs = NAV_TABS.filter((item) => !item.adminOnly || isAdmin);

  return (
    <header className="topbar">
      <div className="topbar-inner">
        <div className="topbar-brand">
          <BrandMark />
        </div>

        <nav className="topbar-nav" aria-label="Navegación principal">
          {visibleTabs.map(({ id, label, shortLabel, Icon }) => (
            <button
              key={id}
              type="button"
              className={currentView === id ? 'topnav-item active' : 'topnav-item'}
              onClick={() => onSelectView(id)}
              aria-current={currentView === id ? 'page' : undefined}
              aria-label={label}
            >
              <Icon size={15} aria-hidden="true" />
              <span className="label-full">{label}</span>
              <span className="label-short" aria-hidden="true">{shortLabel}</span>
            </button>
          ))}
        </nav>

        <div className="topbar-actions">
          <span className="crypto-status" title="Cifrado autenticado AES-256-GCM activo">
            <span className="status-dot" aria-hidden="true" />
            <span className="label-full">AES-256-GCM</span>
            <span className="label-short" aria-hidden="true">AES-256</span>
          </span>
          <div className="user-pill">
            <span className="user-name" title={user.fullName}>{user.fullName}</span>
            <span className="role-badge">{user.role}</span>
          </div>
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={onLogout}
            aria-label="Cerrar sesión"
          >
            <LogOut size={14} aria-hidden="true" />
            <span className="label-full">Cerrar sesión</span>
            <span className="label-short" aria-hidden="true">Salir</span>
          </button>
        </div>
      </div>
    </header>
  );
}

export function Alert({ kind = 'error', children }) {
  if (!children) return null;
  const Icon = kind === 'success' ? CheckCircle2 : kind === 'info' ? Info : AlertTriangle;
  return (
    <div className={`alert alert-${kind}`} role={kind === 'error' ? 'alert' : 'status'}>
      <Icon size={16} aria-hidden="true" />
      <span>{children}</span>
    </div>
  );
}

export function Modal({ title, onClose, children, footer, size = 'md' }) {
  useEffect(() => {
    const onKey = (event) => {
      if (event.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [onClose]);

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={onClose}>
      <div
        className={size === 'sm' ? 'modal modal-sm' : 'modal'}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        onMouseDown={(event) => event.stopPropagation()}
      >
        <header className="modal-header">
          <h2>{title}</h2>
          <button type="button" className="icon-btn" onClick={onClose} aria-label="Cerrar">
            <X size={16} />
          </button>
        </header>
        <div className="modal-body">{children}</div>
        {footer ? <footer className="modal-footer">{footer}</footer> : null}
      </div>
    </div>
  );
}

export const formatDate = (value) => {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleString('es-MX', { dateStyle: 'medium', timeStyle: 'short' });
};
