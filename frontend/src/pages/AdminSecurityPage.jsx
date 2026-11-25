import { useCallback, useEffect, useState } from 'react';
import { KeyRound, LockOpen, RefreshCw, ShieldAlert, Users } from 'lucide-react';
import { api, formatError } from '../api/client.js';
import { useAuth } from '../context/AuthContext.jsx';
import { Alert, Modal, formatDate } from '../components/ui.jsx';

const EVENT_TYPES = [
  'LOGIN_SUCCESS',
  'LOGIN_FAILED',
  'LOGIN_BLOCKED_LOCKOUT',
  'BRUTE_FORCE_LOCKOUT',
  'MFA_FAILED',
  'MFA_ENABLED',
  'IDOR_ATTEMPT_BLOCKED',
  'UNAUTHORIZED_ADMIN_ACCESS',
  'RATE_LIMIT_EXCEEDED',
  'CSRF_VALIDATION_FAILED',
  'USER_REGISTERED',
  'USER_ROLE_CHANGED',
  'USER_ACCOUNT_UNLOCKED',
  'SENSITIVE_DATA_REVEALED',
  'PASSWORD_RESET_REQUESTED',
  'PASSWORD_RESET_SUCCESS',
  'NOTE_CREATED',
  'NOTE_UPDATED',
  'NOTE_DELETED',
  'CRYPTO_KEY_ROTATION',
  'LOGOUT'
];

function Metric({ label, value, tone = 'default' }) {
  return (
    <div className={`card metric metric-${tone}`}>
      <span className="metric-label">{label}</span>
      <strong className="metric-value">{value}</strong>
    </div>
  );
}

function OverviewTab() {
  const [data, setData] = useState(null);
  const [error, setError] = useState('');
  const [confirmRotate, setConfirmRotate] = useState(false);
  const [rotating, setRotating] = useState(false);
  const [rotation, setRotation] = useState(null);

  const load = useCallback(async () => {
    setError('');
    try {
      setData(await api.get('/admin/overview'));
    } catch (err) {
      setError(formatError(err));
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const rotate = async () => {
    setRotating(true);
    setError('');
    try {
      const result = await api.post('/admin/rotate-keys');
      setRotation(result);
      setConfirmRotate(false);
      await load();
    } catch (err) {
      setError(formatError(err));
      setConfirmRotate(false);
    } finally {
      setRotating(false);
    }
  };

  if (!data) {
    return error ? <Alert kind="error">{error}</Alert> : <p className="muted">Cargando métricas…</p>;
  }

  const { users, vault, securityLast24h } = data;
  const sev = securityLast24h.bySeverity;

  return (
    <>
      <Alert kind="error">{error}</Alert>
      <div className="metrics-grid">
        <Metric label="Usuarios registrados" value={users.total} />
        <Metric label="Administradores" value={users.admins} />
        <Metric label="Usuarios con MFA" value={users.mfaEnabled} tone="ok" />
        <Metric label="Cuentas bloqueadas" value={users.locked} tone={users.locked > 0 ? 'warn' : 'default'} />
        <Metric label="Notas cifradas" value={vault.totalNotes} />
        <Metric label="Alertas críticas (24h)" value={sev.critical} tone={sev.critical > 0 ? 'danger' : 'default'} />
        <Metric label="Warnings (24h)" value={sev.warning} tone={sev.warning > 0 ? 'warn' : 'default'} />
        <Metric label="Info (24h)" value={sev.info} />
      </div>

      <div className="two-col">
        <section className="card section">
          <h2>Distribución por versión de llave</h2>
          <p className="muted small">Llave activa: <strong>v{vault.activeKeyVersion}</strong></p>
          <table className="table">
            <thead>
              <tr><th>Tipo</th><th>Versión</th><th>Registros</th></tr>
            </thead>
            <tbody>
              {vault.notesByKeyVersion.map((row) => (
                <tr key={`n-${row.keyVersion}`}>
                  <td>Notas</td>
                  <td>v{row.keyVersion}{row.keyVersion === vault.activeKeyVersion ? ' (activa)' : ''}</td>
                  <td>{row.count}</td>
                </tr>
              ))}
              {vault.phonesByKeyVersion.map((row) => (
                <tr key={`p-${row.keyVersion}`}>
                  <td>Teléfonos</td>
                  <td>v{row.keyVersion}{row.keyVersion === vault.activeKeyVersion ? ' (activa)' : ''}</td>
                  <td>{row.count}</td>
                </tr>
              ))}
              {vault.notesByKeyVersion.length === 0 && vault.phonesByKeyVersion.length === 0 && (
                <tr><td colSpan={3} className="muted">Sin registros.</td></tr>
              )}
            </tbody>
          </table>

          <div className="rotate-box">
            <button type="button" className="btn btn-danger" onClick={() => setConfirmRotate(true)}>
              <KeyRound size={16} aria-hidden="true" /> Rotar llaves de cifrado
            </button>
          </div>
          {rotation && (
            <Alert kind="success">
              {`${rotation.message} — Notas: ${rotation.notesRotated} · Teléfonos: ${rotation.phonesRotated} · Secretos TOTP: ${rotation.totpSecretsRotated} migrados a la llave v${rotation.activeKeyVersion}.`}
            </Alert>
          )}
        </section>

        <section className="card section">
          <h2>Eventos de seguridad (24h)</h2>
          <table className="table">
            <thead>
              <tr><th>Evento</th><th>Cantidad</th></tr>
            </thead>
            <tbody>
              {securityLast24h.byEventType.map((row) => (
                <tr key={row.eventType}><td><code>{row.eventType}</code></td><td>{row.count}</td></tr>
              ))}
              {securityLast24h.byEventType.length === 0 && (
                <tr><td colSpan={2} className="muted">Sin eventos recientes.</td></tr>
              )}
            </tbody>
          </table>
        </section>
      </div>

      {confirmRotate && (
        <Modal title="Confirmar rotación de llaves" size="sm" onClose={() => setConfirmRotate(false)}>
          <p>
            Se re-cifrarán en una transacción atómica todas las notas, teléfonos y secretos TOTP que no usen la llave activa
            (v{vault.activeKeyVersion}). Asegúrate de que la llave activa esté configurada en el servidor.
          </p>
          <div className="modal-actions">
            <button type="button" className="btn btn-ghost" onClick={() => setConfirmRotate(false)}>Cancelar</button>
            <button type="button" className="btn btn-danger" onClick={rotate} disabled={rotating}>
              {rotating ? 'Rotando…' : 'Ejecutar rotación'}
            </button>
          </div>
        </Modal>
      )}
    </>
  );
}

function UsersTab() {
  const { user: me } = useAuth();
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busyId, setBusyId] = useState('');

  const load = useCallback(async () => {
    setError('');
    try {
      const data = await api.get('/admin/users');
      setUsers(data.users || []);
    } catch (err) {
      setError(formatError(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const changeRole = async (target, role) => {
    if (role === target.role) return;
    setBusyId(target.id);
    setError('');
    setNotice('');
    try {
      await api.patch(`/admin/users/${target.id}/role`, { role });
      setNotice(`Rol de ${target.email} actualizado. Sus sesiones activas fueron invalidadas.`);
      await load();
    } catch (err) {
      setError(formatError(err));
    } finally {
      setBusyId('');
    }
  };

  const unlock = async (target) => {
    setBusyId(target.id);
    setError('');
    setNotice('');
    try {
      await api.patch(`/admin/users/${target.id}/unlock`);
      setNotice(`Cuenta de ${target.email} desbloqueada.`);
      await load();
    } catch (err) {
      setError(formatError(err));
    } finally {
      setBusyId('');
    }
  };

  const isLocked = (u) => u.lockedUntil && new Date(u.lockedUntil) > new Date();

  return (
    <section className="card section">
      <h2>Gestión de usuarios</h2>
      <Alert kind="error">{error}</Alert>
      <Alert kind="success">{notice}</Alert>
      {loading ? (
        <p className="muted">Cargando usuarios…</p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Correo</th><th>Empresa</th><th>Teléfono</th><th>MFA</th>
                <th>Intentos</th><th>Rol</th><th>Estado</th><th>Acciones</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id}>
                  <td>{u.email}</td>
                  <td>{u.companyName}</td>
                  <td><code>{u.maskedPhone}</code></td>
                  <td>{u.totpEnabled ? <span className="chip chip-ok">Activo</span> : <span className="chip">No</span>}</td>
                  <td>{u.failedAttempts}</td>
                  <td>
                    <select
                      value={u.role}
                      disabled={u.id === me?.id || busyId === u.id}
                      onChange={(e) => changeRole(u, e.target.value)}
                      aria-label={`Rol de ${u.email}`}
                    >
                      <option value="user">user</option>
                      <option value="admin">admin</option>
                    </select>
                  </td>
                  <td>{isLocked(u) ? <span className="chip chip-warn">Bloqueada</span> : <span className="chip chip-ok">Activa</span>}</td>
                  <td>
                    {isLocked(u) && (
                      <button type="button" className="btn btn-ghost btn-sm" onClick={() => unlock(u)} disabled={busyId === u.id}>
                        <LockOpen size={14} aria-hidden="true" /> Desbloquear
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function LogsTab() {
  const [logs, setLogs] = useState([]);
  const [severity, setSeverity] = useState('');
  const [eventType, setEventType] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    setError('');
    setLoading(true);
    try {
      const data = await api.get('/admin/logs', { severity, eventType });
      setLogs(data.logs || []);
    } catch (err) {
      setError(formatError(err));
    } finally {
      setLoading(false);
    }
  }, [severity, eventType]);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <section className="card section">
      <div className="section-head">
        <h2>Bitácora de auditoría</h2>
        <button type="button" className="btn btn-ghost btn-sm" onClick={load}>
          <RefreshCw size={14} aria-hidden="true" /> Actualizar
        </button>
      </div>
      <div className="filters">
        <select value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Filtrar por severidad">
          <option value="">Todas las severidades</option>
          <option value="info">info</option>
          <option value="warning">warning</option>
          <option value="critical">critical</option>
        </select>
        <select value={eventType} onChange={(e) => setEventType(e.target.value)} aria-label="Filtrar por tipo de evento">
          <option value="">Todos los eventos</option>
          {EVENT_TYPES.map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
      </div>
      <Alert kind="error">{error}</Alert>
      {loading ? (
        <p className="muted">Cargando bitácora…</p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr><th>Fecha</th><th>Severidad</th><th>Evento</th><th>Actor</th><th>IP</th><th>Detalles</th></tr>
            </thead>
            <tbody>
              {logs.map((log) => (
                <tr key={log.id}>
                  <td className="nowrap">{formatDate(log.created_at)}</td>
                  <td><span className={`chip sev-${log.severity}`}>{log.severity}</span></td>
                  <td><code>{log.event_type}</code></td>
                  <td>{log.actor_email || '—'}</td>
                  <td>{log.ip_address || '—'}</td>
                  <td>
                    <pre className="json">{JSON.stringify(log.details ?? {})}</pre>
                  </td>
                </tr>
              ))}
              {logs.length === 0 && (
                <tr><td colSpan={6} className="muted">Sin registros para los filtros seleccionados.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

export default function AdminSecurityPage() {
  const { isAdmin } = useAuth();
  const [tab, setTab] = useState('overview');

  if (!isAdmin) {
    return (
      <div className="page">
        <Alert kind="error">Acceso denegado. Se requiere rol de administrador.</Alert>
      </div>
    );
  }

  return (
    <div className="page">
      <header className="page-header">
        <div>
          <h1>Centro de seguridad</h1>
          <p className="muted">Métricas, usuarios, auditoría y gestión criptográfica.</p>
        </div>
      </header>

      <div className="tabs tabs-light" role="tablist">
        <button type="button" role="tab" aria-selected={tab === 'overview'} className={tab === 'overview' ? 'tab active' : 'tab'} onClick={() => setTab('overview')}>
          <ShieldAlert size={16} aria-hidden="true" /> Resumen
        </button>
        <button type="button" role="tab" aria-selected={tab === 'users'} className={tab === 'users' ? 'tab active' : 'tab'} onClick={() => setTab('users')}>
          <Users size={16} aria-hidden="true" /> Usuarios
        </button>
        <button type="button" role="tab" aria-selected={tab === 'logs'} className={tab === 'logs' ? 'tab active' : 'tab'} onClick={() => setTab('logs')}>
          <KeyRound size={16} aria-hidden="true" /> Bitácora
        </button>
      </div>

      {tab === 'overview' && <OverviewTab />}
      {tab === 'users' && <UsersTab />}
      {tab === 'logs' && <LogsTab />}
    </div>
  );
}
