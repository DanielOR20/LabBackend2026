import { useEffect, useRef, useState } from 'react';
import { Eye, ShieldCheck, ShieldOff, Smartphone } from 'lucide-react';
import { api, formatError } from '../api/client.js';
import { useAuth } from '../context/AuthContext.jsx';
import { Alert, formatDate } from '../components/ui.jsx';

const REVEAL_SECONDS = 15;

export default function ProfileSecurityPage() {
  const { user, refreshUser } = useAuth();

  const [revealedPhone, setRevealedPhone] = useState('');
  const [phoneError, setPhoneError] = useState('');
  const [revealing, setRevealing] = useState(false);
  const timerRef = useRef(null);

  const [setup, setSetup] = useState(null);
  const [totpCode, setTotpCode] = useState('');
  const [mfaError, setMfaError] = useState('');
  const [mfaNotice, setMfaNotice] = useState('');
  const [mfaBusy, setMfaBusy] = useState(false);

  useEffect(() => () => clearTimeout(timerRef.current), []);

  const revealPhone = async () => {
    setPhoneError('');
    setRevealing(true);
    try {
      const data = await api.post('/auth/me/reveal-phone');
      setRevealedPhone(data.phone);
      clearTimeout(timerRef.current);
      timerRef.current = setTimeout(() => setRevealedPhone(''), REVEAL_SECONDS * 1000);
    } catch (err) {
      setPhoneError(formatError(err));
    } finally {
      setRevealing(false);
    }
  };

  const startSetup = async () => {
    setMfaError('');
    setMfaNotice('');
    setMfaBusy(true);
    try {
      const data = await api.post('/auth/mfa/setup');
      setSetup({ qrDataUrl: data.qrDataUrl, manualKey: data.manualKey });
      setTotpCode('');
    } catch (err) {
      setMfaError(formatError(err));
    } finally {
      setMfaBusy(false);
    }
  };

  const verifyMfa = async (event) => {
    event.preventDefault();
    setMfaError('');
    setMfaBusy(true);
    try {
      const data = await api.post('/auth/mfa/verify', { totpCode });
      setMfaNotice(data?.message || 'Autenticación 2FA activada correctamente.');
      setSetup(null);
      setTotpCode('');
      await refreshUser();
    } catch (err) {
      setMfaError(formatError(err));
    } finally {
      setMfaBusy(false);
    }
  };

  if (!user) return null;

  return (
    <div className="page">
      <header className="page-header">
        <div>
          <h1>Perfil y seguridad</h1>
          <p className="page-subtitle">Configuración de identidad corporativa, datos protegidos y segundo factor.</p>
        </div>
      </header>

      <section className="panel">
        <div className="panel-head">
          <div>
            <h2>Datos de la cuenta</h2>
            <p className="panel-head-sub">Metadatos registrados y acceso auditado a información sensible.</p>
          </div>
        </div>

        <div className="settings-list">
          <div className="setting-row">
            <span className="setting-label">Nombre completo</span>
            <span className="setting-value">{user.fullName}</span>
          </div>
          <div className="setting-row">
            <span className="setting-label">Correo electrónico</span>
            <span className="setting-value mono">{user.email}</span>
          </div>
          <div className="setting-row">
            <span className="setting-label">Empresa</span>
            <span className="setting-value">{user.companyName}</span>
          </div>
          <div className="setting-row">
            <span className="setting-label">Rol asignado</span>
            <span className="setting-value">
              <span className="badge mono">{user.role === 'admin' ? 'admin' : 'user'}</span>
            </span>
          </div>
          <div className="setting-row">
            <span className="setting-label">Fecha de registro</span>
            <span className="setting-value mono">{formatDate(user.createdAt)}</span>
          </div>
          <div className="setting-row">
            <span className="setting-label">Teléfono corporativo</span>
            <div className="setting-value">
              <Smartphone size={15} aria-hidden="true" />
              <code>{revealedPhone || user.maskedPhone}</code>
              {!revealedPhone && (
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={revealPhone}
                  disabled={revealing}
                >
                  <Eye size={14} aria-hidden="true" />
                  {revealing ? 'Solicitando…' : 'Revelar dato auditado'}
                </button>
              )}
            </div>
          </div>
        </div>

        {(revealedPhone || phoneError) && (
          <div className="panel-body">
            {revealedPhone && (
              <Alert kind="info">
                Dato revelado y registrado en la bitácora de auditoría. Se ocultará automáticamente en {REVEAL_SECONDS} segundos.
              </Alert>
            )}
            <Alert kind="error">{phoneError}</Alert>
          </div>
        )}
      </section>

      <section className="panel">
        <div className="panel-head">
          <div>
            <h2>Autenticación en dos pasos (2FA TOTP)</h2>
            <p className="panel-head-sub">Protección adicional mediante código temporal de 6 dígitos.</p>
          </div>
          {user.totpEnabled ? (
            <span className="badge badge-ok">
              <ShieldCheck size={14} aria-hidden="true" /> Activado
            </span>
          ) : (
            <span className="badge badge-warn">
              <ShieldOff size={14} aria-hidden="true" /> Desactivado
            </span>
          )}
        </div>

        <div className="panel-body">
          <Alert kind="success">{mfaNotice}</Alert>
          <Alert kind="error">{mfaError}</Alert>

          {user.totpEnabled ? (
            <p className="muted">
              Tu cuenta solicita un código de verificación de tu aplicación autenticadora en cada inicio de sesión.
            </p>
          ) : !setup ? (
            <>
              <p className="muted">
                Vincula una aplicación autenticadora (Google Authenticator, Authy o 1Password) para exigir un segundo factor al iniciar sesión.
              </p>
              <div>
                <button type="button" className="btn btn-primary" onClick={startSetup} disabled={mfaBusy}>
                  {mfaBusy ? 'Generando…' : 'Activar 2FA'}
                </button>
              </div>
            </>
          ) : (
            <div className="mfa-setup">
              <div className="qr-frame">
                <img
                  src={setup.qrDataUrl}
                  alt="Código QR para configurar la aplicación autenticadora"
                  width="184"
                  height="184"
                />
              </div>
              <form onSubmit={verifyMfa} className="form mfa-form">
                <p className="muted">Escanea el código QR o registra esta clave secreta manualmente:</p>
                <code className="manual-key">{setup.manualKey}</code>
                <label className="field">
                  <span>Código de verificación (6 dígitos)</span>
                  <input
                    type="text"
                    className="mono"
                    inputMode="numeric"
                    pattern="\d{6}"
                    maxLength={6}
                    required
                    autoComplete="one-time-code"
                    value={totpCode}
                    onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  />
                </label>
                <div className="modal-actions">
                  <button type="button" className="btn btn-secondary" onClick={() => setSetup(null)}>
                    Cancelar
                  </button>
                  <button type="submit" className="btn btn-primary" disabled={mfaBusy || totpCode.length !== 6}>
                    {mfaBusy ? 'Verificando…' : 'Verificar y activar'}
                  </button>
                </div>
              </form>
            </div>
          )}
        </div>
      </section>
    </div>
  );
}
