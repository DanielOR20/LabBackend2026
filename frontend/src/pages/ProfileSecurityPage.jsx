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

  const [setup, setSetup] = useState(null); // { qrDataUrl, manualKey }
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
          <p className="muted">Datos de tu cuenta y protección de acceso.</p>
        </div>
      </header>

      <section className="card section">
        <h2>Datos de la cuenta</h2>
        <dl className="kv">
          <div><dt>Nombre</dt><dd>{user.fullName}</dd></div>
          <div><dt>Correo</dt><dd>{user.email}</dd></div>
          <div><dt>Empresa</dt><dd>{user.companyName}</dd></div>
          <div><dt>Rol</dt><dd>{user.role === 'admin' ? 'Administrador' : 'Usuario'}</dd></div>
          <div><dt>Miembro desde</dt><dd>{formatDate(user.createdAt)}</dd></div>
          <div>
            <dt>Teléfono corporativo</dt>
            <dd className="phone-row">
              <Smartphone size={16} aria-hidden="true" />
              <code>{revealedPhone || user.maskedPhone}</code>
              {!revealedPhone && (
                <button type="button" className="btn btn-ghost btn-sm" onClick={revealPhone} disabled={revealing}>
                  <Eye size={14} aria-hidden="true" /> {revealing ? 'Solicitando…' : 'Revelar dato auditado'}
                </button>
              )}
            </dd>
          </div>
        </dl>
        {revealedPhone && (
          <Alert kind="info">
            Dato revelado y registrado en la bitácora de auditoría. Se ocultará automáticamente en {REVEAL_SECONDS} segundos.
          </Alert>
        )}
        <Alert kind="error">{phoneError}</Alert>
      </section>

      <section className="card section">
        <h2>Autenticación en dos pasos (TOTP)</h2>
        <div className="mfa-status">
          {user.totpEnabled ? (
            <span className="chip chip-ok"><ShieldCheck size={14} aria-hidden="true" /> 2FA activado</span>
          ) : (
            <span className="chip chip-warn"><ShieldOff size={14} aria-hidden="true" /> 2FA desactivado</span>
          )}
        </div>

        <Alert kind="success">{mfaNotice}</Alert>
        <Alert kind="error">{mfaError}</Alert>

        {user.totpEnabled ? (
          <p className="muted">Tu cuenta solicitará un código de tu aplicación autenticadora en cada inicio de sesión.</p>
        ) : !setup ? (
          <>
            <p className="muted">Protege tu bóveda con un segundo factor usando Google Authenticator, Authy o similar.</p>
            <button type="button" className="btn btn-primary" onClick={startSetup} disabled={mfaBusy}>
              {mfaBusy ? 'Generando…' : 'Activar 2FA'}
            </button>
          </>
        ) : (
          <div className="mfa-setup">
            <div className="qr-box">
              <img src={setup.qrDataUrl} alt="Código QR para configurar la aplicación autenticadora" width="200" height="200" />
            </div>
            <form onSubmit={verifyMfa} className="form">
              <p className="muted">Escanea el código QR o ingresa esta clave manualmente:</p>
              <code className="manual-key">{setup.manualKey}</code>
              <label className="field">
                <span>Código de 6 dígitos</span>
                <input
                  type="text"
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
                <button type="button" className="btn btn-ghost" onClick={() => setSetup(null)}>Cancelar</button>
                <button type="submit" className="btn btn-primary" disabled={mfaBusy || totpCode.length !== 6}>
                  {mfaBusy ? 'Verificando…' : 'Verificar y activar'}
                </button>
              </div>
            </form>
          </div>
        )}
      </section>
    </div>
  );
}
