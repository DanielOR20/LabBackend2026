import { useMemo, useState } from 'react';
import { KeyRound, Lock, ShieldCheck, UserPlus } from 'lucide-react';
import { api, formatError } from '../api/client.js';
import { useAuth } from '../context/AuthContext.jsx';
import { Alert } from '../components/ui.jsx';

const PASSWORD_RULES = [
  { id: 'len', label: 'Mínimo 10 caracteres', test: (v) => v.length >= 10 },
  { id: 'upper', label: 'Una mayúscula', test: (v) => /[A-Z]/.test(v) },
  { id: 'lower', label: 'Una minúscula', test: (v) => /[a-z]/.test(v) },
  { id: 'digit', label: 'Un número', test: (v) => /[0-9]/.test(v) },
  { id: 'symbol', label: 'Un símbolo', test: (v) => /[^A-Za-z0-9]/.test(v) }
];

function PasswordStrength({ value }) {
  const results = useMemo(
    () => PASSWORD_RULES.map((rule) => ({ ...rule, ok: rule.test(value) })),
    [value]
  );
  const score = results.filter((r) => r.ok).length;
  const level = score <= 2 ? 'weak' : score <= 4 ? 'medium' : 'strong';
  const label = level === 'weak' ? 'Débil' : level === 'medium' ? 'Media' : 'Fuerte';

  return (
    <div className="pw-strength" aria-live="polite">
      <div className="pw-bar">
        <span className={`pw-bar-fill pw-${level} pw-w${score}`} />
      </div>
      <p className="pw-label">
        Complejidad: <strong>{value ? label : '—'}</strong>
      </p>
      <ul className="pw-rules">
        {results.map((rule) => (
          <li key={rule.id} className={rule.ok ? 'ok' : ''}>
            {rule.ok ? '✓' : '○'} {rule.label}
          </li>
        ))}
      </ul>
    </div>
  );
}

const isPasswordValid = (value) => PASSWORD_RULES.every((rule) => rule.test(value));

function getInitialMode() {
  if (window.location.pathname === '/reset-password') return 'reset';
  return 'login';
}

function getInitialToken() {
  const params = new URLSearchParams(window.location.search);
  return params.get('token') || '';
}

export default function AuthPage() {
  const { login } = useAuth();
  const [mode, setMode] = useState(getInitialMode);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [busy, setBusy] = useState(false);

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [mfaRequired, setMfaRequired] = useState(false);
  const [totpCode, setTotpCode] = useState('');

  const [fullName, setFullName] = useState('');
  const [companyName, setCompanyName] = useState('');
  const [phone, setPhone] = useState('');

  const [resetToken, setResetToken] = useState(getInitialToken);
  const [newPassword, setNewPassword] = useState('');

  const switchMode = (next) => {
    setMode(next);
    setError('');
    setSuccess('');
    setMfaRequired(false);
    setTotpCode('');
    if (window.location.pathname === '/reset-password') {
      window.history.replaceState(null, '', '/');
    }
  };

  const handleLogin = async (event) => {
    event.preventDefault();
    setError('');
    setBusy(true);
    try {
      const result = await login({ email, password, totpCode: mfaRequired ? totpCode : undefined });
      if (result.mfaRequired) {
        setMfaRequired(true);
        setSuccess('Ingrese el código de verificación 2FA de su aplicación autenticadora.');
      }
    } catch (err) {
      setSuccess('');
      setError(
        err.status === 429
          ? `${err.message} Espere unos minutos antes de volver a intentarlo.`
          : formatError(err)
      );
    } finally {
      setBusy(false);
    }
  };

  const handleRegister = async (event) => {
    event.preventDefault();
    setError('');
    setSuccess('');
    if (!isPasswordValid(password)) {
      setError('La contraseña no cumple la política de complejidad.');
      return;
    }
    setBusy(true);
    try {
      await api.post('/auth/register', { email, fullName, companyName, phone, password });
      setPassword('');
      setMode('login');
      setSuccess('Cuenta creada correctamente. Ya puedes iniciar sesión.');
    } catch (err) {
      setError(formatError(err));
    } finally {
      setBusy(false);
    }
  };

  const handleForgot = async (event) => {
    event.preventDefault();
    setError('');
    setSuccess('');
    setBusy(true);
    try {
      const data = await api.post('/auth/forgot-password', { email });
      setSuccess(data?.message || 'Solicitud enviada.');
    } catch (err) {
      setError(formatError(err));
    } finally {
      setBusy(false);
    }
  };

  const handleReset = async (event) => {
    event.preventDefault();
    setError('');
    setSuccess('');
    if (!isPasswordValid(newPassword)) {
      setError('La nueva contraseña no cumple la política de complejidad.');
      return;
    }
    setBusy(true);
    try {
      await api.post('/auth/reset-password', { token: resetToken.trim(), newPassword });
      setNewPassword('');
      setResetToken('');
      setMode('login');
      window.history.replaceState(null, '', '/');
      setSuccess('Contraseña restablecida. Inicia sesión con tu nueva contraseña.');
    } catch (err) {
      setError(formatError(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="auth-layout">
      <section className="auth-brand">
        <div className="brand-mark">
          <ShieldCheck size={28} aria-hidden="true" />
          <span>SecureVault</span>
        </div>
        <h1>Bóveda corporativa de información confidencial</h1>
        <ul className="brand-points">
          <li><Lock size={16} aria-hidden="true" /> Cifrado AES-256-GCM en reposo</li>
          <li><KeyRound size={16} aria-hidden="true" /> Autenticación con 2FA (TOTP)</li>
          <li><ShieldCheck size={16} aria-hidden="true" /> Auditoría de seguridad completa</li>
        </ul>
      </section>

      <section className="auth-card card">
        <div className="tabs" role="tablist">
          <button type="button" role="tab" aria-selected={mode === 'login'} className={mode === 'login' ? 'tab active' : 'tab'} onClick={() => switchMode('login')}>
            Iniciar sesión
          </button>
          <button type="button" role="tab" aria-selected={mode === 'register'} className={mode === 'register' ? 'tab active' : 'tab'} onClick={() => switchMode('register')}>
            Crear cuenta
          </button>
          <button type="button" role="tab" aria-selected={mode === 'forgot' || mode === 'reset'} className={mode === 'forgot' || mode === 'reset' ? 'tab active' : 'tab'} onClick={() => switchMode('forgot')}>
            Recuperar
          </button>
        </div>

        <Alert kind="error">{error}</Alert>
        <Alert kind="success">{success}</Alert>

        {mode === 'login' && (
          <form onSubmit={handleLogin} className="form" autoComplete="on">
            <label className="field">
              <span>Correo electrónico</span>
              <input type="email" required autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} readOnly={mfaRequired} />
            </label>
            <label className="field">
              <span>Contraseña</span>
              <input type="password" required autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} readOnly={mfaRequired} />
            </label>
            {mfaRequired && (
              <label className="field">
                <span>Código 2FA (6 dígitos)</span>
                <input
                  type="text"
                  inputMode="numeric"
                  pattern="\d{6}"
                  maxLength={6}
                  required
                  autoFocus
                  autoComplete="one-time-code"
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                />
              </label>
            )}
            <button type="submit" className="btn btn-primary" disabled={busy}>
              {busy ? 'Verificando…' : mfaRequired ? 'Verificar y entrar' : 'Entrar'}
            </button>
            {mfaRequired && (
              <button type="button" className="btn btn-ghost" onClick={() => { setMfaRequired(false); setTotpCode(''); setSuccess(''); }}>
                Cambiar credenciales
              </button>
            )}
          </form>
        )}

        {mode === 'register' && (
          <form onSubmit={handleRegister} className="form" autoComplete="on">
            <label className="field">
              <span>Nombre completo</span>
              <input type="text" required minLength={2} maxLength={120} autoComplete="name" value={fullName} onChange={(e) => setFullName(e.target.value)} />
            </label>
            <label className="field">
              <span>Empresa</span>
              <input type="text" required minLength={2} maxLength={120} autoComplete="organization" value={companyName} onChange={(e) => setCompanyName(e.target.value)} />
            </label>
            <label className="field">
              <span>Correo corporativo</span>
              <input type="email" required maxLength={255} autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} />
            </label>
            <label className="field">
              <span>Teléfono corporativo</span>
              <input type="tel" required minLength={8} maxLength={20} autoComplete="tel" placeholder="+52 55 1234 5678" value={phone} onChange={(e) => setPhone(e.target.value)} />
            </label>
            <label className="field">
              <span>Contraseña</span>
              <input type="password" required maxLength={128} autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} />
            </label>
            <PasswordStrength value={password} />
            <button type="submit" className="btn btn-primary" disabled={busy || !isPasswordValid(password)}>
              <UserPlus size={16} aria-hidden="true" /> {busy ? 'Creando…' : 'Crear cuenta corporativa'}
            </button>
          </form>
        )}

        {mode === 'forgot' && (
          <form onSubmit={handleForgot} className="form">
            <p className="muted">Ingresa tu correo. Si está registrado, recibirás instrucciones de recuperación.</p>
            <label className="field">
              <span>Correo electrónico</span>
              <input type="email" required autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} />
            </label>
            <button type="submit" className="btn btn-primary" disabled={busy}>
              {busy ? 'Enviando…' : 'Solicitar recuperación'}
            </button>
            <button type="button" className="btn btn-ghost" onClick={() => switchMode('reset')}>
              Ya tengo un token de recuperación
            </button>
          </form>
        )}

        {mode === 'reset' && (
          <form onSubmit={handleReset} className="form">
            <label className="field">
              <span>Token de recuperación</span>
              <input type="text" required minLength={32} maxLength={256} autoComplete="off" spellCheck={false} value={resetToken} onChange={(e) => setResetToken(e.target.value)} />
            </label>
            <label className="field">
              <span>Nueva contraseña</span>
              <input type="password" required maxLength={128} autoComplete="new-password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} />
            </label>
            <PasswordStrength value={newPassword} />
            <button type="submit" className="btn btn-primary" disabled={busy || !isPasswordValid(newPassword)}>
              {busy ? 'Restableciendo…' : 'Restablecer contraseña'}
            </button>
            <button type="button" className="btn btn-ghost" onClick={() => switchMode('forgot')}>
              Solicitar un nuevo token
            </button>
          </form>
        )}
      </section>
    </main>
  );
}
