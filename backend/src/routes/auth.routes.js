import { randomUUID } from 'node:crypto';
import { Router } from 'express';
import { z } from 'zod';
import { env } from '../config/env.js';
import { query, getClient } from '../config/db.js';
import { DUMMY_PASSWORD_HASH, hashPassword, verifyPassword } from '../crypto/password.js';
import { encryptText, decryptText, maskSensitiveData } from '../crypto/vaultCipher.js';
import { generateSecureToken, hashToken, signJwt, generateCsrfToken } from '../crypto/tokens.js';
import { logSecurityEvent } from '../services/audit.service.js';
import {
  generateTotpSetup,
  verifyTotpCode,
  unpackEncryptedTotpSecret
} from '../services/totp.service.js';
import { validateBody } from '../middlewares/validate.js';
import { pgRateLimiter } from '../middlewares/rateLimiter.js';
import { requireAuth, requireCsrf } from '../middlewares/auth.js';

const router = Router();

const FIFTEEN_MINUTES_MS = 15 * 60 * 1000;
const SESSION_MAX_AGE_MS = 30 * 60 * 1000;
const SESSION_TTL_SECONDS = 1800;

const emailSchema = z
  .string()
  .trim()
  .toLowerCase()
  .email('Correo electrónico inválido')
  .max(255, 'El correo electrónico es demasiado largo');

const passwordPolicySchema = z
  .string()
  .min(10, 'La contraseña debe tener al menos 10 caracteres')
  .max(128, 'La contraseña no debe superar los 128 caracteres')
  .regex(/[A-Z]/, 'La contraseña debe incluir al menos una letra mayúscula')
  .regex(/[a-z]/, 'La contraseña debe incluir al menos una letra minúscula')
  .regex(/[0-9]/, 'La contraseña debe incluir al menos un número')
  .regex(/[^A-Za-z0-9]/, 'La contraseña debe incluir al menos un carácter especial');

const phoneSchema = z
  .string()
  .trim()
  .min(8, 'El teléfono debe tener al menos 8 caracteres')
  .max(20, 'El teléfono no debe superar los 20 caracteres')
  .regex(/^\+?[0-9\s().-]{8,20}$/, 'Formato de teléfono inválido')
  .refine((val) => {
    const digits = val.replace(/\D/g, '');
    return digits.length >= 7 && digits.length <= 15;
  }, 'El teléfono debe contener entre 7 y 15 dígitos');

const totpCodeSchema = z
  .string()
  .trim()
  .regex(/^\d{6}$/, 'El código 2FA debe tener exactamente 6 dígitos');

const registerSchema = z.object({
  email: emailSchema,
  fullName: z.string().trim().min(2, 'Nombre completo inválido').max(120, 'Nombre demasiado largo'),
  companyName: z.string().trim().min(2, 'Nombre de empresa inválido').max(120, 'Empresa demasiado larga'),
  phone: phoneSchema,
  password: passwordPolicySchema
});

const loginSchema = z.object({
  email: emailSchema,
  password: z.string().min(1, 'La contraseña es requerida').max(128),
  totpCode: totpCodeSchema.optional()
});

const mfaVerifySchema = z.object({
  totpCode: totpCodeSchema
});

const forgotPasswordSchema = z.object({
  email: emailSchema
});

const resetPasswordSchema = z.object({
  token: z.string().trim().min(32, 'Token inválido').max(256, 'Token inválido'),
  newPassword: passwordPolicySchema
});

const registerLimiter = pgRateLimiter({
  prefix: 'auth_register',
  windowMs: FIFTEEN_MINUTES_MS,
  maxHits: 5
});

const loginLimiter = pgRateLimiter({
  prefix: 'auth_login',
  windowMs: FIFTEEN_MINUTES_MS,
  maxHits: 10
});

const recoveryLimiter = pgRateLimiter({
  prefix: 'auth_recovery',
  windowMs: FIFTEEN_MINUTES_MS,
  maxHits: 5
});

const getCookieOptions = (httpOnly) => ({
  httpOnly,
  secure: env.NODE_ENV === 'production',
  sameSite: 'strict',
  path: '/'
});

/**
 * POST /api/auth/register
 */
router.post('/register', registerLimiter, validateBody(registerSchema), async (req, res, next) => {
  const { email, fullName, companyName, phone, password } = req.body;

  try {
    const existing = await query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: 'No fue posible completar el registro' });
    }

    const passwordHash = await hashPassword(password);
    const { ciphertext: encryptedPhone, keyVersion: phoneKeyVersion } = encryptText(phone);

    const { rows } = await query(
      `INSERT INTO users (email, full_name, company_name, password_hash, encrypted_phone, phone_key_version, role)
       VALUES ($1, $2, $3, $4, $5, $6, 'user')
       RETURNING id, email`,
      [email, fullName, companyName, passwordHash, encryptedPhone, phoneKeyVersion]
    );

    const createdUser = rows[0];

    await logSecurityEvent({
      userId: createdUser.id,
      actorEmail: createdUser.email,
      eventType: 'USER_REGISTERED',
      severity: 'info',
      req
    });

    return res.status(201).json({ message: 'Usuario registrado correctamente' });
  } catch (err) {
    if (err?.code === '23505') {
      return res.status(409).json({ error: 'No fue posible completar el registro' });
    }
    return next(err);
  }
});

/**
 * POST /api/auth/login
 */
router.post('/login', loginLimiter, validateBody(loginSchema), async (req, res) => {
  const { email, password, totpCode } = req.body;

  const { rows } = await query(
    `SELECT id, email, full_name, company_name, password_hash, role,
            totp_secret_enc, totp_enabled, failed_attempts, locked_until, token_version
     FROM users
     WHERE email = $1`,
    [email]
  );

  const user = rows[0];
  if (!user) {
    await verifyPassword(DUMMY_PASSWORD_HASH, password);
    await logSecurityEvent({
      actorEmail: email,
      eventType: 'LOGIN_FAILED',
      severity: 'warning',
      req,
      details: { reason: 'invalid_credentials' }
    });
    return res.status(401).json({ error: 'Credenciales inválidas' });
  }

  if (user.locked_until && new Date(user.locked_until) > new Date()) {
    await logSecurityEvent({
      userId: user.id,
      actorEmail: user.email,
      eventType: 'LOGIN_BLOCKED_LOCKOUT',
      severity: 'warning',
      req
    });
    return res.status(429).json({
      error: 'Cuenta bloqueada temporalmente por múltiples intentos fallidos.'
    });
  }

  const isPasswordValid = await verifyPassword(user.password_hash, password);
  if (!isPasswordValid) {
    const { rows: updatedRows } = await query(
      `UPDATE users
       SET
         failed_attempts = CASE
           WHEN locked_until IS NOT NULL AND locked_until <= NOW() THEN 1
           ELSE failed_attempts + 1
         END,
         locked_until = CASE
           WHEN (CASE WHEN locked_until IS NOT NULL AND locked_until <= NOW() THEN 1 ELSE failed_attempts + 1 END) >= 5
             THEN NOW() + INTERVAL '15 minutes'
           ELSE NULL
         END
       WHERE id = $1
       RETURNING failed_attempts, locked_until`,
      [user.id]
    );

    const updated = updatedRows[0];
    if (updated.failed_attempts >= 5 || updated.locked_until) {
      await logSecurityEvent({
        userId: user.id,
        actorEmail: user.email,
        eventType: 'BRUTE_FORCE_LOCKOUT',
        severity: 'critical',
        req,
        details: { failedAttempts: updated.failed_attempts },
        notifyDiscord: true
      });
    } else {
      await logSecurityEvent({
        userId: user.id,
        actorEmail: user.email,
        eventType: 'LOGIN_FAILED',
        severity: 'warning',
        req,
        details: { failedAttempts: updated.failed_attempts }
      });
    }

    return res.status(401).json({ error: 'Credenciales inválidas' });
  }

  if (user.totp_enabled === true) {
    if (!totpCode) {
      return res.status(200).json({
        mfaRequired: true,
        message: 'Ingrese el código de verificación 2FA'
      });
    }

    let isTotpValid = false;
    try {
      const { encryptedSecret, keyVersion } = unpackEncryptedTotpSecret(user.totp_secret_enc);
      isTotpValid = verifyTotpCode(encryptedSecret, keyVersion, totpCode);
    } catch {
      isTotpValid = false;
    }

    if (!isTotpValid) {
      await logSecurityEvent({
        userId: user.id,
        actorEmail: user.email,
        eventType: 'MFA_FAILED',
        severity: 'warning',
        req
      });
      return res.status(401).json({ error: 'Código 2FA inválido' });
    }
  }

  await query('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = $1', [user.id]);

  const jwt = signJwt(
    {
      sub: user.id,
      role: user.role,
      tv: user.token_version,
      jti: randomUUID()
    },
    SESSION_TTL_SECONDS
  );
  const csrfToken = generateCsrfToken(`${user.id}:${user.token_version}`);

  res.clearCookie('sv_session', { path: '/' });
  res.clearCookie('sv_csrf', { path: '/' });

  res.cookie('sv_session', jwt, {
    ...getCookieOptions(true),
    maxAge: SESSION_MAX_AGE_MS
  });
  res.cookie('sv_csrf', csrfToken, {
    ...getCookieOptions(false),
    maxAge: SESSION_MAX_AGE_MS
  });

  await logSecurityEvent({
    userId: user.id,
    actorEmail: user.email,
    eventType: 'LOGIN_SUCCESS',
    severity: 'info',
    req
  });

  return res.status(200).json({
    user: {
      id: user.id,
      email: user.email,
      fullName: user.full_name,
      companyName: user.company_name,
      role: user.role,
      totpEnabled: user.totp_enabled
    }
  });
});

/**
 * POST /api/auth/logout
 */
router.post('/logout', requireAuth, requireCsrf, async (req, res) => {
  await query('UPDATE users SET token_version = token_version + 1 WHERE id = $1', [req.user.id]);

  res.clearCookie('sv_session', getCookieOptions(true));
  res.clearCookie('sv_csrf', getCookieOptions(false));

  await logSecurityEvent({
    userId: req.user.id,
    actorEmail: req.user.email,
    eventType: 'LOGOUT',
    severity: 'info',
    req
  });

  return res.status(200).json({ message: 'Sesión cerrada correctamente' });
});

/**
 * GET /api/auth/me
 */
router.get('/me', requireAuth, async (req, res) => {
  const { rows } = await query(
    `SELECT id, email, full_name, company_name, encrypted_phone, phone_key_version, role, totp_enabled, created_at
     FROM users
     WHERE id = $1`,
    [req.user.id]
  );

  const user = rows[0];
  if (!user) {
    return res.status(401).json({ error: 'No autenticado' });
  }

  const plainPhone = decryptText(user.encrypted_phone, user.phone_key_version);

  return res.status(200).json({
    user: {
      id: user.id,
      email: user.email,
      fullName: user.full_name,
      companyName: user.company_name,
      maskedPhone: maskSensitiveData(plainPhone),
      role: user.role,
      totpEnabled: user.totp_enabled,
      createdAt: user.created_at
    }
  });
});

const revealOwnPhoneHandler = async (req, res) => {
  const { rows } = await query(
    `SELECT encrypted_phone, phone_key_version
     FROM users
     WHERE id = $1`,
    [req.user.id]
  );

  const user = rows[0];
  if (!user) {
    return res.status(401).json({ error: 'No autenticado' });
  }

  const plainPhone = decryptText(user.encrypted_phone, user.phone_key_version);

  await logSecurityEvent({
    userId: req.user.id,
    actorEmail: req.user.email,
    eventType: 'SENSITIVE_DATA_REVEALED',
    severity: 'info',
    req,
    details: { field: 'phone' }
  });

  return res.status(200).json({ phone: plainPhone });
};

router.post('/me/reveal-phone', requireAuth, requireCsrf, revealOwnPhoneHandler);
router.get('/me/phone', requireAuth, revealOwnPhoneHandler);

/**
 * POST /api/auth/mfa/setup
 */
router.post('/mfa/setup', requireAuth, requireCsrf, async (req, res) => {
  if (req.user.totp_enabled === true) {
    return res.status(409).json({ error: 'La autenticación 2FA ya se encuentra activada' });
  }

  const { packedSecret, qrDataUrl, manualKey } = await generateTotpSetup(req.user.email);

  await query(
    'UPDATE users SET totp_secret_enc = $1, totp_enabled = FALSE WHERE id = $2',
    [packedSecret, req.user.id]
  );

  await logSecurityEvent({
    userId: req.user.id,
    actorEmail: req.user.email,
    eventType: 'MFA_SETUP_INITIATED',
    severity: 'info',
    req
  });

  return res.status(200).json({ qrDataUrl, manualKey });
});

/**
 * POST /api/auth/mfa/verify
 */
router.post(
  '/mfa/verify',
  requireAuth,
  requireCsrf,
  validateBody(mfaVerifySchema),
  async (req, res) => {
    const { totpCode } = req.body;

    const { rows } = await query(
      'SELECT totp_secret_enc, totp_enabled FROM users WHERE id = $1',
      [req.user.id]
    );
    const user = rows[0];

    if (!user?.totp_secret_enc) {
      return res.status(400).json({ error: 'Debe iniciar la configuración 2FA primero' });
    }

    let isValid = false;
    try {
      const { encryptedSecret, keyVersion } = unpackEncryptedTotpSecret(user.totp_secret_enc);
      isValid = verifyTotpCode(encryptedSecret, keyVersion, totpCode);
    } catch {
      isValid = false;
    }

    if (!isValid) {
      await logSecurityEvent({
        userId: req.user.id,
        actorEmail: req.user.email,
        eventType: 'MFA_FAILED',
        severity: 'warning',
        req
      });
      return res.status(401).json({ error: 'Código 2FA inválido' });
    }

    await query('UPDATE users SET totp_enabled = TRUE WHERE id = $1', [req.user.id]);

    await logSecurityEvent({
      userId: req.user.id,
      actorEmail: req.user.email,
      eventType: 'MFA_ENABLED',
      severity: 'info',
      req
    });

    return res.status(200).json({ message: 'Autenticación 2FA activada correctamente' });
  }
);

/**
 * POST /api/auth/forgot-password
 */
router.post(
  '/forgot-password',
  recoveryLimiter,
  validateBody(forgotPasswordSchema),
  async (req, res) => {
    const { email } = req.body;

    const { rows } = await query('SELECT id, email FROM users WHERE email = $1', [email]);
    const user = rows[0];

    if (user) {
      const { rawToken, tokenHash } = generateSecureToken(32);

      await query(
        `INSERT INTO password_resets (user_id, token_hash, expires_at)
         VALUES ($1, $2, NOW() + INTERVAL '15 minutes')`,
        [user.id, tokenHash]
      );

      const frontendOrigin = env.CORS_ORIGIN.split(',')[0].trim().replace(/\/+$/, '');
      const resetUrl = `${frontendOrigin}/reset-password?token=${rawToken}`;

      await logSecurityEvent({
        userId: user.id,
        actorEmail: user.email,
        eventType: 'PASSWORD_RESET_REQUESTED',
        severity: 'info',
        req,
        details: { expiresInMinutes: 15 },
        notifyDiscord: true,
        ephemeralUrl: resetUrl
      });
    }

    return res.status(200).json({
      message: 'Si el correo está registrado, se enviaron las instrucciones de recuperación.'
    });
  }
);

/**
 * POST /api/auth/reset-password
 */
router.post(
  '/reset-password',
  recoveryLimiter,
  validateBody(resetPasswordSchema),
  async (req, res, next) => {
    const { token, newPassword } = req.body;
    const tokenHash = hashToken(token);
    const client = await getClient();

    try {
      await client.query('BEGIN');

      const { rows: resetRows } = await client.query(
        `UPDATE password_resets
         SET used_at = NOW()
         WHERE token_hash = $1
           AND used_at IS NULL
           AND expires_at > NOW()
         RETURNING id, user_id`,
        [tokenHash]
      );

      const resetRecord = resetRows[0];
      if (!resetRecord) {
        await client.query('ROLLBACK');
        await logSecurityEvent({
          eventType: 'PASSWORD_RESET_FAILED',
          severity: 'warning',
          req,
          details: { reason: 'invalid_or_expired_token' }
        });
        return res.status(400).json({ error: 'Token de recuperación inválido o expirado' });
      }

      const passwordHash = await hashPassword(newPassword);

      const { rows: userRows } = await client.query(
        `UPDATE users
         SET password_hash = $1,
             token_version = token_version + 1,
             failed_attempts = 0,
             locked_until = NULL
         WHERE id = $2
         RETURNING email`,
        [passwordHash, resetRecord.user_id]
      );

      await client.query(
        `UPDATE password_resets
         SET used_at = NOW()
         WHERE user_id = $1 AND used_at IS NULL`,
        [resetRecord.user_id]
      );

      await client.query('COMMIT');

      await logSecurityEvent({
        userId: resetRecord.user_id,
        actorEmail: userRows[0]?.email ?? null,
        eventType: 'PASSWORD_RESET_SUCCESS',
        severity: 'info',
        req
      });

      return res.status(200).json({ message: 'Contraseña restablecida correctamente' });
    } catch (err) {
      try {
        await client.query('ROLLBACK');
      } catch {
        // Ignorar error de rollback si la transacción ya fue abortada
      }
      return next(err);
    } finally {
      client.release();
    }
  }
);

export default router;
