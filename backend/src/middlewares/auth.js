import { timingSafeEqual } from 'node:crypto';
import { env } from '../config/env.js';
import { query } from '../config/db.js';
import { verifyJwt, verifyCsrfToken } from '../crypto/tokens.js';
import { logSecurityEvent } from '../services/audit.service.js';

const MUTABLE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

const constantTimeEqualStrings = (a, b) => {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
};

const extractSessionToken = (req) => {
  if (typeof req.cookies?.sv_session === 'string' && req.cookies.sv_session.length > 0) {
    return req.cookies.sv_session;
  }

  const bearerAllowedForTests =
    env.NODE_ENV === 'test' ||
    (env.NODE_ENV !== 'production' && process.env.ALLOW_BEARER_AUTH === 'true');

  if (bearerAllowedForTests) {
    const authHeader = req.get('authorization');
    if (typeof authHeader === 'string' && authHeader.startsWith('Bearer ')) {
      return authHeader.slice(7).trim();
    }
  }

  return null;
};

/**
 * Exige una sesión JWT válida en cookie HttpOnly (sv_session) y verifica token_version en PostgreSQL.
 */
export const requireAuth = async (req, res, next) => {
  const token = extractSessionToken(req);
  if (!token) {
    return res.status(401).json({ error: 'No autenticado' });
  }

  let payload;
  try {
    payload = verifyJwt(token);
  } catch {
    return res.status(401).json({ error: 'No autenticado' });
  }

  if (typeof payload.sub !== 'string' || typeof payload.tv !== 'number') {
    return res.status(401).json({ error: 'No autenticado' });
  }

  try {
    const { rows } = await query(
      `SELECT id, email, full_name, company_name, role, totp_enabled, token_version
       FROM users
       WHERE id = $1`,
      [payload.sub]
    );

    const user = rows[0];
    if (!user || user.token_version !== payload.tv) {
      return res.status(401).json({ error: 'No autenticado' });
    }

    req.user = user;
    return next();
  } catch (err) {
    return next(err);
  }
};

/**
 * Restringe el acceso exclusivamente a usuarios con rol 'admin' y audita intentos no autorizados.
 */
export const requireAdmin = async (req, res, next) => {
  if (req.user?.role === 'admin') {
    return next();
  }

  await logSecurityEvent({
    userId: req.user?.id ?? null,
    actorEmail: req.user?.email ?? null,
    eventType: 'UNAUTHORIZED_ADMIN_ACCESS',
    severity: 'warning',
    req,
    details: { path: req.originalUrl, method: req.method }
  });

  return res.status(403).json({ error: 'Acceso denegado' });
};

/**
 * Protege rutas autenticadas mutables con Double-Submit Cookie + firma HMAC ligada a la sesión.
 */
export const requireCsrf = async (req, res, next) => {
  if (!MUTABLE_METHODS.has(req.method.toUpperCase())) {
    return next();
  }

  if (!req.user?.id || typeof req.user?.token_version !== 'number') {
    return res.status(401).json({ error: 'No autenticado' });
  }

  const headerToken = req.get('X-CSRF-Token');
  const cookieToken = req.cookies?.sv_csrf;
  const sessionBinding = `${req.user.id}:${req.user.token_version}`;

  const isValid =
    typeof headerToken === 'string' &&
    typeof cookieToken === 'string' &&
    headerToken.length > 0 &&
    constantTimeEqualStrings(headerToken, cookieToken) &&
    verifyCsrfToken(headerToken, sessionBinding);

  if (!isValid) {
    await logSecurityEvent({
      userId: req.user.id,
      actorEmail: req.user.email,
      eventType: 'CSRF_VALIDATION_FAILED',
      severity: 'warning',
      req,
      details: { path: req.originalUrl, method: req.method }
    });

    return res.status(403).json({ error: 'Token CSRF inválido o ausente' });
  }

  return next();
};
