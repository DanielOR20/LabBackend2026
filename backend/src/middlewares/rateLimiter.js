import { query } from '../config/db.js';
import { hashToken } from '../crypto/tokens.js';
import { logSecurityEvent } from '../services/audit.service.js';

/**
 * Rate limiter persistente y atómico respaldado por la tabla rate_limits de PostgreSQL.
 */
export const pgRateLimiter = ({
  prefix,
  windowMs,
  maxHits,
  keyGenerator = (req) => req.ip || 'unknown'
}) => {
  if (typeof prefix !== 'string' || prefix.trim().length === 0) {
    throw new TypeError('prefix es obligatorio para pgRateLimiter');
  }
  if (!Number.isInteger(windowMs) || windowMs <= 0) {
    throw new TypeError('windowMs debe ser un entero positivo');
  }
  if (!Number.isInteger(maxHits) || maxHits <= 0) {
    throw new TypeError('maxHits debe ser un entero positivo');
  }

  const normalizedPrefix = prefix.trim();

  return async (req, res, next) => {
    try {
      const keyIdentifier = String(keyGenerator(req) || 'unknown').trim() || 'unknown';
      const rawKey = `${normalizedPrefix}:${keyIdentifier}`;
      const rateKey =
        rawKey.length > 255 ? `${normalizedPrefix}:${hashToken(rawKey)}` : rawKey;

      const { rows } = await query(
        `INSERT INTO rate_limits (key, hits, reset_at)
         VALUES ($1, 1, NOW() + ($2 * INTERVAL '1 millisecond'))
         ON CONFLICT (key) DO UPDATE
         SET
           hits = CASE
             WHEN rate_limits.reset_at <= NOW() THEN 1
             ELSE rate_limits.hits + 1
           END,
           reset_at = CASE
             WHEN rate_limits.reset_at <= NOW() THEN NOW() + ($2 * INTERVAL '1 millisecond')
             ELSE rate_limits.reset_at
           END
         RETURNING hits, GREATEST(1, CEIL(EXTRACT(EPOCH FROM (reset_at - NOW()))))::INT AS retry_after_seconds`,
        [rateKey, windowMs]
      );

      const { hits, retry_after_seconds: retryAfterSeconds } = rows[0];
      if (hits > maxHits) {
        await logSecurityEvent({
          eventType: 'RATE_LIMIT_EXCEEDED',
          severity: 'warning',
          req,
          details: { prefix: normalizedPrefix, hits, maxHits }
        });

        res.set('Retry-After', String(retryAfterSeconds));
        return res.status(429).json({
          error: 'Demasiadas solicitudes. Intente más tarde.'
        });
      }

      return next();
    } catch (err) {
      return next(err);
    }
  };
};
