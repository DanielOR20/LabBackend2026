import { env } from '../config/env.js';
import { logger } from '../config/logger.js';
import { query } from '../config/db.js';
import { validateDiscordWebhookUrl } from '../utils/ssrfGuard.js';

export { validateDiscordWebhookUrl };

const SENSITIVE_KEYS = new Set([
  'password',
  'newpassword',
  'password_hash',
  'token',
  'totpcode',
  'secret',
  'encrypted_content',
  'content',
  'phone',
  'encrypted_phone',
  'totp_secret_enc'
]);

const SEVERITY_COLORS = Object.freeze({
  info: 0x2563eb,
  warning: 0xd97706,
  critical: 0xdc2626
});

const sanitizeDetails = (value, depth = 0) => {
  if (depth > 5 || value === null || value === undefined) {
    return value ?? null;
  }

  if (Array.isArray(value)) {
    return value.map((item) => sanitizeDetails(item, depth + 1));
  }

  if (typeof value === 'object') {
    const clean = {};
    for (const [key, entryValue] of Object.entries(value)) {
      if (SENSITIVE_KEYS.has(key.toLowerCase())) {
        continue;
      }
      clean[key] = sanitizeDetails(entryValue, depth + 1);
    }
    return clean;
  }

  return value;
};

const sendDiscordAlert = async ({ eventType, severity, actorEmail, ipAddress, details, ephemeralUrl }) => {
  if (!env.DISCORD_WEBHOOK_URL) return;

  if (!validateDiscordWebhookUrl(env.DISCORD_WEBHOOK_URL)) {
    logger.warn(
      { eventType, securityControl: 'SSRF_OUTBOUND_BLOCKED' },
      'SSRF_OUTBOUND_BLOCKED: URL de webhook bloqueada por lista blanca'
    );
    return;
  }

  const fields = [
    { name: 'Evento', value: eventType, inline: true },
    { name: 'Severidad', value: severity.toUpperCase(), inline: true },
    { name: 'Actor', value: actorEmail || 'Anónimo', inline: true },
    { name: 'IP', value: ipAddress || 'N/A', inline: true }
  ];

  if (ephemeralUrl) {
    fields.push({ name: 'Recuperación (dev/$0)', value: ephemeralUrl, inline: false });
  } else if (details && Object.keys(details).length > 0) {
    fields.push({
      name: 'Detalles',
      value: `\`\`\`json\n${JSON.stringify(details).slice(0, 900)}\n\`\`\``,
      inline: false
    });
  }

  const response = await fetch(env.DISCORD_WEBHOOK_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    redirect: 'error',
    body: JSON.stringify({
      username: 'SecureVault Security',
      embeds: [
        {
          title: `Alerta de Seguridad: ${eventType}`,
          color: SEVERITY_COLORS[severity] ?? SEVERITY_COLORS.info,
          fields,
          timestamp: new Date().toISOString()
        }
      ]
    }),
    signal: AbortSignal.timeout(3000)
  });

  if (!response.ok) {
    logger.warn({ status: response.status, eventType }, 'Discord Webhook respondió con estado no exitoso');
  }
};

/**
 * Registra eventos de seguridad en Pino, PostgreSQL (security_logs) y opcionalmente Discord Webhook.
 */
export const logSecurityEvent = async ({
  userId = null,
  actorEmail = null,
  eventType,
  severity = 'info',
  req = null,
  details = {},
  notifyDiscord = false,
  ephemeralUrl = null
}) => {
  const safeSeverity = ['info', 'warning', 'critical'].includes(severity) ? severity : 'info';
  const ipAddress = req?.ip ? String(req.ip).slice(0, 64) : null;
  const userAgent = req?.get?.('user-agent') || null;
  const safeDetails = sanitizeDetails(details) || {};

  const logMethod =
    safeSeverity === 'critical' ? 'error' : safeSeverity === 'warning' ? 'warn' : 'info';

  logger[logMethod](
    {
      audit: true,
      userId,
      actorEmail,
      eventType,
      severity: safeSeverity,
      ipAddress,
      details: safeDetails,
      ...(ephemeralUrl && env.NODE_ENV !== 'production' ? { recoveryLink: ephemeralUrl } : {})
    },
    `Evento de seguridad: ${eventType}`
  );

  try {
    await query(
      `INSERT INTO security_logs (user_id, actor_email, event_type, severity, ip_address, user_agent, details)
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)`,
      [
        userId,
        actorEmail ? String(actorEmail).slice(0, 255) : null,
        String(eventType).slice(0, 60),
        safeSeverity,
        ipAddress,
        userAgent,
        JSON.stringify(safeDetails)
      ]
    );
  } catch (err) {
    logger.error({ err, eventType }, 'Error al persistir evento en security_logs');
  }

  if ((notifyDiscord || safeSeverity === 'critical') && env.DISCORD_WEBHOOK_URL) {
    void sendDiscordAlert({
      eventType,
      severity: safeSeverity,
      actorEmail,
      ipAddress,
      details: safeDetails,
      ephemeralUrl
    }).catch((err) => {
      logger.warn({ err, eventType }, 'Fallo al enviar notificación a Discord Webhook');
    });
  }
};
