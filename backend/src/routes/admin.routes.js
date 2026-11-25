import { Router } from 'express';
import { z } from 'zod';
import { ACTIVE_KEY_VERSION } from '../config/env.js';
import { query, getClient } from '../config/db.js';
import { encryptText, decryptText, maskSensitiveData } from '../crypto/vaultCipher.js';
import { logSecurityEvent } from '../services/audit.service.js';
import { packEncryptedTotpSecret, unpackEncryptedTotpSecret } from '../services/totp.service.js';
import { validateBody, validateParams } from '../middlewares/validate.js';
import { requireAuth, requireAdmin, requireCsrf } from '../middlewares/auth.js';

const router = Router();

const userIdParamSchema = z.object({
  id: z.string().uuid('ID de usuario inválido')
});

const updateRoleSchema = z.object({
  role: z.enum(['user', 'admin'])
});

const logsQuerySchema = z.object({
  severity: z
    .string()
    .trim()
    .optional()
    .transform((val) => (val === '' ? undefined : val))
    .pipe(z.enum(['info', 'warning', 'critical']).optional()),
  eventType: z
    .string()
    .trim()
    .max(60, 'eventType no debe superar los 60 caracteres')
    .optional()
    .transform((val) => (val === '' ? undefined : val))
});

router.use(requireAuth, requireAdmin, requireCsrf);

/**
 * GET /api/admin/overview
 */
router.get('/overview', async (_req, res) => {
  const [usersResult, noteKeysResult, phoneKeysResult, severityResult, eventsResult] =
    await Promise.all([
      query(
        `SELECT
           COUNT(*)::int AS total_users,
           COUNT(*) FILTER (WHERE role = 'admin')::int AS total_admins,
           COUNT(*) FILTER (WHERE totp_enabled = TRUE)::int AS mfa_enabled_users,
           COUNT(*) FILTER (WHERE locked_until IS NOT NULL AND locked_until > NOW())::int AS locked_accounts
         FROM users`
      ),
      query(
        `SELECT key_version, COUNT(*)::int AS count
         FROM vault_notes
         GROUP BY key_version
         ORDER BY key_version ASC`
      ),
      query(
        `SELECT phone_key_version AS key_version, COUNT(*)::int AS count
         FROM users
         GROUP BY phone_key_version
         ORDER BY phone_key_version ASC`
      ),
      query(
        `SELECT severity, COUNT(*)::int AS count
         FROM security_logs
         WHERE created_at >= NOW() - INTERVAL '24 hours'
         GROUP BY severity`
      ),
      query(
        `SELECT event_type, COUNT(*)::int AS count
         FROM security_logs
         WHERE created_at >= NOW() - INTERVAL '24 hours'
         GROUP BY event_type
         ORDER BY count DESC`
      )
    ]);

  const userStats = usersResult.rows[0];
  const notesByKeyVersion = noteKeysResult.rows.map((row) => ({
    keyVersion: row.key_version,
    count: row.count
  }));
  const phonesByKeyVersion = phoneKeysResult.rows.map((row) => ({
    keyVersion: row.key_version,
    count: row.count
  }));
  const totalNotes = notesByKeyVersion.reduce((sum, item) => sum + item.count, 0);

  const severityCounts = { info: 0, warning: 0, critical: 0 };
  for (const row of severityResult.rows) {
    if (row.severity in severityCounts) {
      severityCounts[row.severity] = row.count;
    }
  }

  return res.status(200).json({
    users: {
      total: userStats.total_users,
      admins: userStats.total_admins,
      mfaEnabled: userStats.mfa_enabled_users,
      locked: userStats.locked_accounts
    },
    vault: {
      totalNotes,
      activeKeyVersion: ACTIVE_KEY_VERSION,
      notesByKeyVersion,
      phonesByKeyVersion
    },
    securityLast24h: {
      bySeverity: severityCounts,
      byEventType: eventsResult.rows.map((row) => ({
        eventType: row.event_type,
        count: row.count
      }))
    }
  });
});

/**
 * GET /api/admin/users
 */
router.get('/users', async (_req, res) => {
  const { rows } = await query(
    `SELECT id, email, full_name, company_name, encrypted_phone, phone_key_version,
            role, totp_enabled, failed_attempts, locked_until, created_at
     FROM users
     ORDER BY created_at DESC`
  );

  const users = rows.map((row) => {
    const plainPhone = decryptText(row.encrypted_phone, row.phone_key_version);
    return {
      id: row.id,
      email: row.email,
      fullName: row.full_name,
      companyName: row.company_name,
      maskedPhone: maskSensitiveData(plainPhone),
      role: row.role,
      totpEnabled: row.totp_enabled,
      failedAttempts: row.failed_attempts,
      lockedUntil: row.locked_until,
      createdAt: row.created_at
    };
  });

  return res.status(200).json({ users });
});

/**
 * PATCH /api/admin/users/:id/role
 */
router.patch(
  '/users/:id/role',
  validateParams(userIdParamSchema),
  validateBody(updateRoleSchema),
  async (req, res) => {
    if (req.params.id === req.user.id) {
      return res.status(400).json({
        error: 'No puedes modificar tu propio rol administrativo.'
      });
    }

    const { role } = req.body;
    const { rows } = await query(
      `UPDATE users
       SET role = $1,
           token_version = token_version + 1
       WHERE id = $2
       RETURNING id, email, role`,
      [role, req.params.id]
    );

    const updated = rows[0];
    if (!updated) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    await logSecurityEvent({
      userId: req.user.id,
      actorEmail: req.user.email,
      eventType: 'USER_ROLE_CHANGED',
      severity: 'warning',
      req,
      details: {
        targetUserId: updated.id,
        targetEmail: updated.email,
        newRole: updated.role
      },
      notifyDiscord: true
    });

    return res.status(200).json({
      message: 'Rol de usuario actualizado correctamente',
      user: updated
    });
  }
);

/**
 * PATCH /api/admin/users/:id/unlock
 */
router.patch('/users/:id/unlock', validateParams(userIdParamSchema), async (req, res) => {
  const { rows } = await query(
    `UPDATE users
     SET failed_attempts = 0,
         locked_until = NULL
     WHERE id = $1
     RETURNING id, email`,
    [req.params.id]
  );

  const unlocked = rows[0];
  if (!unlocked) {
    return res.status(404).json({ error: 'Usuario no encontrado' });
  }

  await logSecurityEvent({
    userId: req.user.id,
    actorEmail: req.user.email,
    eventType: 'USER_ACCOUNT_UNLOCKED',
    severity: 'info',
    req,
    details: {
      targetUserId: unlocked.id,
      targetEmail: unlocked.email
    }
  });

  return res.status(200).json({
    message: 'Cuenta desbloqueada correctamente',
    user: unlocked
  });
});

/**
 * GET /api/admin/logs
 */
router.get('/logs', async (req, res, next) => {
  const parsedQuery = logsQuerySchema.safeParse(req.query);
  if (!parsedQuery.success) {
    return next(parsedQuery.error);
  }

  const { severity, eventType } = parsedQuery.data;

  const { rows } = await query(
    `SELECT id, user_id, actor_email, event_type, severity, ip_address, user_agent, details, created_at
     FROM security_logs
     WHERE ($1::varchar IS NULL OR severity = $1)
       AND ($2::varchar IS NULL OR event_type = $2)
     ORDER BY created_at DESC
     LIMIT 100`,
    [severity ?? null, eventType ?? null]
  );

  return res.status(200).json({ logs: rows });
});

/**
 * POST /api/admin/rotate-keys
 */
router.post('/rotate-keys', async (req, res, next) => {
  const client = await getClient();

  try {
    await client.query('BEGIN');

    const { rows: notesToRotate } = await client.query(
      `SELECT id, encrypted_content, key_version
       FROM vault_notes
       WHERE key_version <> $1
       FOR UPDATE`,
      [ACTIVE_KEY_VERSION]
    );

    let notesRotated = 0;
    for (const note of notesToRotate) {
      const plaintext = decryptText(note.encrypted_content, note.key_version);
      const { ciphertext, keyVersion } = encryptText(plaintext, ACTIVE_KEY_VERSION);
      await client.query(
        'UPDATE vault_notes SET encrypted_content = $1, key_version = $2 WHERE id = $3',
        [ciphertext, keyVersion, note.id]
      );
      notesRotated += 1;
    }

    const { rows: phonesToRotate } = await client.query(
      `SELECT id, encrypted_phone, phone_key_version
       FROM users
       WHERE phone_key_version <> $1
       FOR UPDATE`,
      [ACTIVE_KEY_VERSION]
    );

    let phonesRotated = 0;
    for (const user of phonesToRotate) {
      const plainPhone = decryptText(user.encrypted_phone, user.phone_key_version);
      const { ciphertext, keyVersion } = encryptText(plainPhone, ACTIVE_KEY_VERSION);
      await client.query(
        'UPDATE users SET encrypted_phone = $1, phone_key_version = $2 WHERE id = $3',
        [ciphertext, keyVersion, user.id]
      );
      phonesRotated += 1;
    }

    const { rows: totpUsers } = await client.query(
      `SELECT id, totp_secret_enc
       FROM users
       WHERE totp_secret_enc IS NOT NULL
       FOR UPDATE`
    );

    let totpSecretsRotated = 0;
    for (const user of totpUsers) {
      const { encryptedSecret, keyVersion } = unpackEncryptedTotpSecret(user.totp_secret_enc);
      if (keyVersion === ACTIVE_KEY_VERSION) continue;

      const plainSecret = decryptText(encryptedSecret, keyVersion);
      const { ciphertext, keyVersion: nextVersion } = encryptText(plainSecret, ACTIVE_KEY_VERSION);
      await client.query('UPDATE users SET totp_secret_enc = $1 WHERE id = $2', [
        packEncryptedTotpSecret(ciphertext, nextVersion),
        user.id
      ]);
      totpSecretsRotated += 1;
    }

    await client.query('COMMIT');

    await logSecurityEvent({
      userId: req.user.id,
      actorEmail: req.user.email,
      eventType: 'CRYPTO_KEY_ROTATION',
      severity: 'warning',
      req,
      details: {
        targetKeyVersion: ACTIVE_KEY_VERSION,
        notesRotated,
        phonesRotated,
        totpSecretsRotated
      },
      notifyDiscord: true
    });

    return res.status(200).json({
      message: 'Rotación de llaves completada correctamente',
      activeKeyVersion: ACTIVE_KEY_VERSION,
      notesRotated,
      phonesRotated,
      totpSecretsRotated
    });
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
});

export default router;
