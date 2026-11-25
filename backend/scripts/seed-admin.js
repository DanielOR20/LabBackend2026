import { z } from 'zod';
import '../src/config/env.js';
import { query, pool } from '../src/config/db.js';
import { logger } from '../src/config/logger.js';
import { hashPassword } from '../src/crypto/password.js';
import { encryptText } from '../src/crypto/vaultCipher.js';
import { logSecurityEvent } from '../src/services/audit.service.js';

const adminSeedSchema = z.object({
  ADMIN_EMAIL: z
    .string()
    .trim()
    .toLowerCase()
    .email('ADMIN_EMAIL debe ser un correo electrónico válido')
    .max(255),
  ADMIN_PASSWORD: z
    .string()
    .min(10, 'ADMIN_PASSWORD debe tener al menos 10 caracteres')
    .max(128, 'ADMIN_PASSWORD no debe superar los 128 caracteres')
    .regex(/[A-Z]/, 'ADMIN_PASSWORD debe incluir al menos una letra mayúscula')
    .regex(/[a-z]/, 'ADMIN_PASSWORD debe incluir al menos una letra minúscula')
    .regex(/[0-9]/, 'ADMIN_PASSWORD debe incluir al menos un número')
    .regex(/[^A-Za-z0-9]/, 'ADMIN_PASSWORD debe incluir al menos un carácter especial'),
  ADMIN_FULL_NAME: z
    .string()
    .trim()
    .min(2, 'ADMIN_FULL_NAME debe tener al menos 2 caracteres')
    .max(120),
  ADMIN_COMPANY: z
    .string()
    .trim()
    .min(2, 'ADMIN_COMPANY debe tener al menos 2 caracteres')
    .max(120),
  ADMIN_PHONE: z
    .string()
    .trim()
    .min(8, 'ADMIN_PHONE debe tener al menos 8 caracteres')
    .max(20)
    .regex(/^\+?[0-9\s().-]{8,20}$/, 'ADMIN_PHONE tiene un formato inválido')
    .refine((val) => {
      const digits = val.replace(/\D/g, '');
      return digits.length >= 7 && digits.length <= 15;
    }, 'ADMIN_PHONE debe contener entre 7 y 15 dígitos')
});

const seedAdmin = async () => {
  const parsed = adminSeedSchema.safeParse({
    ADMIN_EMAIL: process.env.ADMIN_EMAIL,
    ADMIN_PASSWORD: process.env.ADMIN_PASSWORD,
    ADMIN_FULL_NAME: process.env.ADMIN_FULL_NAME,
    ADMIN_COMPANY: process.env.ADMIN_COMPANY,
    ADMIN_PHONE: process.env.ADMIN_PHONE
  });

  if (!parsed.success) {
    console.error('[FATAL] Variables ADMIN_* inválidas o faltantes para seed-admin:');
    for (const issue of parsed.error.issues) {
      console.error(`  - ${issue.path.join('.') || 'ADMIN'}: ${issue.message}`);
    }
    process.exitCode = 1;
    return;
  }

  const { ADMIN_EMAIL, ADMIN_PASSWORD, ADMIN_FULL_NAME, ADMIN_COMPANY, ADMIN_PHONE } = parsed.data;

  const passwordHash = await hashPassword(ADMIN_PASSWORD);
  const { ciphertext: encryptedPhone, keyVersion: phoneKeyVersion } = encryptText(ADMIN_PHONE);

  const { rows } = await query(
    `INSERT INTO users (email, full_name, company_name, password_hash, encrypted_phone, phone_key_version, role)
     VALUES ($1, $2, $3, $4, $5, $6, 'admin')
     ON CONFLICT (email) DO UPDATE
     SET full_name = EXCLUDED.full_name,
         company_name = EXCLUDED.company_name,
         password_hash = EXCLUDED.password_hash,
         encrypted_phone = EXCLUDED.encrypted_phone,
         phone_key_version = EXCLUDED.phone_key_version,
         role = 'admin',
         failed_attempts = 0,
         locked_until = NULL,
         token_version = users.token_version + 1
     RETURNING id, email, role`,
    [ADMIN_EMAIL, ADMIN_FULL_NAME, ADMIN_COMPANY, passwordHash, encryptedPhone, phoneKeyVersion]
  );

  const adminUser = rows[0];

  await logSecurityEvent({
    userId: adminUser.id,
    actorEmail: adminUser.email,
    eventType: 'ADMIN_BOOTSTRAP_SEEDED',
    severity: 'warning',
    details: { role: adminUser.role },
    notifyDiscord: true
  });

  logger.info({ userId: adminUser.id, email: adminUser.email }, 'Administrador inicial aprovisionado');
};

try {
  await seedAdmin();
} catch (err) {
  logger.fatal({ err }, 'Error al ejecutar seed-admin');
  process.exitCode = 1;
} finally {
  await pool.end();
}
