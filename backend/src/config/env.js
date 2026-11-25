import 'dotenv/config';
import { z } from 'zod';

const KEY_ENV_PREFIX = 'DATA_ENCRYPTION_KEY_V';
const KEY_ENV_PATTERN = /^DATA_ENCRYPTION_KEY_V([1-9]\d*)$/;

const isValidBase64Key32 = (value) => {
  if (typeof value !== 'string') return false;
  const trimmed = value.trim();
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(trimmed)) return false;

  const decoded = Buffer.from(trimmed, 'base64');
  if (decoded.length !== 32) return false;

  return decoded.toString('base64').replace(/=+$/, '') === trimmed.replace(/=+$/, '');
};

const isValidCorsOrigins = (value) => {
  const origins = value
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);

  if (origins.length === 0) return false;

  return origins.every((origin) => {
    if (origin === '*') return false;
    try {
      const parsedUrl = new URL(origin);
      return parsedUrl.protocol === 'http:' || parsedUrl.protocol === 'https:';
    } catch {
      return false;
    }
  });
};

const isValidPostgresUrl = (value) => {
  try {
    const parsedUrl = new URL(value);
    return parsedUrl.protocol === 'postgres:' || parsedUrl.protocol === 'postgresql:';
  } catch {
    return false;
  }
};

const isValidOptionalHttpsUrl = (value) => {
  if (!value) return true;
  try {
    const parsedUrl = new URL(value);
    return parsedUrl.protocol === 'https:';
  } catch {
    return false;
  }
};

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().min(1).max(65535).default(4000),
  CORS_ORIGIN: z
    .string()
    .trim()
    .min(1, 'CORS_ORIGIN es obligatorio')
    .refine(isValidCorsOrigins, 'CORS_ORIGIN debe contener URLs http:// o https:// válidas (sin wildcard *)'),
  DATABASE_URL: z
    .string()
    .trim()
    .min(1, 'DATABASE_URL es obligatorio')
    .refine(isValidPostgresUrl, 'DATABASE_URL debe usar el esquema postgres:// o postgresql://'),
  DB_SSL: z.preprocess(
    (val) => (val === undefined ? undefined : String(val).trim().toLowerCase()),
    z
      .enum(['true', 'false'])
      .default('false')
      .transform((val) => val === 'true')
  ),
  JWT_ACCESS_SECRET: z
    .string()
    .trim()
    .min(64, 'JWT_ACCESS_SECRET debe tener al menos 64 caracteres')
    .refine((val) => !val.startsWith('replace_with_'), 'JWT_ACCESS_SECRET no puede usar el valor de ejemplo'),
  CSRF_SECRET: z
    .string()
    .trim()
    .min(64, 'CSRF_SECRET debe tener al menos 64 caracteres')
    .refine((val) => !val.startsWith('replace_with_'), 'CSRF_SECRET no puede usar el valor de ejemplo'),
  ACTIVE_KEY_VERSION: z.coerce
    .number()
    .int('ACTIVE_KEY_VERSION debe ser un número entero')
    .positive('ACTIVE_KEY_VERSION debe ser mayor que 0'),
  DATA_ENCRYPTION_KEY_V1: z
    .string()
    .trim()
    .refine(isValidBase64Key32, 'DATA_ENCRYPTION_KEY_V1 debe ser una clave Base64 válida de exactamente 32 bytes'),
  DISCORD_WEBHOOK_URL: z
    .string()
    .trim()
    .optional()
    .transform((val) => (val === '' ? undefined : val))
    .refine(isValidOptionalHttpsUrl, 'DISCORD_WEBHOOK_URL debe ser una URL https:// válida')
});

const failClosed = (errors) => {
  console.error('[FATAL] Configuración de entorno inválida (fail-closed):');
  for (const { variable, message } of errors) {
    console.error(`  - ${variable}: ${message}`);
  }
  process.exit(1);
};

const parsed = envSchema.safeParse(process.env);
if (!parsed.success) {
  const formattedErrors = parsed.error.issues.map((issue) => ({
    variable: issue.path.join('.') || 'ENV',
    message: issue.message
  }));
  failClosed(formattedErrors);
}

const encryptionKeys = new Map();
const keyErrors = [];

for (const [envKey, envValue] of Object.entries(process.env)) {
  if (!envKey.startsWith(KEY_ENV_PREFIX)) continue;

  const match = KEY_ENV_PATTERN.exec(envKey);
  if (!match) {
    keyErrors.push({
      variable: envKey,
      message: 'Formato de versión inválido; use DATA_ENCRYPTION_KEY_V<n> con n >= 1'
    });
    continue;
  }

  const version = Number.parseInt(match[1], 10);
  if (!isValidBase64Key32(envValue)) {
    keyErrors.push({
      variable: envKey,
      message: `${envKey} debe ser una clave Base64 válida de exactamente 32 bytes`
    });
    continue;
  }

  encryptionKeys.set(version, Buffer.from(envValue.trim(), 'base64'));
}

if (keyErrors.length > 0) {
  failClosed(keyErrors);
}

if (!encryptionKeys.has(parsed.data.ACTIVE_KEY_VERSION)) {
  failClosed([
    {
      variable: 'ACTIVE_KEY_VERSION',
      message: `No existe ${KEY_ENV_PREFIX}${parsed.data.ACTIVE_KEY_VERSION} válida para ACTIVE_KEY_VERSION=${parsed.data.ACTIVE_KEY_VERSION}`
    }
  ]);
}

export const ENCRYPTION_KEYS = encryptionKeys;
export const ACTIVE_KEY_VERSION = parsed.data.ACTIVE_KEY_VERSION;
export const env = Object.freeze(parsed.data);
export default env;
