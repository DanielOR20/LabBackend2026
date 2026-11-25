import pino from 'pino';
import { env } from './env.js';

const REDACT_PATHS = [
  'req.headers.authorization',
  'req.headers.cookie',
  '*.password',
  '*.newPassword',
  '*.password_hash',
  '*.token',
  '*.totpCode',
  '*.secret',
  '*.encrypted_content',
  '*.content',
  '*.phone',
  '*.encrypted_phone',
  '*.totp_secret_enc',
  'password',
  'newPassword',
  'password_hash',
  'token',
  'totpCode',
  'secret',
  'encrypted_content',
  'content',
  'phone',
  'encrypted_phone',
  'totp_secret_enc',
  '*.*.password',
  '*.*.newPassword',
  '*.*.password_hash',
  '*.*.token',
  '*.*.totpCode',
  '*.*.secret',
  '*.*.encrypted_content',
  '*.*.content',
  '*.*.phone',
  '*.*.encrypted_phone',
  '*.*.totp_secret_enc'
];

export const logger = pino({
  level: env.NODE_ENV === 'production' ? 'info' : 'debug',
  timestamp: pino.stdTimeFunctions.isoTime,
  formatters: {
    level(label) {
      return { level: label };
    }
  },
  redact: {
    paths: REDACT_PATHS,
    censor: '[REDACTED]'
  }
});

export default logger;
