import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { ENCRYPTION_KEYS, ACTIVE_KEY_VERSION } from '../config/env.js';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const BASE64_PATTERN = /^[A-Za-z0-9+/]+={0,2}$/;

const decodeStrictBase64 = (value) => {
  if (value === '') return Buffer.alloc(0);
  if (typeof value !== 'string' || !BASE64_PATTERN.test(value)) {
    throw new Error('Codificación Base64 inválida en payload cifrado');
  }
  const buffer = Buffer.from(value, 'base64');
  if (buffer.toString('base64') !== value) {
    throw new Error('Payload Base64 no canónico o alterado');
  }
  return buffer;
};

/**
 * Cifra texto plano en UTF-8 utilizando AES-256-GCM con IV aleatorio único de 12 bytes.
 */
export const encryptText = (plaintext, version = ACTIVE_KEY_VERSION) => {
  if (typeof plaintext !== 'string') {
    throw new TypeError('El texto a cifrar debe ser una cadena');
  }

  const keyVersion = Number(version);
  const key = ENCRYPTION_KEYS.get(keyVersion);
  if (!key) {
    throw new Error(`Versión de clave de cifrado no encontrada: v${version}`);
  }

  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    ciphertext: [iv, tag, encrypted].map((buf) => buf.toString('base64')).join('.'),
    keyVersion
  };
};

/**
 * Descifra un payload AES-256-GCM seleccionando la clave histórica correspondiente a keyVersion.
 */
export const decryptText = (payload, keyVersion) => {
  if (typeof payload !== 'string' || payload.length === 0) {
    throw new Error('Payload cifrado inválido');
  }

  const key = ENCRYPTION_KEYS.get(Number(keyVersion));
  if (!key) {
    throw new Error(`Versión de clave de cifrado no disponible: v${keyVersion}`);
  }

  const parts = payload.split('.');
  if (parts.length !== 3) {
    throw new Error('Estructura de payload cifrado inválida');
  }

  const [ivB64, tagB64, dataB64] = parts;
  if (!ivB64 || !tagB64) {
    throw new Error('Faltan componentes obligatorios en el payload cifrado');
  }

  const iv = decodeStrictBase64(ivB64);
  const tag = decodeStrictBase64(tagB64);
  const data = decodeStrictBase64(dataB64);

  if (iv.length !== IV_LENGTH || tag.length !== AUTH_TAG_LENGTH) {
    throw new Error('Longitudes de IV o AuthTag inválidas');
  }

  try {
    const decipher = createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(data), decipher.final()]);
    return decrypted.toString('utf8');
  } catch {
    throw new Error('No se pudo descifrar el payload o falló la verificación de integridad');
  }
};

/**
 * Enmascara datos sensibles dejando visibles únicamente los últimos dígitos (ej. ***-***-1234).
 */
export const maskSensitiveData = (plaintext, visibleDigits = 4) => {
  if (typeof plaintext !== 'string' || plaintext.length === 0) {
    return '';
  }

  const safeVisible = Math.max(0, Number.isInteger(visibleDigits) ? visibleDigits : 4);
  if (safeVisible === 0 || plaintext.length <= safeVisible) {
    return '*'.repeat(plaintext.length);
  }

  const suffix = plaintext.slice(-safeVisible);
  const maskedPrefix = plaintext.slice(0, -safeVisible).replace(/[A-Za-z0-9]/g, '*');
  return `${maskedPrefix}${suffix}`;
};
