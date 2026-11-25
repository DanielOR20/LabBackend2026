import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { env } from '../config/env.js';

const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const SHA256_HEX_PATTERN = /^[0-9a-f]{64}$/i;
const JWT_HEADER_B64 = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');

/**
 * Calcula el digest SHA-256 en formato hexadecimal para un token sin procesar.
 */
export const hashToken = (rawToken) => {
  if (typeof rawToken !== 'string' || rawToken.length === 0) {
    throw new TypeError('El token a hashear debe ser una cadena no vacía');
  }

  return createHash('sha256').update(rawToken).digest('hex');
};

/**
 * Genera un token criptográficamente aleatorio y su hash SHA-256 para almacenamiento seguro.
 */
export const generateSecureToken = (bytes = 32) => {
  const rawToken = randomBytes(bytes).toString('hex');
  return {
    rawToken,
    tokenHash: hashToken(rawToken)
  };
};

/**
 * Firma un JWT compacto usando exclusivamente HMAC-SHA256 (HS256).
 */
export const signJwt = (payload, expiresInSeconds = 900) => {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new TypeError('El payload del JWT debe ser un objeto válido');
  }
  if (!Number.isFinite(expiresInSeconds)) {
    throw new TypeError('expiresInSeconds debe ser un número finito');
  }

  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + Math.trunc(expiresInSeconds);
  const payloadB64 = Buffer.from(JSON.stringify({ ...payload, iat, exp })).toString('base64url');
  const signingInput = `${JWT_HEADER_B64}.${payloadB64}`;
  const signatureB64 = createHmac('sha256', env.JWT_ACCESS_SECRET).update(signingInput).digest('base64url');

  return `${signingInput}.${signatureB64}`;
};

/**
 * Verifica un JWT HS256 en tiempo constante rechazando alg='none' o algoritmos distintos de HS256 (OWASP A08).
 */
export const verifyJwt = (token) => {
  if (typeof token !== 'string' || token.length === 0) {
    throw new Error('Token JWT ausente o inválido');
  }

  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Formato de token JWT inválido');
  }

  const [headerB64, payloadB64, signatureB64] = parts;
  if (!BASE64URL_PATTERN.test(headerB64) || !BASE64URL_PATTERN.test(payloadB64)) {
    throw new Error('Codificación base64url inválida en token JWT');
  }

  let header;
  try {
    header = JSON.parse(Buffer.from(headerB64, 'base64url').toString('utf8'));
  } catch {
    throw new Error('Cabecera JWT malformada');
  }

  if (!header || typeof header !== 'object' || header.alg !== 'HS256' || header.typ !== 'JWT') {
    throw new Error('Algoritmo o tipo JWT no permitido');
  }

  if (!BASE64URL_PATTERN.test(signatureB64)) {
    throw new Error('Firma JWT inválida');
  }

  const expectedSignature = createHmac('sha256', env.JWT_ACCESS_SECRET)
    .update(`${headerB64}.${payloadB64}`)
    .digest();

  const actualSignature = Buffer.from(signatureB64, 'base64url');
  if (
    actualSignature.toString('base64url') !== signatureB64 ||
    actualSignature.length !== expectedSignature.length ||
    !timingSafeEqual(actualSignature, expectedSignature)
  ) {
    throw new Error('Firma JWT inválida');
  }

  let payload;
  try {
    payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
  } catch {
    throw new Error('Payload JWT malformado');
  }

  if (!payload || typeof payload !== 'object' || typeof payload.exp !== 'number') {
    throw new Error('Claims JWT inválidos');
  }

  const now = Math.floor(Date.now() / 1000);
  if (now >= payload.exp) {
    throw new Error('Token JWT expirado');
  }

  return payload;
};

/**
 * Genera un token CSRF ligado a la sesión mediante HMAC-SHA256.
 */
export const generateCsrfToken = (sessionBinding) => {
  if (typeof sessionBinding !== 'string' || sessionBinding.length === 0) {
    throw new TypeError('sessionBinding es obligatorio para generar el token CSRF');
  }

  const nonce = randomBytes(16).toString('hex');
  const mac = createHmac('sha256', env.CSRF_SECRET)
    .update(`${sessionBinding}.${nonce}`)
    .digest('hex');

  return `${nonce}.${mac}`;
};

/**
 * Verifica un token CSRF contra sessionBinding en tiempo constante.
 */
export const verifyCsrfToken = (token, sessionBinding) => {
  if (
    typeof token !== 'string' ||
    typeof sessionBinding !== 'string' ||
    token.length === 0 ||
    sessionBinding.length === 0
  ) {
    return false;
  }

  const parts = token.split('.');
  if (parts.length !== 2) {
    return false;
  }

  const [nonce, macHex] = parts;
  if (!nonce || !SHA256_HEX_PATTERN.test(macHex)) {
    return false;
  }

  const expectedMac = createHmac('sha256', env.CSRF_SECRET)
    .update(`${sessionBinding}.${nonce}`)
    .digest();
  const actualMac = Buffer.from(macHex, 'hex');

  if (actualMac.length !== expectedMac.length) {
    return false;
  }

  return timingSafeEqual(actualMac, expectedMac);
};
