import { generateSecret, generateURI, verifySync } from 'otplib';
import QRCode from 'qrcode';
import { ACTIVE_KEY_VERSION } from '../config/env.js';
import { encryptText, decryptText } from '../crypto/vaultCipher.js';

const ISSUER = 'SecureVault';
const TOTP_EPOCH_TOLERANCE_SECONDS = 30;
const ENCRYPTED_SECRET_PREFIX_PATTERN = /^v([1-9]\d*):(.+)$/;

/**
 * Empaqueta el secreto TOTP cifrado junto con su versión de clave para rotación futura.
 */
export const packEncryptedTotpSecret = (ciphertext, keyVersion) => `v${keyVersion}:${ciphertext}`;

/**
 * Extrae el ciphertext y la versión de clave de `totp_secret_enc`.
 */
export const unpackEncryptedTotpSecret = (storedValue) => {
  if (typeof storedValue !== 'string' || storedValue.length === 0) {
    throw new Error('Secreto TOTP cifrado ausente');
  }

  const match = ENCRYPTED_SECRET_PREFIX_PATTERN.exec(storedValue);
  if (match) {
    return {
      keyVersion: Number.parseInt(match[1], 10),
      encryptedSecret: match[2]
    };
  }

  return {
    keyVersion: ACTIVE_KEY_VERSION,
    encryptedSecret: storedValue
  };
};

/**
 * Genera un nuevo secreto TOTP, URL otpauth://, secreto cifrado y código QR en Data URL.
 */
export const generateTotpSetup = async (email) => {
  if (typeof email !== 'string' || email.trim().length === 0) {
    throw new TypeError('El correo electrónico es obligatorio para generar TOTP');
  }

  const secret = generateSecret();
  const otpauthUrl = generateURI({
    issuer: ISSUER,
    label: email.trim(),
    secret
  });
  const { ciphertext, keyVersion } = encryptText(secret);
  const qrDataUrl = await QRCode.toDataURL(otpauthUrl);

  return {
    encryptedSecret: ciphertext,
    keyVersion,
    packedSecret: packEncryptedTotpSecret(ciphertext, keyVersion),
    manualKey: secret,
    qrDataUrl,
    otpauthUrl
  };
};

/**
 * Descifra el secreto TOTP y verifica el código de 6 dígitos con tolerancia de ±1 ventana (30s).
 */
export const verifyTotpCode = (encryptedSecret, keyVersion, code) => {
  if (typeof code !== 'string' || !/^\d{6}$/.test(code.trim())) {
    return false;
  }

  try {
    const secret = decryptText(encryptedSecret, keyVersion);
    const result = verifySync({
      secret,
      token: code.trim(),
      epochTolerance: TOTP_EPOCH_TOLERANCE_SECONDS
    });
    return result.valid === true;
  } catch {
    return false;
  }
};
