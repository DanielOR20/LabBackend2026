import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

// Asegura variables de prueba (incluyendo V2 para pruebas de rotación) antes de cargar env.js
process.env.NODE_ENV ??= 'test';
process.env.PORT ??= '4000';
process.env.CORS_ORIGIN ??= 'http://localhost:5173';
process.env.DATABASE_URL ??= 'postgresql://postgres:password@localhost:5432/securevault';
process.env.DB_SSL ??= 'false';
process.env.JWT_ACCESS_SECRET ??= randomBytes(32).toString('hex');
process.env.CSRF_SECRET ??= randomBytes(32).toString('hex');
process.env.ACTIVE_KEY_VERSION ??= '1';
process.env.DATA_ENCRYPTION_KEY_V1 ??= randomBytes(32).toString('base64');
process.env.DATA_ENCRYPTION_KEY_V2 ??= randomBytes(32).toString('base64');

const { hashPassword, verifyPassword, DUMMY_PASSWORD_HASH } = await import(
  '../src/crypto/password.js'
);
const { encryptText, decryptText, maskSensitiveData } = await import(
  '../src/crypto/vaultCipher.js'
);
const {
  generateSecureToken,
  hashToken,
  signJwt,
  verifyJwt,
  generateCsrfToken,
  verifyCsrfToken
} = await import('../src/crypto/tokens.js');
const { generateTotpSetup, verifyTotpCode, unpackEncryptedTotpSecret } = await import(
  '../src/services/totp.service.js'
);
const { generateSync } = await import('otplib');

const flipCharAt = (str, index = 0) => {
  const replacement = str[index] === 'A' ? 'B' : 'A';
  return `${str.slice(0, index)}${replacement}${str.slice(index + 1)}`;
};

test('1. Argon2id: hash y verificación correcta, incorrecta y manejo seguro de formato inválido', async () => {
  const password = 'Str0ng!Vault#Password2026';
  const hash = await hashPassword(password);

  assert.equal(hash.startsWith('$argon2id$'), true);
  assert.equal(await verifyPassword(hash, password), true);
  assert.equal(await verifyPassword(hash, 'WrongPassword!123'), false);
  assert.equal(await verifyPassword('not-a-valid-argon2-hash', password), false);
  assert.equal(await verifyPassword(DUMMY_PASSWORD_HASH, password), false);
});

test('2. AES-256-GCM: cifrado/descifrado, IVs únicos, rotación v1 vs v2 y rechazo por manipulación', () => {
  const secretNote = 'Credencial secreta de producción: root-key-9911';

  const encA = encryptText(secretNote, 1);
  const encB = encryptText(secretNote, 1);

  assert.equal(encA.keyVersion, 1);
  assert.notEqual(encA.ciphertext, encB.ciphertext);

  const [ivA, tagA, dataA] = encA.ciphertext.split('.');
  const [ivB] = encB.ciphertext.split('.');
  assert.notEqual(ivA, ivB);
  assert.equal(decryptText(encA.ciphertext, 1), secretNote);

  // Rotación de llaves v1 vs v2
  const encV2 = encryptText(secretNote, 2);
  assert.equal(encV2.keyVersion, 2);
  assert.equal(decryptText(encV2.ciphertext, 2), secretNote);
  assert.throws(() => decryptText(encV2.ciphertext, 1));
  assert.throws(() => decryptText(encA.ciphertext, 2));
  assert.throws(() => decryptText(encA.ciphertext, 99));

  // Alteración de 1 carácter en auth tag y en ciphertext
  const tamperedTag = [ivA, flipCharAt(tagA, 0), dataA].join('.');
  const tamperedData = [ivA, tagA, flipCharAt(dataA, 0)].join('.');
  assert.throws(() => decryptText(tamperedTag, 1));
  assert.throws(() => decryptText(tamperedData, 1));

  // Enmascarado de datos sensibles
  assert.equal(maskSensitiveData('555-123-4567'), '***-***-4567');
  assert.equal(maskSensitiveData('1234'), '****');
});

test('3. Tokens: JWT HS256, rechazo de manipulación/expiración/alg=none, SHA-256 y CSRF', () => {
  // JWT válido
  const jwt = signJwt({ sub: 'user-123', role: 'user', tv: 1 }, 300);
  const decoded = verifyJwt(jwt);
  assert.equal(decoded.sub, 'user-123');
  assert.equal(decoded.role, 'user');
  assert.equal(decoded.tv, 1);

  // JWT manipulado en payload o firma
  const [hdr, pay, sig] = jwt.split('.');
  assert.throws(() => verifyJwt(`${hdr}.${flipCharAt(pay, 0)}.${sig}`));
  assert.throws(() => verifyJwt(`${hdr}.${pay}.${flipCharAt(sig, 0)}`));

  // JWT expirado
  const expiredJwt = signJwt({ sub: 'user-123', role: 'user', tv: 1 }, -5);
  assert.throws(() => verifyJwt(expiredJwt), /expirado/i);

  // Rechazo explícito de alg: none (OWASP A08)
  const noneHeader = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const fakePayload = Buffer.from(
    JSON.stringify({ sub: 'admin', role: 'admin', exp: Math.floor(Date.now() / 1000) + 600 })
  ).toString('base64url');
  assert.throws(() => verifyJwt(`${noneHeader}.${fakePayload}.`), /no permitido|inválido/i);
  assert.throws(() => verifyJwt(`${noneHeader}.${fakePayload}.${sig}`), /no permitido|inválido/i);

  // Tokens SHA-256
  const { rawToken, tokenHash } = generateSecureToken(32);
  assert.equal(rawToken.length, 64);
  assert.equal(tokenHash.length, 64);
  assert.equal(hashToken(rawToken), tokenHash);

  // CSRF HMAC ligado a sesión
  const binding = 'user-123:1';
  const csrfToken = generateCsrfToken(binding);
  assert.equal(verifyCsrfToken(csrfToken, binding), true);
  assert.equal(verifyCsrfToken(csrfToken, 'user-123:2'), false);
  assert.equal(verifyCsrfToken(flipCharAt(csrfToken, 0), binding), false);
});

test('4. TOTP MFA: generación de setup cifrado y validación de código de 6 dígitos', async () => {
  const setup = await generateTotpSetup('alice@securevault.test');
  assert.equal(setup.qrDataUrl.startsWith('data:image/png;base64,'), true);
  assert.equal(setup.otpauthUrl.includes('issuer=SecureVault'), true);

  const { encryptedSecret, keyVersion } = unpackEncryptedTotpSecret(setup.packedSecret);
  const validCode = generateSync({ secret: setup.manualKey });

  assert.equal(verifyTotpCode(encryptedSecret, keyVersion, validCode), true);
  assert.equal(verifyTotpCode(encryptedSecret, keyVersion, 'abcdef'), false);
});
