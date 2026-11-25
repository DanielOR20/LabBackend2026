import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

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

const { pool } = await import('../src/config/db.js');
const { encryptText, decryptText } = await import('../src/crypto/vaultCipher.js');
const {
  ALLOWED_CATEGORIES,
  MAX_NOTES_PER_USER,
  noteBodySchema,
  noteIdParamSchema,
  notesQuerySchema
} = await import('../src/routes/notes.routes.js');
const { requireAdmin } = await import('../src/middlewares/auth.js');

after(async () => {
  await pool.end();
});

test('1. Rotación de llaves AES-256-GCM (v1 -> descifrado -> re-cifrado v2 con nuevo IV)', () => {
  const originalSecret = 'API_SECRET_PROD=sk_live_99887766554433221100';

  const v1Encrypted = encryptText(originalSecret, 1);
  assert.equal(v1Encrypted.keyVersion, 1);
  const [ivV1] = v1Encrypted.ciphertext.split('.');

  const decryptedFromV1 = decryptText(v1Encrypted.ciphertext, v1Encrypted.keyVersion);
  assert.equal(decryptedFromV1, originalSecret);

  const v2ReEncrypted = encryptText(decryptedFromV1, 2);
  assert.equal(v2ReEncrypted.keyVersion, 2);
  const [ivV2] = v2ReEncrypted.ciphertext.split('.');

  assert.notEqual(ivV1, ivV2);
  assert.notEqual(v1Encrypted.ciphertext, v2ReEncrypted.ciphertext);
  assert.equal(decryptText(v2ReEncrypted.ciphertext, 2), originalSecret);
  assert.throws(() => decryptText(v2ReEncrypted.ciphertext, 1));
});

test('2. Validación Zod para notas: límites de negocio, categorías, etiquetas y UUID', () => {
  assert.equal(MAX_NOTES_PER_USER, 50);
  assert.deepEqual(ALLOWED_CATEGORIES, [
    'General',
    'Credenciales',
    'Infraestructura',
    'Finanzas',
    'Legal',
    'Incidentes'
  ]);

  // Nota válida en el límite exacto
  const validNote = noteBodySchema.safeParse({
    title: 'Llaves SSH Bastion',
    category: 'Infraestructura',
    tags: ['prod-eu', 'ssh-bastion', 'tier_1'],
    content: 'a'.repeat(10000)
  });
  assert.equal(validNote.success, true);

  // Categoría no permitida
  const invalidCategory = noteBodySchema.safeParse({
    title: 'Nota prueba',
    category: 'Personal',
    tags: ['ok'],
    content: 'secreto'
  });
  assert.equal(invalidCategory.success, false);

  // Exceso de etiquetas (> 10)
  const tooManyTags = noteBodySchema.safeParse({
    title: 'Nota prueba',
    category: 'General',
    tags: Array.from({ length: 11 }, (_, idx) => `tag-${idx}`),
    content: 'secreto'
  });
  assert.equal(tooManyTags.success, false);

  // Etiqueta con caracteres inválidos
  const invalidTagChars = noteBodySchema.safeParse({
    title: 'Nota prueba',
    category: 'General',
    tags: ['tag invalido!'],
    content: 'secreto'
  });
  assert.equal(invalidTagChars.success, false);

  // Contenido > 10,000 caracteres
  const oversizedContent = noteBodySchema.safeParse({
    title: 'Nota prueba',
    category: 'General',
    tags: [],
    content: 'x'.repeat(10001)
  });
  assert.equal(oversizedContent.success, false);

  // Validación de UUID y query params
  assert.equal(noteIdParamSchema.safeParse({ id: 'not-a-uuid' }).success, false);
  assert.equal(
    noteIdParamSchema.safeParse({ id: '550e8400-e29b-41d4-a716-446655440000' }).success,
    true
  );
  assert.equal(notesQuerySchema.safeParse({ category: 'Finanzas', search: 'banco' }).success, true);
  assert.equal(notesQuerySchema.safeParse({ category: 'Invalida' }).success, false);
});

test('3. Control RBAC: requireAdmin devuelve HTTP 403 para role=user y permite role=admin', async () => {
  const createMockRes = () => ({
    statusCode: 0,
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.body = payload;
      return this;
    }
  });

  // Usuario estándar -> 403
  const userReq = {
    user: { id: '550e8400-e29b-41d4-a716-446655440001', email: 'user@securevault.test', role: 'user' },
    originalUrl: '/api/admin/overview',
    method: 'GET',
    ip: '127.0.0.1',
    get: () => 'node-test'
  };
  const userRes = createMockRes();
  let userNextCalled = false;

  await requireAdmin(userReq, userRes, () => {
    userNextCalled = true;
  });

  assert.equal(userNextCalled, false);
  assert.equal(userRes.statusCode, 403);
  assert.deepEqual(userRes.body, { error: 'Acceso denegado' });

  // Administrador -> next()
  const adminReq = {
    user: { id: '550e8400-e29b-41d4-a716-446655440002', email: 'admin@securevault.test', role: 'admin' },
    originalUrl: '/api/admin/overview',
    method: 'GET',
    ip: '127.0.0.1',
    get: () => 'node-test'
  };
  const adminRes = createMockRes();
  let adminNextCalled = false;

  await requireAdmin(adminReq, adminRes, () => {
    adminNextCalled = true;
  });

  assert.equal(adminNextCalled, true);
  assert.equal(adminRes.statusCode, 0);
});
