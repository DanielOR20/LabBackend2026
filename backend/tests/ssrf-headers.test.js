import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { Duplex } from 'node:stream';
import { IncomingMessage, ServerResponse } from 'node:http';

process.env.NODE_ENV ??= 'test';
process.env.PORT ??= '4000';
process.env.CORS_ORIGIN ??= 'http://localhost:5173';
process.env.DATABASE_URL ??= 'postgresql://postgres:password@localhost:5432/securevault';
process.env.DB_SSL ??= 'false';
process.env.JWT_ACCESS_SECRET ??= randomBytes(32).toString('hex');
process.env.CSRF_SECRET ??= randomBytes(32).toString('hex');
process.env.ACTIVE_KEY_VERSION ??= '1';
process.env.DATA_ENCRYPTION_KEY_V1 ??= randomBytes(32).toString('base64');

const { pool } = await import('../src/config/db.js');
const { validateDiscordWebhookUrl } = await import('../src/utils/ssrfGuard.js');
const { validateDiscordWebhookUrl: reexportedValidator } = await import(
  '../src/services/audit.service.js'
);
const { default: app } = await import('../src/app.js');

after(async () => {
  await pool.end();
});

const invokeApp = (expressApp, { method = 'GET', url = '/api/health', headers = {} } = {}) =>
  new Promise((resolve, reject) => {
    const chunks = [];
    const socket = new Duplex({
      read() {},
      write(chunk, _encoding, callback) {
        chunks.push(Buffer.from(chunk));
        callback();
      }
    });
    socket.remoteAddress = '127.0.0.1';

    const req = new IncomingMessage(socket);
    req.method = method;
    req.url = url;
    req.headers = { host: 'localhost:4000', ...headers };

    const res = new ServerResponse(req);
    res.assignSocket(socket);

    res.on('finish', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      const headerEnd = raw.indexOf('\r\n\r\n');
      const body = headerEnd !== -1 ? raw.slice(headerEnd + 4) : '';
      resolve({
        statusCode: res.statusCode,
        headers: res.getHeaders(),
        body
      });
    });

    res.on('error', reject);
    expressApp(req, res);
    req.push(null);
  });

test('1. Anti-SSRF (OWASP A01): validateDiscordWebhookUrl acepta lista blanca y bloquea URLs peligrosas', () => {
  assert.equal(validateDiscordWebhookUrl, reexportedValidator);

  // Válidas
  assert.equal(
    validateDiscordWebhookUrl('https://discord.com/api/webhooks/123456/abcdef'),
    true
  );
  assert.equal(
    validateDiscordWebhookUrl('https://discordapp.com/api/webhooks/987654/tokenXYZ'),
    true
  );

  // Bloqueadas (metadatos cloud, localhost, dominio arbitrario, HTTP sin TLS, puertos, traversal)
  assert.equal(validateDiscordWebhookUrl('http://169.254.169.254/latest/meta-data/'), false);
  assert.equal(validateDiscordWebhookUrl('http://localhost:4000/api/webhooks/1'), false);
  assert.equal(validateDiscordWebhookUrl('https://evil.com/api/webhooks/1'), false);
  assert.equal(validateDiscordWebhookUrl('http://discord.com/api/webhooks/1'), false);
  assert.equal(validateDiscordWebhookUrl('https://discord.com:8443/api/webhooks/1/abc'), false);
  assert.equal(validateDiscordWebhookUrl('https://evil.discord.com/api/webhooks/1/abc'), false);
  assert.equal(validateDiscordWebhookUrl('https://discord.com/api/webhooks/1/../users'), false);
  assert.equal(validateDiscordWebhookUrl('https://discord.com/api/webhooks/1/%2e%2e/users'), false);
  assert.equal(validateDiscordWebhookUrl('https://discord.com/api/v10/users/@me'), false);
  assert.equal(validateDiscordWebhookUrl('file:///etc/passwd'), false);
  assert.equal(validateDiscordWebhookUrl(''), false);
});

test('2. Cabeceras de seguridad (OWASP A02): Express devuelve CSP, Referrer-Policy, Permissions-Policy, HSTS, X-Frame-Options y omite X-Powered-By', async () => {
  const response = await invokeApp(app, { method: 'GET', url: '/api/health' });

  assert.equal(response.statusCode, 200);
  const parsedBody = JSON.parse(response.body);
  assert.equal(parsedBody.status, 'ok');

  assert.equal(response.headers['x-powered-by'], undefined);
  assert.ok(
    typeof response.headers['content-security-policy'] === 'string' &&
      response.headers['content-security-policy'].includes("default-src 'self'"),
    'Content-Security-Policy debe incluir default-src self'
  );
  assert.equal(response.headers['referrer-policy'], 'strict-origin-when-cross-origin');
  assert.equal(
    response.headers['permissions-policy'],
    'camera=(), microphone=(), geolocation=(), payment=()'
  );
  assert.equal(
    response.headers['strict-transport-security'],
    'max-age=31536000; includeSubDomains; preload'
  );
  assert.equal(response.headers['x-frame-options'], 'DENY');
  assert.equal(response.headers['x-content-type-options'], 'nosniff');
});
