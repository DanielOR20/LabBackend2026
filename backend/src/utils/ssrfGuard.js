const ALLOWED_DISCORD_HOSTS = new Set(['discord.com', 'discordapp.com']);
const REQUIRED_WEBHOOK_PREFIX = '/api/webhooks/';

/**
 * Valida estrictamente que una URL saliente de Discord Webhook cumpla lista blanca anti-SSRF (OWASP A01).
 */
export const validateDiscordWebhookUrl = (rawUrl) => {
  if (typeof rawUrl !== 'string' || rawUrl.trim().length === 0) {
    return false;
  }

  const trimmed = rawUrl.trim();
  if (trimmed.includes('..') || /%2e/i.test(trimmed) || /%252e/i.test(trimmed)) {
    return false;
  }

  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    return false;
  }

  if (parsed.protocol !== 'https:') {
    return false;
  }

  if (parsed.username || parsed.password || parsed.port !== '') {
    return false;
  }

  const hostname = parsed.hostname.toLowerCase();
  if (!ALLOWED_DISCORD_HOSTS.has(hostname)) {
    return false;
  }

  let decodedPathname;
  try {
    decodedPathname = decodeURIComponent(parsed.pathname);
  } catch {
    return false;
  }

  if (
    !parsed.pathname.startsWith(REQUIRED_WEBHOOK_PREFIX) ||
    !decodedPathname.startsWith(REQUIRED_WEBHOOK_PREFIX) ||
    parsed.pathname.length <= REQUIRED_WEBHOOK_PREFIX.length ||
    parsed.pathname.includes('..') ||
    decodedPathname.includes('..')
  ) {
    return false;
  }

  return true;
};
