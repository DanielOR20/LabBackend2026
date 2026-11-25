const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '/api').replace(/\/+$/, '');
const MUTABLE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

export class ApiError extends Error {
  constructor(message, { status = 0, details = [] } = {}) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.details = details;
  }
}

const GENERIC_MESSAGES = Object.freeze({
  400: 'Solicitud inválida.',
  401: 'Sesión no válida o credenciales incorrectas.',
  403: 'No tienes permiso para realizar esta acción.',
  404: 'Recurso no encontrado.',
  409: 'No fue posible completar la operación.',
  422: 'No se pudo procesar la solicitud.',
  429: 'Demasiadas solicitudes. Intenta más tarde.',
  500: 'Error interno del servidor. Intenta nuevamente.'
});

/**
 * Lee la cookie legible por JS sv_csrf (double-submit).
 */
export const readCsrfCookie = () => {
  const entry = document.cookie
    .split('; ')
    .find((row) => row.startsWith('sv_csrf='));
  if (!entry) return null;
  try {
    return decodeURIComponent(entry.slice('sv_csrf='.length));
  } catch {
    return null;
  }
};

const buildUrl = (path, params) => {
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  const url = `${API_BASE_URL}${normalizedPath}`;
  if (!params) return url;

  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') {
      search.set(key, String(value));
    }
  }
  const qs = search.toString();
  return qs ? `${url}?${qs}` : url;
};

/**
 * Wrapper seguro de fetch: credenciales incluidas, JSON y X-CSRF-Token automático en métodos mutables.
 */
export const request = async (path, { method = 'GET', body, params } = {}) => {
  const upperMethod = method.toUpperCase();
  const headers = { 'Content-Type': 'application/json', Accept: 'application/json' };

  if (MUTABLE_METHODS.has(upperMethod)) {
    const csrf = readCsrfCookie();
    if (csrf) headers['X-CSRF-Token'] = csrf;
  }

  let response;
  try {
    response = await fetch(buildUrl(path, params), {
      method: upperMethod,
      credentials: 'include',
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined
    });
  } catch {
    throw new ApiError('No se pudo conectar con el servidor. Verifica tu conexión.', { status: 0 });
  }

  let data = null;
  const raw = await response.text();
  if (raw) {
    try {
      data = JSON.parse(raw);
    } catch {
      data = null;
    }
  }

  if (!response.ok) {
    const message =
      (data && typeof data.error === 'string' && data.error) ||
      GENERIC_MESSAGES[response.status] ||
      'Ocurrió un error inesperado.';
    const details = Array.isArray(data?.details)
      ? data.details.map((d) => ({
          field: String(d.field ?? ''),
          message: String(d.message ?? '')
        }))
      : [];
    throw new ApiError(message, { status: response.status, details });
  }

  return data;
};

export const api = {
  get: (path, params) => request(path, { method: 'GET', params }),
  post: (path, body) => request(path, { method: 'POST', body: body ?? {} }),
  put: (path, body) => request(path, { method: 'PUT', body: body ?? {} }),
  patch: (path, body) => request(path, { method: 'PATCH', body: body ?? {} }),
  delete: (path) => request(path, { method: 'DELETE' })
};

/**
 * Convierte un error en texto legible para el usuario (sin trazas técnicas).
 */
export const formatError = (err) => {
  if (!(err instanceof ApiError)) return 'Ocurrió un error inesperado.';
  if (err.details.length === 0) return err.message;
  const lines = err.details.map((d) => (d.field ? `${d.field}: ${d.message}` : d.message));
  return `${err.message} — ${lines.join(' · ')}`;
};
