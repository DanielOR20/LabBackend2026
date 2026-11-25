import argon2 from 'argon2';

const ARGON2_OPTIONS = Object.freeze({
  type: argon2.argon2id,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1
});

/**
 * Hash precalculado válido de Argon2id para igualar tiempos de respuesta
 * cuando un correo no existe en el flujo de login (mitigación de enumeración por tiempo).
 */
export const DUMMY_PASSWORD_HASH =
  '$argon2id$v=19$m=19456,t=2,p=1$+PGVh08MfFQAlFCpf3R0eA$jScJGKW+QUhplKyqNM/v9WmRzNDH/eKKPz2EOyMCv78';

/**
 * Genera un hash Argon2id seguro a partir de una contraseña en texto plano.
 */
export const hashPassword = async (plainPassword) => {
  if (typeof plainPassword !== 'string' || plainPassword.length === 0) {
    throw new TypeError('La contraseña debe ser una cadena no vacía');
  }

  return argon2.hash(plainPassword, ARGON2_OPTIONS);
};

/**
 * Verifica una contraseña contra su hash Argon2id manejando formatos inválidos de forma segura.
 */
export const verifyPassword = async (hash, plainPassword) => {
  if (
    typeof hash !== 'string' ||
    typeof plainPassword !== 'string' ||
    hash.length === 0 ||
    plainPassword.length === 0
  ) {
    return false;
  }

  try {
    return await argon2.verify(hash, plainPassword);
  } catch {
    return false;
  }
};
