import { Router } from 'express';
import { z } from 'zod';
import { query, getClient } from '../config/db.js';
import { encryptText, decryptText } from '../crypto/vaultCipher.js';
import { logSecurityEvent } from '../services/audit.service.js';
import { validateBody, validateParams } from '../middlewares/validate.js';
import { requireAuth, requireCsrf } from '../middlewares/auth.js';

const router = Router();

export const MAX_NOTES_PER_USER = 50;
export const ALLOWED_CATEGORIES = [
  'General',
  'Credenciales',
  'Infraestructura',
  'Finanzas',
  'Legal',
  'Incidentes'
];

const TAG_PATTERN = /^[A-Za-z0-9_-]+$/;

export const noteIdParamSchema = z.object({
  id: z.string().uuid('ID de nota inválido')
});

export const noteBodySchema = z.object({
  title: z
    .string()
    .trim()
    .min(1, 'El título es obligatorio')
    .max(150, 'El título no debe superar los 150 caracteres'),
  category: z.enum(ALLOWED_CATEGORIES).default('General'),
  tags: z
    .array(
      z
        .string()
        .trim()
        .min(1, 'La etiqueta no puede estar vacía')
        .max(30, 'Cada etiqueta debe tener como máximo 30 caracteres')
        .regex(TAG_PATTERN, 'Las etiquetas solo pueden contener caracteres alfanuméricos y guiones')
    )
    .max(10, 'Máximo 10 etiquetas por nota')
    .default([]),
  content: z
    .string()
    .max(10000, 'El contenido no debe superar los 10,000 caracteres')
    .refine((val) => val.trim().length > 0, 'El contenido es obligatorio')
});

export const notesQuerySchema = z.object({
  category: z
    .string()
    .trim()
    .optional()
    .transform((val) => (val === '' ? undefined : val))
    .pipe(z.enum(ALLOWED_CATEGORIES).optional()),
  search: z
    .string()
    .trim()
    .max(100, 'El término de búsqueda no debe superar los 100 caracteres')
    .optional()
    .transform((val) => (val === '' ? undefined : val))
});

const formatNote = (row, content) => ({
  id: row.id,
  title: row.title,
  category: row.category,
  tags: row.tags,
  content,
  keyVersion: row.key_version,
  createdAt: row.created_at,
  updatedAt: row.updated_at
});

const findOwnedNoteOrReject = async ({ noteId, user, attemptedAction, req, res }) => {
  const { rows } = await query(
    `SELECT id, owner_id, title, category, tags, encrypted_content, key_version, created_at, updated_at
     FROM vault_notes
     WHERE id = $1`,
    [noteId]
  );

  const note = rows[0];
  if (!note) {
    res.status(404).json({ error: 'Nota no encontrada' });
    return null;
  }

  if (note.owner_id !== user.id) {
    await logSecurityEvent({
      userId: user.id,
      actorEmail: user.email,
      eventType: 'IDOR_ATTEMPT_BLOCKED',
      severity: 'warning',
      req,
      details: { targetNoteId: note.id, attemptedAction }
    });

    res.status(403).json({ error: 'Acceso denegado a este recurso' });
    return null;
  }

  return note;
};

router.use(requireAuth, requireCsrf);

/**
 * GET /api/notes
 */
router.get('/', async (req, res, next) => {
  const parsedQuery = notesQuerySchema.safeParse(req.query);
  if (!parsedQuery.success) {
    return next(parsedQuery.error);
  }

  const { category, search } = parsedQuery.data;

  const { rows } = category
    ? await query(
        `SELECT id, title, category, tags, encrypted_content, key_version, created_at, updated_at
         FROM vault_notes
         WHERE owner_id = $1 AND category = $2
         ORDER BY updated_at DESC`,
        [req.user.id, category]
      )
    : await query(
        `SELECT id, title, category, tags, encrypted_content, key_version, created_at, updated_at
         FROM vault_notes
         WHERE owner_id = $1
         ORDER BY updated_at DESC`,
        [req.user.id]
      );

  let notes = rows.map((row) =>
    formatNote(row, decryptText(row.encrypted_content, row.key_version))
  );

  if (search) {
    const needle = search.toLowerCase();
    notes = notes.filter(
      (note) =>
        note.title.toLowerCase().includes(needle) ||
        note.content.toLowerCase().includes(needle) ||
        note.tags.some((tag) => tag.toLowerCase().includes(needle))
    );
  }

  return res.status(200).json({ notes });
});

/**
 * GET /api/notes/:id
 */
router.get('/:id', validateParams(noteIdParamSchema), async (req, res) => {
  const note = await findOwnedNoteOrReject({
    noteId: req.params.id,
    user: req.user,
    attemptedAction: 'READ',
    req,
    res
  });

  if (!note) return;

  const decryptedContent = decryptText(note.encrypted_content, note.key_version);
  return res.status(200).json({ note: formatNote(note, decryptedContent) });
});

/**
 * POST /api/notes
 */
router.post('/', validateBody(noteBodySchema), async (req, res, next) => {
  const { title, category, tags, content } = req.body;
  const client = await getClient();

  try {
    await client.query('BEGIN');

    // Bloquea la fila del usuario para evitar condiciones de carrera en el límite de 50 notas (OWASP A06)
    await client.query('SELECT id FROM users WHERE id = $1 FOR UPDATE', [req.user.id]);

    const { rows: countRows } = await client.query(
      'SELECT COUNT(*)::int AS total FROM vault_notes WHERE owner_id = $1',
      [req.user.id]
    );

    if (countRows[0].total >= MAX_NOTES_PER_USER) {
      await client.query('ROLLBACK');
      return res.status(422).json({
        error: 'Límite máximo de 50 notas alcanzado para esta cuenta.'
      });
    }

    const { ciphertext, keyVersion } = encryptText(content);

    const { rows: insertRows } = await client.query(
      `INSERT INTO vault_notes (owner_id, title, category, tags, encrypted_content, key_version)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, title, category, tags, key_version, created_at, updated_at`,
      [req.user.id, title, category, tags, ciphertext, keyVersion]
    );

    await client.query('COMMIT');

    const created = insertRows[0];

    await logSecurityEvent({
      userId: req.user.id,
      actorEmail: req.user.email,
      eventType: 'NOTE_CREATED',
      severity: 'info',
      req,
      details: { noteId: created.id, category: created.category }
    });

    return res.status(201).json({
      message: 'Nota cifrada y almacenada correctamente',
      note: formatNote(created, content)
    });
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch {
      // Ignorar error de rollback si la transacción ya fue abortada
    }
    return next(err);
  } finally {
    client.release();
  }
});

/**
 * PUT /api/notes/:id
 */
router.put(
  '/:id',
  validateParams(noteIdParamSchema),
  validateBody(noteBodySchema),
  async (req, res) => {
    const existing = await findOwnedNoteOrReject({
      noteId: req.params.id,
      user: req.user,
      attemptedAction: 'UPDATE',
      req,
      res
    });

    if (!existing) return;

    const { title, category, tags, content } = req.body;
    const { ciphertext, keyVersion } = encryptText(content);

    const { rows } = await query(
      `UPDATE vault_notes
       SET title = $1,
           category = $2,
           tags = $3,
           encrypted_content = $4,
           key_version = $5,
           updated_at = NOW()
       WHERE id = $6 AND owner_id = $7
       RETURNING id, title, category, tags, key_version, created_at, updated_at`,
      [title, category, tags, ciphertext, keyVersion, req.params.id, req.user.id]
    );

    const updated = rows[0];
    if (!updated) {
      return res.status(404).json({ error: 'Nota no encontrada' });
    }

    await logSecurityEvent({
      userId: req.user.id,
      actorEmail: req.user.email,
      eventType: 'NOTE_UPDATED',
      severity: 'info',
      req,
      details: { noteId: updated.id, category: updated.category }
    });

    return res.status(200).json({
      message: 'Nota actualizada correctamente',
      note: formatNote(updated, content)
    });
  }
);

/**
 * DELETE /api/notes/:id
 */
router.delete('/:id', validateParams(noteIdParamSchema), async (req, res) => {
  const existing = await findOwnedNoteOrReject({
    noteId: req.params.id,
    user: req.user,
    attemptedAction: 'DELETE',
    req,
    res
  });

  if (!existing) return;

  const { rowCount } = await query(
    'DELETE FROM vault_notes WHERE id = $1 AND owner_id = $2',
    [req.params.id, req.user.id]
  );

  if (rowCount === 0) {
    return res.status(404).json({ error: 'Nota no encontrada' });
  }

  await logSecurityEvent({
    userId: req.user.id,
    actorEmail: req.user.email,
    eventType: 'NOTE_DELETED',
    severity: 'info',
    req,
    details: { noteId: existing.id }
  });

  return res.status(200).json({ message: 'Nota eliminada permanentemente' });
});

export default router;
