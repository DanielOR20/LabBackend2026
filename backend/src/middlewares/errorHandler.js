import { ZodError } from 'zod';
import { logger } from '../config/logger.js';

export const notFoundHandler = (_req, res) => {
  res.status(404).json({ error: 'Recurso no encontrado' });
};

export const globalErrorHandler = (err, req, res, next) => {
  if (res.headersSent) {
    return next(err);
  }

  if (err instanceof ZodError) {
    return res.status(400).json({
      error: 'Datos de entrada inválidos',
      details: err.issues.map((issue) => ({
        field: issue.path.join('.'),
        message: issue.message
      }))
    });
  }

  logger.error({ err, path: req.originalUrl, method: req.method }, 'Error interno no controlado');
  return res.status(500).json({ error: 'Error interno del servidor' });
};
