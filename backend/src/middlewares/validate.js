/**
 * Valida req.body contra un esquema Zod y delega errores de validación a globalErrorHandler.
 */
export const validateBody = (schema) => (req, _res, next) => {
  const result = schema.safeParse(req.body);
  if (!result.success) {
    return next(result.error);
  }
  req.body = result.data;
  return next();
};

/**
 * Valida req.params contra un esquema Zod y delega errores de validación a globalErrorHandler.
 */
export const validateParams = (schema) => (req, _res, next) => {
  const result = schema.safeParse(req.params);
  if (!result.success) {
    return next(result.error);
  }
  req.params = result.data;
  return next();
};
