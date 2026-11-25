import app from './app.js';
import { env } from './config/env.js';
import { logger } from './config/logger.js';
import { pool } from './config/db.js';

const server = app.listen(env.PORT, () => {
  logger.info(
    { port: env.PORT, env: env.NODE_ENV },
    'Servidor SecureVault iniciado'
  );
});

let isShuttingDown = false;

const shutdown = async (signal, exitCode = 0) => {
  if (isShuttingDown) return;
  isShuttingDown = true;

  logger.info({ signal }, 'Iniciando apagado ordenado del servidor');

  const forceExitTimer = setTimeout(() => {
    logger.fatal('Tiempo de espera de apagado agotado; forzando salida');
    process.exit(1);
  }, 5000);
  forceExitTimer.unref();

  try {
    await new Promise((resolve) => {
      server.close(() => resolve());
      server.closeIdleConnections?.();
    });
    await pool.end();
    logger.info('Servidor HTTP y pool de PostgreSQL cerrados correctamente');
    process.exit(exitCode);
  } catch (err) {
    logger.fatal({ err }, 'Error durante el apagado ordenado');
    process.exit(1);
  }
};

server.on('error', (err) => {
  logger.fatal({ err }, 'Error fatal en el servidor HTTP');
  void shutdown('serverError', 1);
});

process.on('SIGTERM', () => {
  void shutdown('SIGTERM', 0);
});

process.on('SIGINT', () => {
  void shutdown('SIGINT', 0);
});

process.on('unhandledRejection', (reason) => {
  logger.fatal({ err: reason }, 'Unhandled Promise Rejection');
  void shutdown('unhandledRejection', 1);
});

process.on('uncaughtException', (err) => {
  logger.fatal({ err }, 'Uncaught Exception');
  void shutdown('uncaughtException', 1);
});
