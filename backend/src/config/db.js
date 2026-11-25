import pg from 'pg';
import { env } from './env.js';
import { logger } from './logger.js';

const { Pool } = pg;

export const pool = new Pool({
  connectionString: env.DATABASE_URL,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
  statement_timeout: 5000,
  ssl: env.DB_SSL ? { rejectUnauthorized: false } : false
});

pool.on('error', (err) => {
  logger.error({ err }, 'Error inesperado en cliente inactivo del pool de PostgreSQL');
});

export const query = (text, params) => pool.query(text, params);

export const getClient = () => pool.connect();

export default pool;
