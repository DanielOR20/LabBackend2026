import { Router } from 'express';

const router = Router();

const healthCheck = (_req, res) => {
  res.status(200).json({
    status: 'ok',
    timestamp: new Date().toISOString()
  });
};

router.get('/health', healthCheck);
router.get('/api/health', healthCheck);

export default router;
