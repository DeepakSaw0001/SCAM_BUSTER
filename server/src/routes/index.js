const express = require('express');
const router = express.Router();

const healthRoutes = require('./health');
const analysisRoutes = require('./analysis');

router.use('/health', healthRoutes);
router.use('/analysis', analysisRoutes);

module.exports = router;
