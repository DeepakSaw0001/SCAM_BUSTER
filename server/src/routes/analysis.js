const express = require('express');
const router = express.Router();
const { submitAnalysis, getHistory, getAnalysisById } = require('../controllers/analysisController');

router.post('/submit', submitAnalysis);
router.get('/history', getHistory);
router.get('/:id', getAnalysisById);

module.exports = router;
