const { AppError } = require('../middleware/errorHandler');
const analysisEngine = require('../services/analysisEngine');
const Analysis = require('../models/Analysis');
const mongoose = require('mongoose');

const VALID_INPUT_TYPES = ['url', 'email', 'message', 'phone'];

const submitAnalysis = async (req, res, next) => {
  try {
    const { inputType, inputValue } = req.body;

    if (!inputType || !inputValue) {
      throw new AppError('inputType and inputValue are required', 400);
    }

    if (!VALID_INPUT_TYPES.includes(inputType)) {
      throw new AppError(`Invalid inputType. Must be one of: ${VALID_INPUT_TYPES.join(', ')}`, 400);
    }

    if (typeof inputValue !== 'string' || inputValue.trim().length === 0) {
      throw new AppError('inputValue must be a non-empty string', 400);
    }

    if (inputValue.length > 10000) {
      throw new AppError('inputValue must not exceed 10000 characters', 400);
    }

    const result = await analysisEngine.analyze(inputType, inputValue.trim());

    // Persist to DB if connected
    let savedAnalysis = null;
    if (mongoose.connection.readyState === 1) {
      savedAnalysis = await Analysis.create({
        inputType,
        inputValue: inputValue.trim(),
        result,
        status: 'completed',
      });
    }

    res.status(200).json({
      success: true,
      data: {
        id: savedAnalysis?._id || null,
        inputType,
        result,
      },
    });
  } catch (error) {
    next(error);
  }
};

const getHistory = async (req, res, next) => {
  try {
    if (mongoose.connection.readyState !== 1) {
      throw new AppError('Database not available — history requires MongoDB', 503);
    }

    const page = Math.max(parseInt(req.query.page, 10) || 1, 1);
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 20, 1), 100);
    const skip = (page - 1) * limit;

    const [analyses, total] = await Promise.all([
      Analysis.find().sort({ createdAt: -1 }).skip(skip).limit(limit).lean(),
      Analysis.countDocuments(),
    ]);

    res.status(200).json({
      success: true,
      data: {
        analyses,
        pagination: { page, limit, total, pages: Math.ceil(total / limit) },
      },
    });
  } catch (error) {
    next(error);
  }
};

const getAnalysisById = async (req, res, next) => {
  try {
    if (mongoose.connection.readyState !== 1) {
      throw new AppError('Database not available', 503);
    }

    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) {
      throw new AppError('Invalid analysis ID', 400);
    }

    const analysis = await Analysis.findById(id).lean();
    if (!analysis) {
      throw new AppError('Analysis not found', 404);
    }

    res.status(200).json({ success: true, data: analysis });
  } catch (error) {
    next(error);
  }
};

module.exports = { submitAnalysis, getHistory, getAnalysisById };
