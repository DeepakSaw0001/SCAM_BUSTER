// Centralized error handler middleware
const config = require('../config');

const errorHandler = (err, req, res, next) => {
  const statusCode = err.statusCode || 500;
  const message = err.message || 'Internal Server Error';

  console.error(`[ERROR] ${statusCode} - ${message}`, config.nodeEnv === 'development' ? err.stack : '');

  res.status(statusCode).json({
    success: false,
    error: {
      message,
      ...(config.nodeEnv === 'development' && { stack: err.stack }),
    },
  });
};

// Custom error class for operational errors
class AppError extends Error {
  constructor(message, statusCode = 500) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = true;
    Error.captureStackTrace(this, this.constructor);
  }
}

module.exports = { errorHandler, AppError };
