const { AppError } = require('./errorHandler');

// Basic request validation middleware factory
const validateRequest = (schema) => {
  return (req, res, next) => {
    const errors = [];

    if (schema.body) {
      for (const [field, rules] of Object.entries(schema.body)) {
        const value = req.body[field];
        if (rules.required && (value === undefined || value === null || value === '')) {
          errors.push(`${field} is required`);
        }
        if (value && rules.type && typeof value !== rules.type) {
          errors.push(`${field} must be of type ${rules.type}`);
        }
        if (value && rules.maxLength && value.length > rules.maxLength) {
          errors.push(`${field} must not exceed ${rules.maxLength} characters`);
        }
      }
    }

    if (errors.length > 0) {
      return next(new AppError(`Validation failed: ${errors.join(', ')}`, 400));
    }
    next();
  };
};

module.exports = { validateRequest };
