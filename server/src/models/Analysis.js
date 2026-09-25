const mongoose = require('mongoose');

const analysisSchema = new mongoose.Schema(
  {
    inputType: {
      type: String,
      enum: ['url', 'email', 'message', 'phone', 'file'],
      required: true,
    },
    inputValue: {
      type: String,
      required: true,
      maxlength: 10000,
    },
    result: {
      riskLevel: {
        type: String,
        enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE'],
      },
      riskScore: {
        type: Number,
        min: 0,
        max: 100,
      },
      reasons: [String],
      indicators: [
        {
          name: String,
          description: String,
          severity: { type: String, enum: ['high', 'medium', 'low'] },
        },
      ],
      recommendations: [String],
      metadata: {
        analysisEngine: String,
        analysisTimeMs: Number,
        analyzedAt: Date,
      },
    },
    status: {
      type: String,
      enum: ['pending', 'completed', 'error'],
      default: 'pending',
    },
  },
  {
    timestamps: true,
  }
);

analysisSchema.index({ createdAt: -1 });
analysisSchema.index({ inputType: 1 });

module.exports = mongoose.model('Analysis', analysisSchema);
