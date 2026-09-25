/**
 * Scam Analysis Engine — modular analysis service.
 *
 * Architecture: Each input type has its own analyzer. The engine routes
 * input to the correct analyzer and aggregates the results.
 *
 * For the MVP, we use rule-based heuristic analyzers. These will be
 * replaced/augmented with ML models and external API integrations later.
 */

const urlAnalyzer = require('./analyzers/urlAnalyzer');
const messageAnalyzer = require('./analyzers/messageAnalyzer');
const emailAnalyzer = require('./analyzers/emailAnalyzer');
const phoneAnalyzer = require('./analyzers/phoneAnalyzer');

const analyzers = {
  url: urlAnalyzer,
  message: messageAnalyzer,
  email: emailAnalyzer,
  phone: phoneAnalyzer,
};

const analyze = async (inputType, inputValue) => {
  const startTime = Date.now();
  const analyzer = analyzers[inputType];

  if (!analyzer) {
    throw new Error(`No analyzer available for input type: ${inputType}`);
  }

  const result = await analyzer.analyze(inputValue);

  return {
    ...result,
    metadata: {
      analysisEngine: 'scambuster-heuristic-v1',
      analysisTimeMs: Date.now() - startTime,
      analyzedAt: new Date(),
    },
  };
};

module.exports = { analyze };
