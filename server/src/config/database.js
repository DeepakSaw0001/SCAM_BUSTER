const mongoose = require('mongoose');
const config = require('../config');

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(config.mongodbUri, {
      serverSelectionTimeoutMS: 2000,
    });
    console.log(`[DB] MongoDB connected: ${conn.connection.host}`);
    return conn;
  } catch (error) {
    console.warn(`[DB] MongoDB not available (${error.message}). Running in offline mode.`);
    // Don't crash the server — let it run without DB for development
    // Features requiring DB will return appropriate errors
    return null;
  }
};

module.exports = connectDB;
