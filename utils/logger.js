const { MongoClient } = require('mongodb');
const { DateTime } = require('luxon'); // For timezone conversion

// MongoDB connection
const MONGO_URI = process.env.MONGO_URI; // Add this in your Vercel environment variables
const client = new MongoClient(MONGO_URI);

/**
 * Logs data to a specific MongoDB collection based on logType.
 * @param {string} logType - The type of log (e.g., "register", "login", "protected").
 * @param {string} message - The log message.
 * @param {object} [data] - Additional data for the log entry.
 */
async function logToMongo(logType, message, data = {}) {
  try {
    // Ensure MongoDB client is connected
    if (!client.isConnected()) await client.connect();
    const db = client.db('logsDB'); // Replace with your DB name
    const logsCollection = db.collection(logType); // Use logType as the collection name

    // Convert timestamp to India Standard Time
    const timestamp = DateTime.now()
      .setZone('Asia/Kolkata')
      .toISO({ includeOffset: true }); // Format: 2024-12-25T17:30:00+05:30

    // Insert log into MongoDB
    await logsCollection.insertOne({
      timestamp,
      message,
      data,
    });
    console.log(`[LOG] ${logType.toUpperCase()}: ${message}`);
  } catch (error) {
    console.error('Error logging to MongoDB:', error.message);
  }
}

module.exports = {
  logRegister: (message, data) => logToMongo('register', message, data),
  logLogin: (message, data) => logToMongo('login', message, data),
  logProtected: (message, data) => logToMongo('protected', message, data),
};
