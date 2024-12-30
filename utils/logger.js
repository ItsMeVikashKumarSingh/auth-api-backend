const { MongoClient } = require('mongodb');
const { DateTime } = require('luxon');

const MONGO_URI = process.env.MONGO_URI; // Add this to your .env or Vercel environment variables

// Initialize the MongoDB client
const client = new MongoClient(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });

async function logToMongo(logType, message, data = {}) {
  console.log(`[DEBUG] Attempting to log to MongoDB - Type: ${logType}`);

  try {
    // Check if MongoDB connection is already established
    if (!client.topology || !client.topology.isConnected()) {
      console.log('[DEBUG] MongoDB client not connected. Attempting to connect...');
      await client.connect(); // Connect if not already connected
      console.log('[DEBUG] MongoDB connected.');
    } else {
      console.log('[DEBUG] MongoDB already connected.');
    }

    const db = client.db('logsDB'); // Replace with your database name
    const logsCollection = db.collection(logType); // Collection for the specific log type

    // Convert timestamp to India Standard Time (IST)
    const timestamp = DateTime.now()
      .setZone('Asia/Kolkata')
      .toISO({ includeOffset: true }); // Format: 2024-12-25T17:30:00+05:30

    // Insert log into MongoDB
    const result = await logsCollection.insertOne({
      timestamp,
      message,
      data,
    });

    console.log(`[DEBUG] Log successfully inserted with ID: ${result.insertedId}`);
  } catch (error) {
    console.error('[ERROR] MongoDB Logging Failed:', error.message);
  }
}

module.exports = {
  logRegister: (message, data) => logToMongo('register', message, data),
  logLogin: (message, data) => logToMongo('login', message, data),
  logForgotPassword: (message, data) => logToMongo('ForgotPassword', message, data),
  logProtected: (message, data) => logToMongo('protected', message, data),  // Specifically for 'protected' log type
};
