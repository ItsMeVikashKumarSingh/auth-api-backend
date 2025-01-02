const { MongoClient } = require('mongodb');
const { DateTime } = require('luxon');

const MONGO_URI = process.env.MONGO_URI; // Add this to your .env or Vercel environment variables

// Initialize a global MongoDB client
let mongoClient;

async function connectToMongo() {
  if (!mongoClient || !mongoClient.isConnected()) {
    console.log('[DEBUG] MongoDB client not connected. Attempting to connect...');
    mongoClient = new MongoClient(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });
    await mongoClient.connect();
    console.log('[DEBUG] MongoDB connected.');
  } else {
    console.log('[DEBUG] MongoDB already connected.');
  }
}

async function logToMongo(logType, message, data = {}) {
  console.log(`[DEBUG] Attempting to log to MongoDB - Type: ${logType}`);

  try {
    // Ensure MongoDB connection is established
    await connectToMongo();

    const db = mongoClient.db('logsDB'); // Replace with your database name
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

    // Retry logic for transient errors (optional)
    if (error.message.includes('ECONNRESET') || error.message.includes('timed out')) {
      console.log('[DEBUG] Retrying MongoDB log insertion...');
      try {
        await connectToMongo(); // Reconnect if necessary
        await logToMongo(logType, message, data); // Retry logging
      } catch (retryError) {
        console.error('[ERROR] MongoDB Retry Failed:', retryError.message);
      }
    }
  }
}

// Export log methods
module.exports = {
  logRegister: (message, data) => logToMongo('register', message, data),
  logLogin: (message, data) => logToMongo('login', message, data),
  logForgotPassword: (message, data) => logToMongo('ForgotPassword', message, data),
  logProtected: (message, data) => logToMongo('protected', message, data),
  unauthorizedLog: (message, data) => logToMongo('unauthorized', message, data),
  getapiLog: (message, data) => logToMongo('getapi', message, data),
};
