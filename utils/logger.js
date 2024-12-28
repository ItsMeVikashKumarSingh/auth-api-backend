const { MongoClient } = require('mongodb');
const { DateTime } = require('luxon');

// MongoDB connection string

const MONGO_URI = process.env.MONGO_URI; // Add this to your environment variables

// Create a new MongoClient instance
const client = new MongoClient(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });

// Logging function
async function logToMongo(logType, message, data = {}) {
  try {
    // Connect to MongoDB (if not already connected)
    if (!client.topology || !client.topology.isConnected()) {
      await client.connect();
    }

    const db = client.db('logsDB'); // Replace with your actual database name
    const logsCollection = db.collection(logType); // Each logType gets its own collection

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
