const admin = require('firebase-admin');

if (!process.env.FIREBASE_CREDENTIALS) {
  throw new Error('FIREBASE_CREDENTIALS environment variable is missing!');
}

const serviceAccount = JSON.parse(process.env.FIREBASE_CREDENTIALS);

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
}

const db = admin.firestore();

module.exports = db;
