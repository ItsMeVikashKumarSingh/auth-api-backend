const db = require('../utils/firebaseAdmin');
const { cleanupExpiredSessions } = require('../utils/helpers');
require('dotenv').config();

module.exports = async (req, res) => {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed.' });
  }

  // Example: Protected route response
  res.status(200).json({ message: 'Protected content.' });
};
