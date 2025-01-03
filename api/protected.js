const jwt = require('jsonwebtoken');
const { extendSessionIfNecessary } = require('../utils/sessionManager');
const { cleanupExpiredSessions } = require('../utils/helpers');
const { logProtected } = require('../utils/logger');
require('dotenv').config();

const JWT_SECRET = process.env.JWT_SECRET;

module.exports = async (req, res) => {
  logProtected(`Incoming request: ${JSON.stringify(req.headers)}`);

  if (req.method !== 'GET') {
    logProtected('Method not allowed.');
    return res.status(405).json({ error: 'Method not allowed.' });
  }

  const token = req.headers.authorization?.split(' ')[1]; // Extract Bearer token
  if (!token) {
    logProtected('Unauthorized: Missing token.');
    return res.status(401).json({ error: 'Unauthorized. Token missing.' });
  }

  try {
    // Verify JWT
    const decoded = jwt.verify(token, JWT_SECRET);
    const hashedUsername = decoded.username;

    // Cleanup expired sessions
    await cleanupExpiredSessions(hashedUsername);

    // Extend session if necessary
    const sessionExtended = await extendSessionIfNecessary(hashedUsername, token);
    if (sessionExtended) {
      logProtected('Session validity extended.');
    } else {
      logProtected('Session did not need extension.');
    }

    logProtected('Access granted to protected content.');
    return res.status(200).json({ message: 'Access granted.', user: decoded });
  } catch (error) {
    logProtected(`Error during protected route access: ${error.message}`);
    return res.status(401).json({ error: 'Unauthorized. Invalid token or session.' });
  }
};
