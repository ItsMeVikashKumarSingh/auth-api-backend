// module.exports = async (req, res) => {
//     if (req.method !== 'GET') {
//       return res.status(405).json({ error: 'Method not allowed.' });
//     }
  
//     res.status(200).json({ message: 'Your API is working fine!' });
//   };
  

const { logProtected } = require('../utils/logger'); // Reusing the logger utility

module.exports = async (req, res) => {
  logProtected('Incoming request for health check.', { headers: req.headers });

  if (req.method !== 'GET') {
    logProtected('Health check failed: Method not allowed.');
    return res.status(405).json({ error: 'Method not allowed.' });
  }

  try {
    // Simulate a health check (e.g., database connectivity, uptime)
    const healthStatus = {
      uptime: process.uptime(), // Server uptime in seconds
      timestamp: new Date().toISOString(), // Current timestamp
      status: 'OK', // Server status
    };

    logProtected('Health check successful.', healthStatus);
    return res.status(200).json(healthStatus);
  } catch (error) {
    logProtected('Health check failed.', { error: error.message });
    return res.status(500).json({ error: 'Health check failed.', details: error.message });
  }
};
