const fs = require('fs');
const path = require('path');

// Helper to write logs to specific files
function writeLog(logFile, message) {
  const logPath = path.join(__dirname, '..', 'logs', logFile);
  const timestamp = new Date().toISOString();
  const logMessage = `[${timestamp}] ${message}\n`;
  fs.appendFileSync(logPath, logMessage, 'utf8');
}

module.exports = {
  logRegister: (message) => writeLog('register.log', message),
  logLogin: (message) => writeLog('login.log', message),
  logProtected: (message) => writeLog('protected.log', message),
};
