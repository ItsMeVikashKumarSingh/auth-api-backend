const crypto = require('crypto');

/**
 * Generates a 64-character (256-bit) random backup code.
 * @returns {string} - The generated backup code.
 */
function generateBackupCode() {
  return crypto.randomBytes(32).toString('hex'); // 32 bytes = 256 bits
}

/**
 * Creates a deterministic HMAC-SHA256 hash for a backup code.
 * @param {string} backupCode - The plain-text backup code to hash.
 * @param {string} key - The secret key for HMAC.
 * @returns {string} - The hex-encoded HMAC-SHA256 hash of the backup code.
 */
function hashBackupCode(backupCode, key) {
  if (!key) {
    throw new Error('Key is required for hashing backup code.');
  }
  return crypto.createHmac('sha256', key).update(backupCode).digest('hex');
}

module.exports = {
  generateBackupCode,
  hashBackupCode,
};
