const crypto = require('crypto');

/**
 * Generates a deterministic HMAC-SHA256 hash for a given input.
 * @param {string} input - The input string to hash.
 * @param {string} key - The secret key for HMAC.
 * @returns {string} - The hex-encoded HMAC-SHA256 hash.
 */
function deterministicUsernameHash(input, key) {
  if (!key) {
    throw new Error('Key is required for HMAC.');
  }
  return crypto.createHmac('sha256', key).update(input).digest('hex');
}

module.exports = deterministicUsernameHash;
