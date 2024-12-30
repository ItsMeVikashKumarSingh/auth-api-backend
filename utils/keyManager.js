const dotenv = require('dotenv');
dotenv.config();

const hashKeys = JSON.parse(process.env.USERNAME_HASH_KEYS_VERSIONS || '{}');
const jwtSecretKeys = JSON.parse(process.env.JWT_SECRET_KEYS_VERSIONS || '{}');

/**
 * Retrieves the active key for hashing.
 * @returns {{key: string, version: string}} - Active key and its version.
 */
function getActiveHashKey() {
  const activeVersion = process.env.ACTIVE_USERNAME_HASH_KEY_VERSION;
  return {
    key: hashKeys[activeVersion],
    version: activeVersion,
  };
}

/**
 * Retrieves a specific key for hashing based on version.
 * @param {string} version - Version of the key to retrieve.
 * @returns {string} - The key for the specified version.
 */
function getHashKey(version) {
  return hashKeys[version];
}

/**
 * Retrieves the active key for JWT signing.
 * @returns {{key: string, version: string}} - Active JWT key and its version.
 */
function getActiveJwtKey() {
  const activeVersion = process.env.ACTIVE_JWT_SECRET_KEY_VERSION;
  return {
    key: jwtSecretKeys[activeVersion],
    version: activeVersion,
  };
}

/**
 * Retrieves a specific JWT key based on version.
 * @param {string} version - Version of the key to retrieve.
 * @returns {string} - The key for the specified version.
 */
function getJwtKey(version) {
  return jwtSecretKeys[version];
}

module.exports = {
  getActiveHashKey,
  getHashKey,
  getActiveJwtKey,
  getJwtKey,
};
