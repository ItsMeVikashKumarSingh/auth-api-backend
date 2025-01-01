const argon2 = require('argon2');
const jwt = require('jsonwebtoken');
const db = require('../utils/firebaseAdmin');
const { logLogin } = require('../utils/logger');
const sodium = require('libsodium-wrappers');
const deterministicUsernameHash = require('../utils/deterministicUsernameHash');
const { cleanupExpiredSessions } = require('../utils/helpers');
const { getHashKey, getActiveJwtKey } = require('../utils/keyManager');
const { DateTime } = require('luxon');
const crypto = require('crypto');
require('dotenv').config();

const PRIVATE_KEY_HEX = process.env.PRIVATE_KEY_HEX;
const PUBLIC_KEY_HEX = process.env.PUBLIC_KEY_HEX;

module.exports = async (req, res) => {
  logLogin('Incoming login request.', { headers: req.headers });

  if (req.method !== 'POST') {
    logLogin('Login failed: Method not allowed.');
    return res.status(405).json({ error: 'Method not allowed.' });
  }

  try {
    const { encryptedData } = req.body;

    if (!encryptedData) {
      logLogin('Login failed: Missing encrypted data.');
      return res.status(400).json({ error: 'Missing encrypted data.' });
    }

    await sodium.ready;

    const privateKey = Uint8Array.from(Buffer.from(PRIVATE_KEY_HEX, 'hex'));
    const publicKey = Uint8Array.from(Buffer.from(PUBLIC_KEY_HEX, 'hex'));
    const sealedBox = Uint8Array.from(Buffer.from(encryptedData, 'base64'));

    let decryptedBytes;
    try {
      decryptedBytes = sodium.crypto_box_seal_open(sealedBox, publicKey, privateKey);
    } catch (error) {
      console.error('Decryption failed:', error.message);
      return res.status(400).json({ error: 'Decryption failed.', details: error.message });
    }

    const decryptedData = JSON.parse(Buffer.from(decryptedBytes).toString());
    const { username, password, clientPublicKey } = decryptedData;

    // Hash username and find corresponding UUID from reg_user
    const hashKeys = JSON.parse(process.env.USERNAME_HASH_KEYS_VERSIONS || '{}');
    let userUUID = null;

    for (const [version, hashKey] of Object.entries(hashKeys)) {
      const usernameHash = deterministicUsernameHash(username, hashKey);

      const regUserDoc = await db.collection('reg_user').doc(usernameHash).get();
      if (regUserDoc.exists) {
        userUUID = regUserDoc.data().uuid;
        break;
      }
    }

    if (!userUUID) {
      logLogin('Login failed: Invalid username.', { username });
      return res.status(401).json({ error: 'Invalid username or password.' });
    }

    // Fetch user data from users collection using UUID
    const userDocRef = db.collection('users').doc(userUUID);
    const userDoc = await userDocRef.get();

    if (!userDoc.exists) {
      logLogin('Login failed: User data missing or corrupted.', { uuid: userUUID });
      return res.status(500).json({ error: 'User data missing or corrupted.' });
    }

    const userData = userDoc.data();

    // Verify password
    if (!(await argon2.verify(userData.p_hash, password))) {
      logLogin('Login failed: Invalid password.', { uuid: userUUID });
      return res.status(401).json({ error: 'Invalid username or password.' });
    }

    // Update last login
    const currentTimestamp = DateTime.now().setZone('Asia/Kolkata').toISO();
    await userDocRef.update({ last_login: currentTimestamp });

    // Cleanup expired sessions
    await cleanupExpiredSessions(userUUID);

    // Generate new session
    const sessionId = crypto.randomUUID();
    const { key: jwtKey, version: jwtVersion } = getActiveJwtKey();
    const token = jwt.sign(
      { uuid: userUUID, sessionId, keyVersion: jwtVersion },
      jwtKey,
      { expiresIn: '1h' }
    );

    const expiryTimestamp = DateTime.now().setZone('Asia/Kolkata').plus({ hours: 1 }).toISO();

    const sessionsRef = db.collection('sessions').doc(userUUID);
    const sessionsDoc = await sessionsRef.get();

    const updatedSessions = sessionsDoc.exists ? sessionsDoc.data() : {};
    updatedSessions[sessionId] = {
      token,
      expires_at: expiryTimestamp,
      jwt_version: jwtVersion,
    };

    // Save updated sessions
    await sessionsRef.set(updatedSessions);

    // Encrypt response
    const responseData = {
      message: 'Login successful.',
      token,
      expires_at: expiryTimestamp,
      uuid: userUUID, // Include uuid in the response
    };

    const clientPublicKeyBytes = Uint8Array.from(Buffer.from(clientPublicKey, 'hex'));
    const encryptedResponse = sodium.crypto_box_seal(
      Buffer.from(JSON.stringify(responseData)),
      clientPublicKeyBytes
    );

    logLogin('Login successful.', { uuid: userUUID, sessionId });
    return res.status(200).json({
      encryptedData: Buffer.from(encryptedResponse).toString('base64'),
    });
  } catch (error) {
    console.error('Error during login:', error);
    logLogin('Login failed due to server error.', { error: error.message });
    return res.status(500).json({ error: 'Login failed.', details: error.message });
  }
};
