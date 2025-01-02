const argon2 = require('argon2');
const jwt = require('jsonwebtoken');
const db = require('../utils/firebaseAdmin');
const sodium = require('libsodium-wrappers');
const deterministicUsernameHash = require('../utils/deterministicUsernameHash');
const { cleanupExpiredSessions } = require('../utils/helpers');
const { getHashKey, getActiveJwtKey } = require('../utils/keyManager');
const { DateTime } = require('luxon');
const crypto = require('crypto');
const { logLogin } = require('../utils/logger');
require('dotenv').config();

const PRIVATE_KEY_HEX = process.env.PRIVATE_KEY_HEX;
const PUBLIC_KEY_HEX = process.env.PUBLIC_KEY_HEX;

module.exports = async (req, res) => {
  console.log('Incoming login request.', { headers: req.headers });
  logLogin('Incoming login request.', { headers: req.headers });

  if (req.method !== 'POST') {
    console.log('Login failed: Method not allowed.');
    logLogin('Login failed: Method not allowed.');
    return res.status(405).json({ error: 'Method not allowed.' });
  }

  try {
    const { encryptedData } = req.body;

    if (!encryptedData) {
      console.log('Login failed: Missing encrypted data.');
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
      logLogin('Decryption failed.', { error: error.message });
      return res.status(400).json({ error: 'Decryption failed.', details: error.message });
    }

    const decryptedData = JSON.parse(Buffer.from(decryptedBytes).toString());
    const { username, password, clientPublicKey } = decryptedData;

    console.log('Decrypted username:', username);
    logLogin('Decrypted username.', { username });

    if (!username || typeof username !== 'string' || username.trim() === '') {
      console.log('Login failed: Missing or invalid username.');
      logLogin('Login failed: Missing or invalid username.');
      return res.status(400).json({ error: 'Missing or invalid username.' });
    }

    const hashKeys = JSON.parse(process.env.USERNAME_HASH_KEYS_VERSIONS || '{}');
    let userUUID = null;

    for (const [version, hashKey] of Object.entries(hashKeys)) {
      const usernameHash = deterministicUsernameHash(username, hashKey);

      console.log('Generated username hash:', usernameHash);
      logLogin('Generated username hash.', { version, usernameHash });

      if (!usernameHash || typeof usernameHash !== 'string') {
        console.log('Invalid username hash for version:', version);
        logLogin('Invalid username hash for version.', { version });
        continue;
      }

      try {
        const regUserDoc = await db.collection('reg_user').doc(usernameHash).get();

        if (regUserDoc.exists) {
          userUUID = regUserDoc.data().uuid;
          console.log('User found with UUID:', userUUID);
          logLogin('User found with UUID.', { uuid: userUUID });
          break;
        }
      } catch (error) {
        console.error('Firestore query failed for usernameHash:', usernameHash, error.message);
        logLogin('Firestore query failed for usernameHash.', { usernameHash, error: error.message });
        return res.status(500).json({ error: 'Database query error.', details: error.message });
      }
    }

    if (!userUUID) {
      console.log('Login failed: User not found.');
      logLogin('Login failed: User not found.');
      return res.status(401).json({ error: 'Invalid username or password.' });
    }

    const userDocRef = db.collection('users').doc(String(userUUID));
    const userDoc = await userDocRef.get();

    if (!userDoc.exists) {
      console.log('Login failed: User data missing or corrupted.', { uuid: userUUID });
      logLogin('Login failed: User data missing or corrupted.', { uuid: userUUID });
      return res.status(500).json({ error: 'User data missing or corrupted.' });
    }

    const userData = userDoc.data();

    if (!(await argon2.verify(userData.p_hash, password))) {
      console.log('Login failed: Invalid password.', { uuid: userUUID });
      logLogin('Login failed: Invalid password.', { uuid: userUUID });
      return res.status(401).json({ error: 'Invalid username or password.' });
    }

    const currentTimestamp = DateTime.now().setZone('Asia/Kolkata').toISO();
    await userDocRef.update({ last_login: currentTimestamp });

    await cleanupExpiredSessions(String(userUUID));

    const sessionId = crypto.randomUUID();
    const { key: jwtKey, version: jwtVersion } = getActiveJwtKey();
    const token = jwt.sign(
      { uuid: userUUID, sessionId, keyVersion: jwtVersion },
      jwtKey,
      { expiresIn: '1h' }
    );

    const expiryTimestamp = DateTime.now().setZone('Asia/Kolkata').plus({ hours: 1 }).toISO();

    const sessionsRef = db.collection('sessions').doc(String(userUUID));
    const sessionsDoc = await sessionsRef.get();

    const updatedSessions = sessionsDoc.exists ? sessionsDoc.data() : {};
    updatedSessions[sessionId] = {
      token,
      expires_at: expiryTimestamp,
      jwt_version: jwtVersion,
    };

    await sessionsRef.set(updatedSessions);

    const responseData = {
      message: 'Login successful.',
      token,
      expires_at: expiryTimestamp,
      uuid: userUUID,
    };

    const clientPublicKeyBytes = Uint8Array.from(Buffer.from(clientPublicKey, 'hex'));
    const encryptedResponse = sodium.crypto_box_seal(
      Buffer.from(JSON.stringify(responseData)),
      clientPublicKeyBytes
    );

    console.log('Login successful.', { uuid: userUUID, sessionId });
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
