const argon2 = require('argon2');
const jwt = require('jsonwebtoken');
const db = require('../utils/firebaseAdmin');
const { logLogin } = require('../utils/logger');
const sodium = require('libsodium-wrappers');
const { getHashKey, getActiveJwtKey } = require('../utils/keyManager');
const deterministicUsernameHash = require('../utils/deterministicUsernameHash');
const { cleanupExpiredSessions } = require('../utils/helpers');
const { DateTime } = require('luxon');
const crypto = require('crypto');
require('dotenv').config();

const PRIVATE_KEY_HEX = process.env.PRIVATE_KEY_HEX;
const PUBLIC_KEY_HEX = process.env.PUBLIC_KEY_HEX;
const APP_SIGNATURE = process.env.APP_SIGNATURE;

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
    const { appSignature, username, password, clientPublicKey } = decryptedData;

    // Match plain text appSignature
if (appSignature !== APP_SIGNATURE) {
  logLogin('Login failed: Unauthorized app.', { appSignature });

  // Debugging: Log environment and input details
  console.error('APP_SIGNATURE from ENV:', APP_SIGNATURE);
  console.error('Received appSignature:', appSignature);

  // Fetch user by hashed username
  const hashKeys = JSON.parse(process.env.USERNAME_HASH_KEYS_VERSIONS || '{}');
  console.log('Hash keys versions:', hashKeys);

  let userUUID = null;

  for (const [version, hashKey] of Object.entries(hashKeys)) {
    const usernameHash = deterministicUsernameHash(username, hashKey);
    console.log(`Checking username hash for version ${version}:`, usernameHash);

    const regUserSnapshot = await db
      .collection('reg_user')
      .where('hashedUsername', '==', usernameHash)
      .where('hashVersion', '==', version)
      .get();

    console.log(`Snapshot for version ${version}:`, regUserSnapshot.empty ? 'No Match' : 'Match Found');

    if (!regUserSnapshot.empty) {
      userUUID = regUserSnapshot.docs[0].id;
      console.log('User UUID found:', userUUID);
      break;
    }
  }

  if (!userUUID) {
    logLogin('Login failed: Invalid username.', { username });
    console.error('No matching user found in reg_user for username:', username);
    return res.status(401).json({ error: 'Invalid username.' });
  }

  // Fetch user document
  let userDocRef, userDoc, userData;
  try {
    userDocRef = db.collection('users').doc(userUUID);
    console.log('Fetching user document with UUID:', userUUID);

    userDoc = await userDocRef.get();

    if (!userDoc.exists) {
      console.error('User document does not exist for UUID:', userUUID);
      logLogin('Login failed: User data missing or corrupted.', { uuid: userUUID });
      return res.status(500).json({ error: 'User data missing or corrupted.' });
    }

    userData = userDoc.data();
    console.log('Fetched user data:', userData);
  } catch (fetchError) {
    console.error('Error fetching user document:', fetchError.message);
    logLogin('Login failed: Error fetching user document.', { error: fetchError.message });
    return res.status(500).json({ error: 'Internal server error.', details: fetchError.message });
  }

  // Check if account is already banned
  if (userData.status === 'banned') {
    logLogin('Login failed: Account is banned.', { uuid: userUUID });
    console.error('Account is banned:', userUUID);
    return res.status(403).json({ error: 'You are banned.' });
  }

  const currentTime = DateTime.now().setZone('Asia/Kolkata');
  const lastAttemptTime = userData.lastAttemptTime ? DateTime.fromISO(userData.lastAttemptTime) : null;
  let attempts = userData.attempts || 0;
  let warnings = userData.warnings || 0;

  // Log login attempt details
  console.log('Current time:', currentTime.toISO());
  console.log('Last attempt time:', lastAttemptTime ? lastAttemptTime.toISO() : 'None');
  console.log('Current attempts:', attempts);
  console.log('Current warnings:', warnings);

  // Handle login attempts logic
  if (lastAttemptTime && currentTime.diff(lastAttemptTime, 'minutes').minutes <= 30) {
    if (attempts >= 3) {
      const retryAfter = lastAttemptTime.plus({ minutes: 30 }).toFormat('hh:mm a');
      logLogin('Login failed: Too many attempts.', { uuid: userUUID, attempts, retryAfter });
      console.warn('Too many attempts. Retry after:', retryAfter);
      return res.status(429).json({
        error: `Too many attempts. Please try again after ${retryAfter} IST.`,
      });
    }

    // Increment attempts within 30 minutes threshold
    attempts += 1;
  } else {
    // Reset attempts if last attempt was more than 30 minutes ago
    attempts = 1; // Current attempt is counted as the first
  }

  // Increment warnings
  warnings += 1;

  // Log updated warnings and attempts
  console.log('Updated warnings:', warnings);
  console.log('Updated attempts:', attempts);

  // Ban account if warnings exceed threshold
  if (warnings >= 5) {
    await userDocRef.update({
      status: 'banned',
    });
    logLogin('Login failed: Account is banned.', { uuid: userUUID });
    console.error('User account banned:', userUUID);
    return res.status(403).json({ error: 'You are banned.' });
  }

  // Update user document with new attempts, warnings, and last attempt time
  try {
    await userDocRef.update({
      warnings,
      attempts,
      lastAttemptTime: currentTime.toISO(),
    });
    console.log('User document updated successfully.');
  } catch (updateError) {
    console.error('Error updating user document:', updateError.message);
    logLogin('Login failed: Error updating user document.', { error: updateError.message });
    return res.status(500).json({ error: 'Internal server error.', details: updateError.message });
  }

  logLogin('Login failed: Unauthorized app.', { uuid: userUUID, warnings, attempts });
  return res.status(403).json({ error: 'Unauthorized app.', warnings, attempts });
}
    // Reset warnings and attempts on successful login
    await userDocRef.update({attempts: 0 });

    // Update last login
    const currentTimestamp = currentTime.toISO();
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

    const expiryTimestamp = currentTime.plus({ hours: 1 }).toISO();

    const sessionsRef = db.collection('sessions').doc(userUUID);
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
