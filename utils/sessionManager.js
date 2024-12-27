const db = require('./firebaseAdmin');
const { logProtected } = require('./logger');

/**
 * Extends session validity if less than 30 minutes remain.
 * @param {string} hashedUsername - The hashed username of the user.
 * @param {string} token - The JWT token of the current session.
 * @returns {boolean} - Returns true if the session was extended, otherwise false.
 */
async function extendSessionIfNecessary(hashedUsername, token) {
  const sessionsRef = db.collection('sessions').doc(hashedUsername);
  const sessionsDoc = await sessionsRef.get();

  if (!sessionsDoc.exists) {
    logProtected(`No active session found for user: ${hashedUsername}`);
    return false;
  }

  const currentTime = new Date();
  const sessions = sessionsDoc.data();
  let sessionUpdated = false;

  for (const [sessionId, sessionData] of Object.entries(sessions)) {
    if (sessionData.token === token) {
      const expiresAt = new Date(sessionData.expires_at);
      const timeRemaining = (expiresAt - currentTime) / (1000 * 60); // Time remaining in minutes

      if (timeRemaining <= 30) {
        // Extend session to 1 hour from the current time
        expiresAt.setHours(currentTime.getHours() + 1);
        sessionData.expires_at = expiresAt.toISOString();
        sessionUpdated = true;
        logProtected(`Session ${sessionId} extended for user: ${hashedUsername}`);
      }
    }
  }

  if (sessionUpdated) {
    await sessionsRef.set(sessions);
  }

  return sessionUpdated;
}

module.exports = {
  extendSessionIfNecessary,
};
