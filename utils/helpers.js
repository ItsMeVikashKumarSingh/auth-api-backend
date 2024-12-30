const db = require('./firebaseAdmin');

// Verify Argon2 hash
async function verifyHash(data, hash) {
  return await argon2.verify(hash, data);
}

// Cleanup expired sessions
async function cleanupExpiredSessions(uuid) {
  const sessionsRef = db.collection('sessions').doc(uuid);
  const sessionsDoc = await sessionsRef.get();

  if (sessionsDoc.exists) {
    const currentTime = new Date();
    const validSessions = {};
    const sessions = sessionsDoc.data();

    for (const [sessionId, sessionData] of Object.entries(sessions)) {
      if (new Date(sessionData.expires_at) > currentTime) {
        validSessions[sessionId] = sessionData;
      }
    }

    await sessionsRef.set(validSessions);
  }
}

module.exports = {
  verifyHash,
  cleanupExpiredSessions,
};
