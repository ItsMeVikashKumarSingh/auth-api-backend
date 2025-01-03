const db = require('../utils/firebaseAdmin');
const sodium = require('libsodium-wrappers');
const { unauthorizedLog, getapiLog } = require('../utils/logger');
require('dotenv').config();

const APP_SIGNATURE = process.env.APP_SIGNATURE;
const SERVER_PUBLIC_KEY_HEX = process.env.PUBLIC_KEY_HEX;

module.exports = async (req, res) => {
  console.log('Incoming request for app signature verification.');
  getapiLog('Incoming request for app signature verification.');

  if (req.method !== 'POST') {
    console.log('Method not allowed.');
    getapiLog('Method not allowed.');
    return res.status(405).json({ error: 'Method not allowed.' });
  }

  try {
    const { signature, deviceId, clientPublicKey } = req.body;

    if (!signature || !deviceId || !clientPublicKey) {
      console.log('Invalid request: Missing required fields.');
      getapiLog('Invalid request: Missing required fields.', { signature, deviceId, clientPublicKey });
      return res.status(400).json({ error: 'Missing required fields.' });
    }

    if (signature !== APP_SIGNATURE) {
      console.log(`Unauthorized app detected for device: ${deviceId}`);
      unauthorizedLog(`Unauthorized app detected for device: ${deviceId}`, { signature });

      const deviceDocRef = db.collection('ban').doc(deviceId);
      const deviceDoc = await deviceDocRef.get();
      const warningCount = deviceDoc.exists ? (deviceDoc.data().warningCount || 0) + 1 : 0;

      await deviceDocRef.set({ warningCount });

      if (warningCount > 5) {
        console.log(`Device ${deviceId} is banned for unauthorized app usage.`);
        unauthorizedLog(`Device ${deviceId} is banned for unauthorized app usage.`, { warningCount });
        return res.status(403).json({ error: 'You are banned because of using unauthorized app.' });
      }

      return res.status(403).json({
        error: 'You are using an unauthorized app. Please use the official app, otherwise you will be banned.',
        warnings: warningCount,
      });
    }

    console.log('App signature verified successfully.');
    getapiLog('App signature verified successfully.', { deviceId });

    await sodium.ready;
    const clientPublicKeyBytes = Uint8Array.from(Buffer.from(clientPublicKey, 'hex'));
    const encryptedResponse = sodium.crypto_box_seal(
      Buffer.from(JSON.stringify({ publicKey: SERVER_PUBLIC_KEY_HEX })),
      clientPublicKeyBytes
    );

    return res.status(200).json({
      encryptedData: Buffer.from(encryptedResponse).toString('base64'),
    });
  } catch (error) {
    console.error('Error during app signature verification:', error.message);
    getapiLog('Error during app signature verification.', { error: error.message });
    return res.status(500).json({ error: 'Internal server error.', details: error.message });
  }
};
