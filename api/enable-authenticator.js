const { authenticator } = require('otplib');
const db = require('../utils/firebaseAdmin');
const sodium = require('libsodium-wrappers');
require('dotenv').config();

const PRIVATE_KEY_HEX = process.env.PRIVATE_KEY_HEX;
const PUBLIC_KEY_HEX = process.env.PUBLIC_KEY_HEX;

module.exports = async (req, res) => {
  console.log('Incoming request to enable authenticator.');

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed.' });
  }

  try {
    const { encryptedData } = req.body;

    if (!encryptedData) {
      console.log('Request failed: Missing encrypted data.');
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
    const { uuid, totpCode, clientPublicKey } = decryptedData;

    // Fetch TOTP secret from Firestore
    const userDoc = await db.collection('users').doc(String(uuid)).get();
    if (!userDoc.exists) {
      console.log('Enable authenticator failed: User not found.');
      return res.status(404).json({ error: 'User not found.' });
    }

    const { authenticatorSecret } = userDoc.data();

    // Verify the TOTP code
    if (!authenticator.verify({ token: totpCode, secret: authenticatorSecret })) {
      console.log('Enable authenticator failed: Invalid TOTP code.');
      return res.status(401).json({ error: 'Invalid TOTP code.' });
    }

    // Update Firestore to mark authenticator as enabled
    await db.collection('users').doc(String(uuid)).update({ isAuthenticatorEnabled: true });

    const responseData = {
      message: 'Authenticator enabled successfully.',
    };

    const clientPublicKeyBytes = Uint8Array.from(Buffer.from(clientPublicKey, 'hex'));
    const encryptedResponse = sodium.crypto_box_seal(
      Buffer.from(JSON.stringify(responseData)),
      clientPublicKeyBytes
    );

    console.log('Authenticator enabled successfully.');
    return res.status(200).json({
      encryptedData: Buffer.from(encryptedResponse).toString('base64'),
    });
  } catch (error) {
    console.error('Error enabling authenticator:', error);
    return res.status(500).json({ error: 'Failed to enable authenticator.', details: error.message });
  }
};
