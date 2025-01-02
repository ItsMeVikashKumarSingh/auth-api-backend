const { authenticator } = require('otplib');
const qrcode = require('qrcode');
const db = require('../utils/firebaseAdmin');
const sodium = require('libsodium-wrappers');
require('dotenv').config();

const PRIVATE_KEY_HEX = process.env.PRIVATE_KEY_HEX;
const PUBLIC_KEY_HEX = process.env.PUBLIC_KEY_HEX;

module.exports = async (req, res) => {
  console.log('Incoming request to generate QR code.');

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
    const { uuid, clientPublicKey } = decryptedData;

    // Generate TOTP secret
    const serviceName = process.env.SERVICE_NAME || 'MySecureApp';
    const totpSecret = authenticator.generateSecret();
    const otpauthUrl = authenticator.keyuri(uuid, serviceName, totpSecret);

    // Generate QR code
    const qrCodeUrl = await qrcode.toDataURL(otpauthUrl);

    // Store TOTP secret in Firestore
    await db.collection('users').doc(String(uuid)).update({ authenticatorSecret: totpSecret });

    // Encrypt the response
    const responseData = {
      message: 'QR code generated successfully.',
      qrCodeUrl,
    };

    const clientPublicKeyBytes = Uint8Array.from(Buffer.from(clientPublicKey, 'hex'));
    const encryptedResponse = sodium.crypto_box_seal(
      Buffer.from(JSON.stringify(responseData)),
      clientPublicKeyBytes
    );

    console.log('QR code generated successfully.');
    return res.status(200).json({
      encryptedData: Buffer.from(encryptedResponse).toString('base64'),
    });
  } catch (error) {
    console.error('Error generating QR code:', error);
    return res.status(500).json({ error: 'Failed to generate QR code.', details: error.message });
  }
};
