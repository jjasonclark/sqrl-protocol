const crypto = require('crypto');
const base64url = require('universal-base64url');

const alg = 'bf-cbc';

/**
 * Signs a string to make a HMAC hash
 *
 * @param {String} message to sign
 * @param {String} secret HMAC secret value
 * @return {String} Base64Url encoded hash string
 */
const sign = (message, secret) => {
  const crypt = crypto.createHmac('sha256', secret);
  crypt.update(message);
  return base64url.encode(crypt.digest());
};

/**
 * Encrypts a buffer with Blowfish
 *
 * @param {Object} message Buffer to be encrypted
 * @param {Object} secrets key and iv secrets
 * @return {String} Base64Url encoded ID string
 */
const encrypt = (message, secrets) => {
  try {
    const cipher = crypto.createCipheriv(alg, secrets.key, secrets.iv);
    const encrypted = Buffer.concat([
      cipher.update(message.toString()),
      cipher.final()
    ]);
    return base64url.encode(encrypted);
  } catch (ex) {
    return null;
  }
};

/**
 * Decrypts a message into a buffer
 *
 * @param {String} encoded Base64 encoded message
 * @param {Object} secrets key and iv secrets
 * @return {Object} Buffer of decrypted message
 */
const decrypt = (encoded, secrets) => {
  try {
    const message = Buffer.from(encoded, 'base64');
    const decipher = crypto.createDecipheriv(alg, secrets.key, secrets.iv);
    return Buffer.concat([decipher.update(message), decipher.final()]);
  } catch (ex) {
    return null;
  }
};

module.exports = { sign, encrypt, decrypt };
