const { createHmac } = require('crypto');
const base64url = require('universal-base64url');

const signHmac = (message, secret) => {
  const crypt = createHmac('sha256', secret);
  crypt.update(message);
  return base64url.encode(crypt.digest());
};

module.exports = { signHmac };
