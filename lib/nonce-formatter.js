const debug = require('debug')('sqrl-protocol:nonce-formatter');
const { encrypt, decrypt } = require('./crypto');

class NonceFormatter {
  constructor(secrets) {
    this.secrets = secrets;
  }

  format(nut) {
    const result = encrypt(nut.id, this.secrets);
    debug('Encrypted nut id %s to %s', nut.id, result);
    return result;
  }

  parse(nutParam) {
    const nut = decrypt(nutParam, this.secrets);
    if (nut) {
      const nutId = nut.toString().trim();
      debug('Decrypted nut %s to %s', nutParam, nutId);
      return nutId;
    }
    debug('Could not decrypt nut: %s', nutParam);
    return null;
  }
}

module.exports = NonceFormatter;
