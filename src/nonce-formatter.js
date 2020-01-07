const crypto = require('crypto');
const base64url = require('universal-base64url');

const alg = 'bf-cbc';
const Uint32Size = 4;

const encrypt = (message, secrets) => {
  try {
    const cipher = crypto.createCipheriv(alg, secrets.key, secrets.iv);
    const encrypted = Buffer.concat([cipher.update(message), cipher.final()]);
    return base64url.encode(encrypted);
  } catch (ex) {
    return null;
  }
};

const decrypt = (encoded, secrets) => {
  try {
    const message = Buffer.from(encoded, 'base64');
    const decipher = crypto.createDecipheriv(alg, secrets.key, secrets.iv);
    return Buffer.concat([decipher.update(message), decipher.final()]);
  } catch (ex) {
    return null;
  }
};

const intToBuffer = nut => {
  const message = new ArrayBuffer(Uint32Size);
  const dv = new DataView(message, 0, Uint32Size);
  dv.setUint32(0, nut.id, false);
  return Buffer.from(message);
};

class NonceFormatter {
  constructor(secrets) {
    this.secrets = secrets;
  }

  format(nut) {
    return encrypt(intToBuffer(nut), this.secrets);
  }

  parse(nutParam) {
    const nut = decrypt(nutParam, this.secrets);
    if (nut) {
      return nut.readUInt32BE(0);
    }
    return null;
  }
}

module.exports = NonceFormatter;
