const querystring = require('querystring');
const rowSeperator = '\r\n';

// TODO: handle just strings
const decodeSQRLPack = what =>
  what
    .split(rowSeperator)
    .reduce((memo, item) => Object.assign(memo, querystring.decode(item)), {});

// TODO: handle just string
const encodeSQRLPack = what =>
  Object.keys(what).reduce(
    (memo, key) => `${memo}${key}=${what[key]}${rowSeperator}`,
    ''
  );

module.exports = { decodeSQRLPack, encodeSQRLPack };
