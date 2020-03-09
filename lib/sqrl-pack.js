const querystring = require('querystring');
const rowSeperator = '\r\n';

const decodeSQRLPack = what =>
  what
    .toString()
    .split(rowSeperator)
    .reduce((memo, item) => Object.assign(memo, querystring.parse(item)), {});

const encodeSQRLPack = what =>
  Object.keys(what).reduce(
    (memo, key) => `${memo}${key}=${what[key]}${rowSeperator}`,
    ''
  );

module.exports = { decodeSQRLPack, encodeSQRLPack };
