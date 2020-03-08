const base64url = require('universal-base64url');
const get = require('dlv');
const querystring = require('querystring');
const debug = require('debug')('sqrl-protocol');
const { decodeSQRLPack } = require('./sqrl-pack');
const { isValidSignature } = require('./signature');

const idkLength = 43;
const maxCmdLength = 7;
const protocolVersion = '1';

const decodeRequest = (body, nut) => {
  const request = querystring.decode(body);
  const client = decodeSQRLPack(base64url.decode(get(request, 'client', '')));
  debug('Decoded inputs: %O', { request, client });
  if (
    get(client, 'ver') === protocolVersion &&
    get(client, 'idk.length') === idkLength &&
    get(client, 'cmd.length') <= maxCmdLength &&
    get(client, 'opt') &&
    get(request, 'server') &&
    get(request, 'ids') &&
    // valid signature
    isValidSignature(request, request.ids, client.idk) &&
    // valid previous signature
    (!get(client, 'pidk') ||
      isValidSignature(request, request.pids, client.pidk)) &&
    // server text includes nut
    base64url
      .decode(get(request, 'server'))
      .includes(querystring.encode({ nut }))
  ) {
    return { client, request };
  }
  debug('Invalid message body');
  return {};
};

module.exports = { decodeRequest };
