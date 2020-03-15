const debug = require('debug')('sqrl-protocol');
const base64url = require('universal-base64url');
const get = require('dlv');
const url = require('url');
const NonceFormatter = require('./nonce-formatter');
const NutProvider = require('./nut-provider');
const { decodeMessage } = require('./decode-message');
const { encodeSQRLPack } = require('./sqrl-pack');
const { processMessage } = require('./process-message');
const crypto = require('./crypto');
const {
  tif,
  maxIpLength,
  maxMessageSize,
  maxNutParamLength,
  protocolVersion
} = require('./constants');

function sqrlProtocol(options) {
  const opts = Object.assign({}, options);
  const nutFormatter = new NonceFormatter(opts.nutSecrets);
  const codeFormatter = new NonceFormatter(opts.codeSecrets);
  const nutProvider = new NutProvider(opts.store, opts.hmacSecret);

  // Create HMAC signature for an input
  const hasSameHmac = (what, hmac) =>
    crypto.sign(what.toString(), opts.hmacSecret) === hmac;

  const withinTimeout = nut =>
    Date.now() - Date.parse(nut.created) <= opts.nutTimeout;

  const createNextSqrlPath = nut =>
    [opts.sqrlPath, new url.URLSearchParams({ nut })].join('?');

  const findUser = async userId => await opts.store.retrieveUser(userId);

  // Valid input request and nut needs next nut to continue protocol
  const createNextResponse = async (ip, currentReturn, existingNut) => {
    // Create a nut with everything except hmac
    const created = await nutProvider.create({
      ip,
      idk: get(existingNut, 'idk', null),
      initial: get(existingNut, 'initial') || get(existingNut, 'id', null),
      user_id: get(existingNut, 'user_id', null)
    });
    // Add nut to client response and create an hmac signature
    const nut = nutFormatter.format(created);
    const clientReturn = Object.assign({}, currentReturn, {
      tif: currentReturn.tif.toString(16),
      nut,
      qry: createNextSqrlPath(nut)
    });
    return {
      clientReturn,
      existingNut,
      createdNut: created,
      body: base64url.encode(encodeSQRLPack(clientReturn))
    };
  };

  // Valid input request and nut needs next nut to continue protocol
  const createFollowUpReturn = async (ip, clientReturn, existingNut) => {
    const response = await createNextResponse(ip, clientReturn, existingNut);
    await nutProvider.sign(response.createdNut, response.body);
    return response;
  };

  // Got invalid input or an error has ocurred
  // cannot trust the client params
  const createErrorReturn = (ip, clientReturn) =>
    createNextResponse(ip, clientReturn);

  /**
   * Creates a nut for initial use by a client
   * @param {String} ip IP address of calling client
   * @param {String} userId Optional User ID
   * @param {Object} question Optional message and choice
   * @return {Object} Object with raw nut object and nut and code formatted values
   * @api public
   */
  const createNut = async (ip, userId, question) => {
    debug('Create nut %s, %s, %o', ip, userId, question);
    const ask = [
      get(question, 'message'),
      get(question, 'choice1'),
      get(question, 'choice2')
    ]
      .filter(Boolean)
      .map(choice => base64url.encode(choice))
      .join('~');

    const savedNut = await nutProvider.create({ ip, user_id: userId, ask });
    return {
      raw: savedNut,
      nut: nutFormatter.format(savedNut),
      code: codeFormatter.format(savedNut)
    };
  };

  /**
   * Handle a single SQRL message
   *
   * @param {String} ip IP address of calling client
   * @param {String} inputNutParam nut param from request
   * @param {String} messageParam Body of request
   * @return {Object} SQRL response with body
   * @api public
   */
  const process = async (ip, inputNutParam, messageParam) => {
    const body = (messageParam || '').toString();
    const inputNut = (inputNutParam || '').toString();
    debug('Process message %s, %s, %s', ip, inputNut, body);
    try {
      if (
        get(body, 'length', 0) <= maxMessageSize &&
        get(inputNut, 'length', 0) <= maxNutParamLength &&
        get(ip, 'length', 0) <= maxIpLength
      ) {
        const { client, request } = decodeMessage(body, inputNut);
        if (client && request) {
          const nutId = nutFormatter.parse(inputNut);
          if (nutId) {
            const nut = await nutProvider.find(nutId);
            if (nut) {
              // Initial nuts can be used by any client
              // Other nuts must be used by the same client as the initial nut
              const isInitialNut = !nut.initial;
              const isFollowUpNut =
                client.idk === nut.idk && hasSameHmac(request.server, nut.hmac);
              if (withinTimeout(nut) && (isInitialNut || isFollowUpNut)) {
                await nutProvider.use(nut, client);
                const clientReturn = await processMessage({
                  client,
                  request,
                  ip,
                  nut,
                  opts
                });
                debug('Processed message');
                return await createFollowUpReturn(ip, clientReturn, nut);
              } else {
                debug('Failed to process message: nut issue');
                return await createErrorReturn(ip, {
                  ver: protocolVersion,
                  tif: tif.transientError
                });
              }
            }
          }
        }
      }
      debug('Failed to process message: client issue');
      return await createErrorReturn(ip, {
        ver: protocolVersion,
        tif: tif.clientFailure
      });
    } catch (error) {
      debug('Error while processing message');
      debug(error);
      return await createErrorReturn(ip, {
        ver: protocolVersion,
        tif: tif.commandFailed | tif.clientFailure
      });
    }
  };

  /**
   * Authenticate a client via it's code
   * @param {String} ip IP address of calling client
   * @param {String} codeParam Code value from client request
   * @return {Object} User data
   * @api public
   */
  const useCode = async (ip, codeParam) => {
    debug('Use code %s, %s', ip, codeParam);
    const nutId = codeFormatter.parse(codeParam);
    if (!nutId) {
      debug('Nut not found %s', nutId);
      return null;
    }
    const nut = await nutProvider.find(nutId);
    // nut must match ip and be identified and not issued
    if (nut && nut.ip === ip && nut.identified && nut.user_id && !nut.issued) {
      debug('Authenticating user %s', nut.user_id);
      await nutProvider.issue(nut);
      const dbUser = await findUser(nut.user_id);
      return {
        id: dbUser.id || null,
        created: dbUser.created || null
      };
    }
    return null;
  };

  return { createNut, process, useCode };
}

module.exports = sqrlProtocol;
