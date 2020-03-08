const base64url = require('universal-base64url');
const get = require('dlv');
const querystring = require('querystring');
const debug = require('debug')('sqrl-protocol');
const NonceFormatter = require('./nonce-formatter');
const IdentityProvider = require('./identity-provider');
const { decodeRequest } = require('./decode-request');
const { encodeSQRLPack } = require('./sqrl-pack');
const { isValidSignature } = require('./signature');
const { signHmac } = require('./hmac');
const {
  tif,
  maxIpLength,
  maxMessageSize,
  maxNutParamLength
} = require('./constants');

function sqrlProtocol(options) {
  const opts = Object.assign({}, options);
  const nutFormatter = new NonceFormatter(opts.nutSecrets);
  const codeFormatter = new NonceFormatter(opts.codeSecrets);
  const identityProvider = new IdentityProvider(opts.store);

  // use a nut for a client message
  // this is to limit each nut to a single use
  const useNut = async (nut, { idk }) => {
    nut.idk = idk;
    debug('Marking nut used: %o', nut);
    await opts.store.updateNut(nut);
  };

  // identify a nut for a sqrl identity
  const identifyNut = async (nut, { user_id }) => {
    nut.identified = new Date().toISOString();
    nut.user_id = user_id; // might be already set
    debug('Marking nut to identify user: %O', nut);
    await opts.store.updateNut(nut);
  };

  // mark a nut as issued
  // indicate a user has logged in using this identified nut
  const issueNut = async nut => {
    nut.issued = new Date().toISOString();
    debug('Marking nut issued: %o', nut);
    await opts.store.updateNut(nut);
  };

  // Create HMAC signature for an input
  const signData = what => signHmac(what.toString(), opts.hmacSecret);

  // Valid input request and nut needs next nut to continue protocol
  const createNextResponse = async (ip, currentReturn, existingNut) => {
    // Create a nut with everything except hmac
    const created = await opts.store.createNut({
      ip,
      idk: get(existingNut, 'idk', null),
      initial: get(existingNut, 'initial') || get(existingNut, 'id', null),
      user_id: get(existingNut, 'user_id', null),
      ask: null,
      hmac: null
    });
    // Add nut to client response and create an hmac signature
    const nut = nutFormatter.format(created);
    const clientReturn = Object.assign({}, currentReturn, {
      tif: currentReturn.tif.toString(16),
      nut,
      qry: `${opts.sqrlPath}?${querystring.encode({ nut })}`
    });
    return {
      clientReturn,
      existingNut,
      createdNut: created,
      body: base64url.encode(encodeSQRLPack(clientReturn))
    };
  };

  // Valid input request and nut needs next nut to continue protocol
  const createFollowUpReturn = async (clientReturn, existingNut) => {
    const response = await createNextResponse(
      existingNut.ip,
      clientReturn,
      existingNut
    );
    response.createdNut.hmac = signData(response.body);
    await opts.store.updateNut(response.createdNut);
    return response;
  };

  // Got invalid input or an error has ocurred
  // cannot trust the client params
  const createErrorReturn = (ip, clientReturn) =>
    createNextResponse(ip, clientReturn);

  // Log in an account
  const sqrlLogin = async (sqrl, nut, client, clientReturn) => {
    if (client.opt.includes('cps')) {
      // CPS log in
      clientReturn.url = `${opts.authenticateUrl}?${querystring.encode({
        code: codeFormatter.format(nut)
      })}`;
      await identifyNut(nut, sqrl);
    } else {
      // off device login
      const loginNut = await opts.store.retrieveNut(nut.initial);
      await identifyNut(loginNut, sqrl);
    }
  };

  const processRequest = async ({ client, request, ip, nut }) => {
    const clientReturn = { ver: 1, tif: 0 };

    // Do same IP check for every request
    // even if not requested to
    // If success mark return as success
    // Fail is covered when the nut is marked as invalid
    const sameIp = nut.ip === ip;
    if (sameIp) {
      clientReturn.tif |= tif.ipMatch;
    }

    // look up user
    const [sqrlData, pSqrlData] = await identityProvider.find([
      client.idk,
      client.pidk
    ]);
    debug('SQRL data: %O', { sqrlData, pSqrlData });

    // Found current idk
    if (sqrlData) {
      clientReturn.tif |= tif.idMatch;
      if (sqrlData.disabled) {
        clientReturn.tif |= tif.sqrlDisabled;
      }
      if (sqrlData.superseded) {
        clientReturn.tif |= tif.idSuperseded;
      }
      // Did the client ask for suk values?
      if (client.opt.includes('suk')) {
        clientReturn.suk = sqrlData.suk;
      }
    }

    const userIds = [nut, sqrlData, pSqrlData]
      .map(i => get(i, 'user_id'))
      .filter(Boolean);
    const allSameUser =
      userIds.length <= 1 || userIds.every(i => i === userIds[0]);
    const isBasicCommand = ['query', 'ident'].includes(client.cmd);
    if (
      // all user ids must be the same
      !allSameUser ||
      // Check IP if same ip check is requested
      (!sameIp && client.opt.includes('noiptest')) ||
      // Initial nuts are only allowed to query
      (client.cmd !== 'query' && !nut.initial) ||
      // Unknown idks can only query and ident
      (!sqrlData && !isBasicCommand) ||
      // Superseded idks can only use the query command
      (client.cmd !== 'query' && sqrlData && sqrlData.superseded) ||
      // Pidks can only query and ident
      (client.pidk && !isBasicCommand)
    ) {
      debug('Cannot processes');
      clientReturn.tif |= tif.commandFailed | tif.clientFailure;
      return clientReturn;
    }

    // Process SQRL command
    debug('Processing command: %s', client.cmd);
    switch (client.cmd) {
      case 'query':
        if (sqrlData) {
          if (sqrlData.disabled) {
            // Add the suk value so user can enable account
            clientReturn.suk = sqrlData.suk;
          } else if (nut.ask) {
            // include the encoded question
            debug('Including ask in response: %s', nut.ask);
            clientReturn.ask = nut.ask;
          }
        }
        if (pSqrlData) {
          clientReturn.tif |= tif.previousIdMatch;
          if (!sqrlData) {
            clientReturn.suk = pSqrlData.suk;
          }
        }
        return clientReturn;
      case 'ident':
        if (sqrlData) {
          if (!sqrlData.disabled && (await identityProvider.enable(sqrlData))) {
            await sqrlLogin(sqrlData, nut, client, clientReturn);
            if (client.btn) {
              debug('Got ask response btn=%s', client.btn);
              clientReturn.btn = client.btn;
            }
          } else {
            // Command failed
            clientReturn.tif |= tif.commandFailed;
            // Add the suk value so user can unlock
            clientReturn.suk = sqrlData.suk;
            debug('Ident failed on disabled account');
          }
        } else if (pSqrlData) {
          if (pSqrlData.superseded) {
            clientReturn.tif |= tif.idSuperseded | tif.commandFailed;
            debug('Previous idk has been superseded');
          } else if (
            isValidSignature(request, request.urs, pSqrlData.vuk) &&
            (await identityProvider.create(pSqrlData.user_id, client)) &&
            // mark old idk as disabled and superseded
            (await identityProvider.superseded(pSqrlData))
          ) {
            // Flag this is new idk
            clientReturn.tif |= tif.idMatch;
            // Log in an account
            await sqrlLogin(pSqrlData, nut, client, clientReturn);
          } else {
            clientReturn.tif |= tif.commandFailed;
            debug('Previous idk unlock signature failed');
          }
        } else {
          debug('Unknown idk');
          const newSqrl = nut.user_id
            ? await identityProvider.create(nut.user_id, client)
            : null;
          if (newSqrl) {
            debug('Created new SQRL: %O', newSqrl);
            clientReturn.tif |= tif.idMatch;
            await sqrlLogin(newSqrl, nut, client, clientReturn);
          } else {
            debug('Could not create identity');
            clientReturn.tif |= tif.commandFailed;
          }
        }
        return clientReturn;
      case 'enable':
        if (
          isValidSignature(request, request.urs, sqrlData.vuk) &&
          (await identityProvider.enable(sqrlData))
        ) {
          await sqrlLogin(sqrlData, nut, client, clientReturn);
          // clear disabled bit
          clientReturn.tif &= ~tif.sqrlDisabled;
        } else {
          // Command failed
          clientReturn.tif |= tif.commandFailed;
          clientReturn.suk = sqrlData.suk;
        }
        return clientReturn;
      case 'disable':
        if (await identityProvider.disable(sqrlData)) {
          // Log in an account
          await sqrlLogin(sqrlData, nut, client, clientReturn);
        }
        return clientReturn;
      case 'remove':
        if (await identityProvider.remove(sqrlData)) {
          // Log in an account
          await sqrlLogin(sqrlData, nut, client, clientReturn);
        }
        return clientReturn;
      default:
        debug('Unknown command %s', client.cmd);
        // Command failed
        clientReturn.tif |= tif.commandFailed | tif.clientFailure;
        return clientReturn;
    }
  };

  /**
   * Creates a nut for initial use by a client
   * @param {string} ip IP address of calling client
   * @param {string} userId Optional User ID
   * @param {Object} question Optional message and choice
   */
  const createNut = async (ip, userId, question) => {
    debug('Create urls %s', ip);
    const ask = [
      get(question, 'message'),
      get(question, 'choice1'),
      get(question, 'choice2')
    ]
      .filter(Boolean)
      .map(choice => base64url.encode(choice))
      .join('~');

    const savedNut = await opts.store.createNut({
      ip,
      idk: null,
      initial: null,
      user_id: userId,
      hmac: null,
      ask
    });
    debug('Saved nut %O', savedNut);
    return {
      raw: savedNut,
      nut: nutFormatter.format(savedNut),
      code: codeFormatter.format(savedNut)
    };
  };

  /**
   * Handle a single SQRL message
   *
   * @param {string} ip IP address of calling client
   * @param {string} inputNutParam nut param from request
   * @param {string} messageParam Body of request
   */
  const process = async (ip, inputNutParam, messageParam) => {
    const body = (messageParam || '').toString();
    const inputNut = (inputNutParam || '').toString();
    try {
      if (
        get(body, 'length', 0) <= maxMessageSize &&
        get(inputNut, 'length', 0) <= maxNutParamLength &&
        get(ip, 'length', 0) <= maxIpLength
      ) {
        const { client, request } = decodeRequest(body, inputNut);
        if (client && request) {
          const nutId = nutFormatter.parse(inputNut);
          if (nutId) {
            const nut = await opts.store.retrieveNut(nutId);
            if (nut) {
              const withinTimeout =
                Date.now() - Date.parse(nut.created) <= opts.nutTimeout;
              // Initial nuts can be used by any client
              // Other nuts must be used by the same client as the initial nut
              const isInitialNut = !nut.initial;
              const isFollowUpNut =
                client.idk === nut.idk && signData(request.server) === nut.hmac;
              if (withinTimeout && (isInitialNut || isFollowUpNut)) {
                await useNut(nut, client);
                const clientReturn = await processRequest({
                  client,
                  request,
                  ip,
                  nut
                });
                return await createFollowUpReturn(clientReturn, nut);
              } else {
                return await createErrorReturn(ip, {
                  ver: 1,
                  tif: tif.transientError
                });
              }
            }
          }
        }
      }
      return await createErrorReturn(ip, { ver: 1, tif: tif.clientFailure });
    } catch (error) {
      debug(error);
      return await createErrorReturn(ip, {
        ver: 1,
        tif: tif.commandFailed | tif.clientFailure
      });
    }
  };

  /**
   * Authenticate a client via it's code
   * @param {string} ip IP address of calling client
   * @param {string} codeParam Code value from client request
   */
  const useCode = async (ip, codeParam) => {
    const code = codeFormatter.parse(codeParam);
    if (!code) {
      return null;
    }
    const nut = await opts.store.retrieveNut(code.toString());
    // nut must match ip and be identified and not issued
    if (nut && nut.ip === ip && nut.identified && nut.user_id && !nut.issued) {
      await issueNut(nut);
      return await opts.store.retrieveUser(nut.user_id);
    }
    return null;
  };

  return { createNut, process, useCode };
}

module.exports = sqrlProtocol;
