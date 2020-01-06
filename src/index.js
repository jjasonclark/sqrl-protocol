const base64url = require('universal-base64url');
const get = require('dlv');
const querystring = require('querystring');
const url = require('url');
const debug = require('debug')('sqrl-protocol');
const NonceFormatter = require('./nonce-formatter');
const IdentityProvider = require('./identity-provider');
const { decodeSQRLPack, encodeSQRLPack } = require('./sqrl-pack');
const { isValidSignature } = require('./signature');
const { signHmac } = require('./hmac');

const idkLength = 43;
const maxCmdLength = 7;
const maxIpLength = 23;
const maxMessageSize = 4096;
const maxNutParamLength = 12;
const protocolVersion = '1';
const exemptPorts = [80, 443, '80', '443', ''];
const defaultNutTimeout = 60 * 60 * 1000; // 1 hour in ms

const convertToBody = clientReturn => {
  clientReturn.tif = clientReturn.tif.toString(16);
  const rawReturn = encodeSQRLPack(clientReturn);
  return base64url.encode(rawReturn);
};

const urlJoin = (left, right) =>
  left.endsWith('/') ? left + right.substr(1) : left + right;

const defaultOptions = base => {
  const portCmd = exemptPorts.includes(base.port) ? '' : `:${base.port}`;
  return {
    nutTimeout: defaultNutTimeout,
    cancelPath: urlJoin(base.pathname, '/sqrl'),
    // used for qry return value
    sqrlUrl: urlJoin(base.pathname, '/sqrl'),
    // used for login url
    sqrlProtoUrl: urlJoin(
      `sqrl://${base.hostname}${portCmd}${base.pathname}`,
      '/sqrl'
    ),
    successUrl: urlJoin(base.toString(), '/loggedin'),
    authUrl: urlJoin(base.toString(), '/authenticate'),
    x: base.pathname.length - (base.pathname.endsWith('/') ? 1 : 0),
    cpsBaseUrl: 'http://localhost:25519',
    blowfishSecrets: {
      key: '',
      iv: ''
    },
    hmacSecret: ''
  };
};

const applyDefaults = (dest, defaults) =>
  Object.keys(defaults).reduce((memo, key) => {
    if (!Object.prototype.hasOwnProperty.call(memo, key)) {
      memo[key] = defaults[key];
    }
    return memo;
  }, dest);

const createSQRLHandler = options => {
  const apiBaseUrl = new url.URL(options.baseUrl);
  const opts = applyDefaults(
    Object.assign({}, options),
    defaultOptions(apiBaseUrl)
  );
  const nonceFormatter = new NonceFormatter(opts.blowfishSecrets);
  const identityProvider = new IdentityProvider(opts.store);

  // TODO: validate required options are set

  const signData = what => signHmac(what.toString(), opts.hmacSecret);

  const createUser = async () => {
    debug('Creating user');
    return await opts.store.createUser();
  };

  const retrieveUser = async userId => await opts.store.retrieveUser(userId);

  const deleteUser = async userId => await opts.store.deleteUser(userId);

  const createNut = async what => await opts.store.createNut(what);

  const retrieveNut = async nutId => await opts.store.retrieveNut(nutId);

  const updateNut = async nut => await opts.store.updateNut(nut);

  const findFromNutParam = nutParam => {
    debug('Nut lookup %s', nutParam);
    const nutId = nonceFormatter.parseNutParam(nutParam);
    if (nutId) {
      return retrieveNut(nutId);
    }
    return null;
  };

  const createUrls = async (ip, userId = null) => {
    debug('Create urls %s', ip);
    const savedNut = await createNut({
      ip,
      initial: null,
      user_id: userId,
      hmac: null
    });
    debug('Saved nut %O', savedNut);
    const urlReturn = { nut: nonceFormatter.formatReturnNut(savedNut) };
    if (opts.x > 0) {
      urlReturn.x = opts.x;
    }
    const cpsAuthUrl = `${opts.sqrlProtoUrl}?${querystring.encode(
      Object.assign({}, urlReturn, {
        can: base64url.encode(opts.cancelPath)
      })
    )}`;
    return {
      cps: urlJoin(opts.cpsBaseUrl, `/${base64url.encode(cpsAuthUrl)}`),
      login: `${opts.sqrlProtoUrl}?${querystring.encode(urlReturn)}`,
      poll: `${opts.authUrl}?${querystring.encode({
        code: nonceFormatter.formatOffCode(savedNut)
      })}`,
      success: opts.successUrl
    };
  };

  const useCode = async (codeParam, ip) => {
    const { code, type } = nonceFormatter.parseCodeParam(codeParam);
    if (!code || !type) {
      return null;
    }
    const nut = await retrieveNut(code);
    // nut must match ip and be identified and not issued
    // plus cps type must be follow up nut
    // plus off type must be initial nut
    if (
      nut &&
      ((type === 'off-' && !nut.initial) || (type === 'cps-' && nut.initial)) &&
      nut.ip === ip &&
      nut.identified &&
      nut.user_id &&
      !nut.issued
    ) {
      nut.issued = new Date().toISOString();
      await updateNut(nut);
      return retrieveUser(nut.user_id);
    }
    return null;
  };

  const createFollowUpReturn = async (clientReturn, existingNut) => {
    const created = await createNut({
      ip: existingNut.ip,
      initial: existingNut.initial || existingNut.id,
      user_id: existingNut.user_id,
      hmac: null
    });
    const nut = nonceFormatter.formatReturnNut(created);
    clientReturn.nut = nut;
    clientReturn.qry = `${opts.sqrlUrl}?${querystring.encode({ nut })}`;
    debug('Return values: %O', { clientReturn, created });
    const body = convertToBody(clientReturn);
    created.hmac = signData(body);
    await updateNut(created);
    return body;
  };

  const createErrorReturn = async (clientReturn, ip) => {
    const created = await createNut({
      ip,
      initial: null,
      user_id: null,
      hmac: null
    });
    const nut = nonceFormatter.formatReturnNut(created);
    clientReturn.nut = nut;
    clientReturn.qry = `${opts.sqrlUrl}?${querystring.encode({ nut })}`;
    debug('Return values: %O', { clientReturn, created });
    return convertToBody(clientReturn);
  };

  // Log in an account
  const sqrlLogin = async (sqrl, nut, client, clientReturn) => {
    let loginNut = nut;
    if (client.opt.includes('cps')) {
      // CPS log in
      loginNut = nut;
      clientReturn.url = `${opts.authUrl}?${querystring.encode({
        code: nonceFormatter.formatCpsCode(nut)
      })}`;
    } else {
      // off device login
      loginNut = await retrieveNut(nut.initial);
    }
    loginNut.identified = new Date().toISOString();
    loginNut.user_id = sqrl.user_id;
    debug('Logging in user: %O', loginNut);
    await updateNut(loginNut);
  };

  const handler = async (ip, inputNut, body) => {
    try {
      // validate input params
      if (
        !body ||
        body.toString().length > maxMessageSize ||
        !inputNut ||
        inputNut.length > maxNutParamLength ||
        !ip ||
        ip.length > maxIpLength
      ) {
        debug('Invalid inputs: %O', { inputNut, ip, body });
        return await createErrorReturn({ ver: 1, tif: 0x80 }, ip);
      }

      const request = querystring.decode(body);
      const client = decodeSQRLPack(
        base64url.decode(get(request, 'client', ''))
      );

      // validate decoded params
      if (
        !client ||
        client.ver !== protocolVersion ||
        !client.idk ||
        client.idk.length !== idkLength ||
        !client.opt ||
        !client.cmd ||
        client.cmd.length > maxCmdLength ||
        !request ||
        !request.server ||
        !request.ids ||
        // server should include nut
        request.server.includes(querystring.encode({ nut: inputNut })) ||
        // valid signature
        !isValidSignature(request, request.ids, client.idk) ||
        // valid previous signature
        (client.pidk && !isValidSignature(request, request.pids, client.pidk))
      ) {
        debug('Invalid decoded inputs: %O', { request, client });
        return await createErrorReturn({ ver: 1, tif: 0x80 }, ip);
      }

      const nut = await findFromNutParam(inputNut);
      if (
        // must have nut
        !nut ||
        // must not be used
        nut.used ||
        // Follow up nut's have same hmac
        (nut.initial && signData(request.server) !== nut.hmac) ||
        // nut created within timeout
        Date.now() - Date.parse(nut.created) > opts.nutTimeout
      ) {
        debug('Nut invalid: %s', nut);
        return await createErrorReturn({ ver: 1, tif: 0x20 }, ip);
      }
      nut.used = new Date().toISOString();
      await updateNut(nut);

      // Do same IP check for every request
      // even if not requested to
      // If success mark return as success
      // Fail is covered when the nut is marked as invalid
      const sameIp = nut.ip === ip;

      // look up user
      const [sqrlData, pSqrlData] = await identityProvider.find([
        client.idk,
        client.pidk
      ]);
      debug('SQRL data: %O', { sqrlData, pSqrlData });

      const found = [sqrlData, pSqrlData].find(i => get(i, 'user_id'));
      if (found && nut && !nut.user_id) {
        nut.user_id = found.user_id;
        debug('Claiming nut for user %d', nut.user_id);
        await updateNut(nut);
      }

      const clientReturn = { ver: 1, tif: 0 };
      if (sameIp) {
        clientReturn.tif |= 0x04;
      }

      // Found current idk
      if (sqrlData) {
        clientReturn.tif |= 0x01;
        if (sqrlData.disabled) {
          clientReturn.tif |= 0x08;
        }
        if (sqrlData.superseded) {
          clientReturn.tif |= 0x200;
        }
        // Did the client ask for suk values?
        if (client.opt.includes('suk')) {
          clientReturn.suk = sqrlData.suk;
        }
      }

      const isBasicCommand = ['query', 'ident'].includes(client.cmd);
      if (
        // Check IP if same ip check is requested
        (!sameIp && client.opt.includes('noiptest')) ||
        // Initial nuts are only allowed to query
        (client.cmd !== 'query' && !nut.initial) ||
        // Follow up nut with existing accounts have same user ids
        (nut.initial && sqrlData && sqrlData.user_id !== nut.user_id) ||
        // idk and pidk must have same user
        (sqrlData && pSqrlData && sqrlData.user_id !== pSqrlData.user_id) ||
        // Unknown idks can only query and ident
        (!sqrlData && !isBasicCommand) ||
        // Superseded idks can only use the query command
        (client.cmd !== 'query' && sqrlData && sqrlData.superseded) ||
        // Pidks can only query and ident
        (client.pidk && !isBasicCommand)
      ) {
        debug('Cannot processes');
        clientReturn.tif |= 0x40 | 0x80;
        return await createFollowUpReturn(clientReturn, nut);
      }

      // Process SQRL command
      debug('Processing command: %O', clientReturn);
      switch (client.cmd) {
        case 'query':
          if (sqrlData && sqrlData.disabled) {
            // Add the suk value so user can enable account
            clientReturn.suk = sqrlData.suk;
          }
          if (pSqrlData) {
            clientReturn.tif |= 0x02;
            if (!sqrlData) {
              clientReturn.suk = pSqrlData.suk;
            }
          }
          return await createFollowUpReturn(clientReturn, nut);
        case 'ident':
          if (sqrlData) {
            if (
              !sqrlData.disabled &&
              (await identityProvider.enable(sqrlData))
            ) {
              await sqrlLogin(sqrlData, nut, client, clientReturn);
            } else {
              // Command failed
              clientReturn.tif |= 0x40;
              // Add the suk value so user can unlock
              clientReturn.suk = sqrlData.suk;
              debug('Ident failed on disabled account');
            }
          } else if (pSqrlData) {
            if (pSqrlData.superseded) {
              clientReturn.tif |= 0x200 | 0x40;
              debug('Previous idk has been superseded');
            } else if (
              isValidSignature(request, request.urs, pSqrlData.vuk) &&
              (await identityProvider.create(pSqrlData.user_id, client)) &&
              // mark old idk as disabled and superseded
              (await identityProvider.superseded(pSqrlData))
            ) {
              // Flag this is new idk
              clientReturn.tif |= 0x01;
              // Log in an account
              await sqrlLogin(pSqrlData, nut, client, clientReturn);
            } else {
              clientReturn.tif |= 0x40;
              debug('Previous idk unlock signature failed');
            }
          } else {
            debug('Unknown idk');
            const userId = nut.user_id || get(await createUser(), 'id');
            const newSqrl = await identityProvider.create(userId, client);
            if (userId && newSqrl) {
              debug('Created new SQRL: %O', newSqrl);
              clientReturn.tif |= 0x01;
              await sqrlLogin(newSqrl, nut, client, clientReturn);
            } else {
              debug('Could not create account');
              clientReturn.tif |= 0x40;
            }
          }
          return await createFollowUpReturn(clientReturn, nut);
        case 'enable':
          if (
            isValidSignature(request, request.urs, sqrlData.vuk) &&
            (await identityProvider.enable(sqrlData))
          ) {
            await sqrlLogin(sqrlData, nut, client, clientReturn);
            // clear disabled bit
            clientReturn.tif &= ~0x08;
          } else {
            // Command failed
            clientReturn.tif |= 0x40;
            clientReturn.suk = sqrlData.suk;
          }
          return await createFollowUpReturn(clientReturn, nut);
        case 'disable':
          if (await identityProvider.disable(sqrlData)) {
            // Log in an account
            await sqrlLogin(sqrlData, nut, client, clientReturn);
          }
          return await createFollowUpReturn(clientReturn, nut);
        case 'remove':
          if (await identityProvider.remove(sqrlData)) {
            // Delete user account
            await deleteUser(sqrlData.user_id);
            // Log in an account
            await sqrlLogin(sqrlData, nut, client, clientReturn);
          }
          return await createFollowUpReturn(clientReturn, nut);
      }
      debug('Unknown command %s', client.cmd);
      // Command failed
      clientReturn.tif |= 0x40 | 0x80;
      return await createFollowUpReturn(clientReturn, nut);
    } catch (error) {
      debug(error);
      return await createErrorReturn({ ver: 1, tif: 0x40 | 0x80 }, ip);
    }
  };

  return { handler, useCode, createUrls, createUser };
};

module.exports = { createSQRLHandler };
