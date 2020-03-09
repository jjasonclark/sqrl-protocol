const url = require('url');
const debug = require('debug')('sqrl-protocol');
const get = require('dlv');
const IdentityProvider = require('./identity-provider');
const NonceFormatter = require('./nonce-formatter');
const NutProvider = require('./nut-provider');
const { isValidSignature } = require('./signature');
const { tif } = require('./constants');

const appendQueryParam = (inputUrl, name, value) => {
  const parsed = new url.URL(inputUrl);
  const params = parsed.searchParams;
  params.set(name, value);
  parsed.search = params.toString();
  return parsed.toString();
};

const processMessage = async ({ client, request, ip, nut, opts }) => {
  const identityProvider = new IdentityProvider(opts.store);
  const codeFormatter = new NonceFormatter(opts.codeSecrets);
  const nutProvider = new NutProvider(opts.store, opts.hmacSecret);

  // Return value from function
  const clientReturn = { ver: 1, tif: 0 };

  // Helper method to log in an account
  const sqrlLogin = async sqrl => {
    if (client.opt.includes('cps')) {
      // CPS log in
      clientReturn.url = appendQueryParam(
        opts.authenticateUrl,
        'code',
        codeFormatter.format(nut)
      );
      await nutProvider.identify(nut, sqrl);
    } else {
      // off device login
      const loginNut = await nutProvider.find(nut.initial);
      await nutProvider.identify(loginNut, sqrl);
    }
  };

  // Do same IP check for every request
  // If success mark return as success
  // If different ip and same ip check requested then fail request
  if (nut.ip === ip) {
    clientReturn.tif |= tif.ipMatch;
  } else if (client.opt.includes('noiptest')) {
    debug('Same IP address request but are different');
    clientReturn.tif |= tif.clientFailure;
    return clientReturn;
  }

  // look up user
  const [sqrlData, pSqrlData] = await identityProvider.find([
    client.idk,
    client.pidk
  ]);
  debug('SQRL data: %O', { sqrlData, pSqrlData });

  // all user ids must be the same
  const userIds = [nut, sqrlData, pSqrlData]
    .map(i => get(i, 'user_id'))
    .filter(Boolean);
  const allSameUser =
    userIds.length <= 1 || userIds.every(i => i === userIds[0]);
  if (!allSameUser) {
    debug('All identities must be for same user');
    clientReturn.tif |= tif.commandFailed | tif.clientFailure;
    return clientReturn;
  }

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
      if (!nut.initial || get(sqrlData, 'superseded')) {
        debug('Incorrect nut or superseded identity');
        clientReturn.tif |= tif.commandFailed | tif.clientFailure;
        return clientReturn;
      } else if (sqrlData) {
        if (!sqrlData.disabled) {
          await identityProvider.enable(sqrlData);
          await sqrlLogin(sqrlData);
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
        } else if (isValidSignature(request, request.urs, pSqrlData.vuk)) {
          await identityProvider.create(pSqrlData.user_id, client);
          // mark old idk as disabled and superseded
          await identityProvider.superseded(pSqrlData);
          // Flag this is new idk
          clientReturn.tif |= tif.idMatch;
          // Log in an account
          await sqrlLogin(pSqrlData);
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
          await sqrlLogin(newSqrl);
        } else {
          debug('Could not create identity');
          clientReturn.tif |= tif.commandFailed;
        }
      }
      return clientReturn;
    case 'enable':
      if (
        nut.initial &&
        !get(sqrlData, 'superseded') &&
        isValidSignature(request, request.urs, get(sqrlData, 'vuk'))
      ) {
        await identityProvider.enable(sqrlData);
        await sqrlLogin(sqrlData);
        // clear disabled bit
        clientReturn.tif &= ~tif.sqrlDisabled;
      } else {
        // Command failed
        clientReturn.tif |= tif.commandFailed;
        clientReturn.suk = sqrlData.suk;
      }
      return clientReturn;
    case 'disable':
      if (nut.initial && sqrlData && !sqrlData.superseded) {
        await identityProvider.disable(sqrlData);
        // Log in an account
        await sqrlLogin(sqrlData);
      }
      return clientReturn;
    case 'remove':
      if (nut.initial && sqrlData && !sqrlData.superseded) {
        await identityProvider.remove(sqrlData);
        // Log in an account
        await sqrlLogin(sqrlData);
      }
      return clientReturn;
    default:
      debug('Unknown command %s', client.cmd);
  }
  // Command failed
  clientReturn.tif |= tif.commandFailed | tif.clientFailure;
  return clientReturn;
};

module.exports = { processMessage };
