const debug = require('debug')('sqrl-protocol:nut-provider');
const { signHmac } = require('./hmac');

function mapping(it) {
  if (!it) {
    return null;
  }
  return {
    id: it.id || null,
    ip: it.ip || null,
    idk: it.idk || null,
    initial: it.initial || null,
    user_id: it.user_id || null,
    created: it.created || new Date().toISOString(),
    ask: it.ask || null,
    identified: it.identified || null,
    issued: it.issued || null,
    hmac: it.hmac || null
  };
}

class NutProvider {
  constructor(store, hmacSecret) {
    this.store = store;
    this.hmacSecret = hmacSecret;
  }

  async create(it) {
    if (!it) {
      return null;
    }
    const nut = mapping(it);
    debug('Creating nut: %o', nut);
    return mapping(await this.store.createNut(nut));
  }

  async find(id) {
    return mapping(await this.store.retrieveNut(id));
  }

  // use a nut for a client message
  // this is to limit each nut to a single use
  async use(nut, { idk }) {
    nut.idk = idk;
    debug('Marking nut used: %o', nut);
    await this.store.updateNut(nut);
  }

  // identify a nut for a sqrl identity
  async identify(nut, { user_id }) {
    nut.identified = new Date().toISOString();
    nut.user_id = user_id; // might be already set
    debug('Marking nut to identify user: %O', nut);
    await this.store.updateNut(nut);
  }

  // mark a nut as issued
  // indicate a user has logged in using this identified nut
  async issue(nut) {
    nut.issued = new Date().toISOString();
    debug('Marking nut issued: %o', nut);
    await this.store.updateNut(nut);
  }

  // Create HMAC signature for an input
  async sign(nut, message) {
    nut.hmac = signHmac(message.toString(), this.hmacSecret);
    debug('Adding hmac to nut: %o', nut);
    await this.store.updateNut(nut);
  }
}

module.exports = NutProvider;
