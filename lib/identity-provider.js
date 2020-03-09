const debug = require('debug')('sqrl-protocol:identity-provider');

function mapping(it) {
  if (!it) {
    return null;
  }
  return {
    id: it.id || null,
    idk: it.idk || null,
    suk: it.suk || null,
    vuk: it.vuk || null,
    user_id: it.user_id || null,
    created: it.created || new Date().toISOString(),
    disabled: it.disabled || null,
    superseded: it.superseded || null
  };
}

class IdentityProvider {
  constructor(store) {
    this.store = store;
  }

  async find(idks) {
    const filtered = idks.filter(Boolean);
    debug('Fetching sqrl data: %o', filtered);
    const results = await this.store.retrieveSqrl(filtered);
    return (results || []).map(mapping);
  }

  async create(userId, client) {
    if (!userId || !client) {
      return null;
    }
    const sqrlData = mapping({
      idk: client.idk,
      suk: client.suk,
      vuk: client.vuk,
      user_id: userId
    });
    debug('Creating sqrl: %o', sqrlData);
    return mapping(await this.store.createSqrl(sqrlData));
  }

  async enable(sqrlData) {
    debug('Enabling sqrl: %o', sqrlData);
    sqrlData.disabled = null;
    // Set flags to current choices
    await this.store.updateSqrl(sqrlData);
  }

  async disable(sqrlData) {
    debug('Disabling sqrl: %o', sqrlData);
    sqrlData.disabled = new Date().toISOString();
    await this.store.updateSqrl(sqrlData);
  }

  async superseded(sqrlData) {
    debug('Superseding sqrl: %o', sqrlData);
    const updateTime = new Date().toISOString();
    sqrlData.disabled = sqrlData.disabled || updateTime;
    sqrlData.superseded = updateTime;
    // mark old idk as disabled and superseded
    await this.store.updateSqrl(sqrlData);
  }

  async remove(sqrlData) {
    debug('Deleting sqrl: %o', sqrlData);
    // do not delete, just disable the identity
    sqrlData.disabled = new Date().toISOString();
    await this.store.updateSqrl(sqrlData);
  }
}

module.exports = IdentityProvider;
