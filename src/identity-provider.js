const debug = require('debug')('sqrl-protocol:identity-provider');

const boolResult = async func => {
  try {
    await func();
    return true;
  } catch (ex) {
    return false;
  }
};

class IdentityProvider {
  constructor(store) {
    this.store = store;
  }

  async find(idks) {
    const filtered = idks.filter(Boolean);
    debug('Fetching sqrl data: %O', filtered);
    const results = await this.store.retrieveSqrl(filtered);
    return results || [];
  }

  async create(userId, client) {
    if (!userId || !client) {
      return null;
    }
    const sqrlData = {
      idk: client.idk,
      suk: client.suk,
      vuk: client.vuk,
      user_id: userId,
      created: new Date().toISOString(),
      disabled: null,
      superseded: null
    };
    debug('Creating sqrl: %O', sqrlData);
    const result = await boolResult(() => this.store.createSqrl(sqrlData));
    return result ? sqrlData : null;
  }

  async enable(sqrlData) {
    debug('Enabling sqrl: %O', sqrlData);
    sqrlData.disabled = null;
    // Set flags to current choices
    return await boolResult(() => this.store.updateSqrl(sqrlData));
  }

  async disable(sqrlData) {
    debug('Disabling sqrl: %O', sqrlData);
    sqrlData.disabled = new Date().toISOString();
    return await boolResult(() => this.store.updateSqrl(sqrlData));
  }

  async superseded(sqrlData) {
    debug('Superseding sqrl: %O', sqrlData);
    const updateTime = new Date().toISOString();
    sqrlData.disabled = sqrlData.disabled || updateTime;
    sqrlData.superseded = updateTime;
    // mark old idk as disabled and superseded
    return await boolResult(() => this.store.updateSqrl(sqrlData));
  }

  async remove(sqrlData) {
    debug('Deleting sqrl: %O', sqrlData);
    // Delete login to user association
    return await boolResult(() => this.store.deleteSqrl(sqrlData));
  }
}

module.exports = IdentityProvider;
