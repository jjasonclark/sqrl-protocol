const sqrlProtocol = require('./sqrl-protocol');
const MemorySqrlStore = require('memory-sqrl-store');

test('creates object', () => {
  const sqrlHandler = sqrlProtocol({
    authenticateUrl: 'https://example.com/authenticate',
    sqrlPath: '/sqrl',
    nutTimeout: 60 * 60 * 1000 // 1 hour in ms
  });
  expect(sqrlHandler).toBeTruthy();
});

test('uses code', async () => {
  const store = new MemorySqrlStore();
  const sqrlHandler = sqrlProtocol({
    authenticateUrl: 'https://example.com/authenticate',
    sqrlPath: '/sqrl',
    nutTimeout: 60 * 60 * 1000, // 1 hour in ms
    store,
    hmacSecret: 'mysuperSecret!',
    codeSecrets: {
      key: 'abcdefghijklmnopqrst',
      iv: '12345678'
    },
    nutSecrets: {
      key: 'abcdefghijklmnopqrst',
      iv: '12345678'
    }
  });
  expect(sqrlHandler).toBeDefined();
  const user = await store.createUser();
  expect(user).toBeTruthy();
  expect(user.id).toEqual(1);
  const nut = await sqrlHandler.createNut('127.0.0.1', user.id);
  nut.raw.identified = new Date().toISOString();
  await store.updateNut(nut.raw);
  const returnUser = await sqrlHandler.useCode('127.0.0.1', 'qaUn_E_IrC4');
  expect(returnUser).toBeTruthy();
  expect(returnUser.id).toEqual(user.id);
});

test('handles missing body', async () => {
  const store = new MemorySqrlStore();
  const sqrlHandler = sqrlProtocol({
    authenticateUrl: 'https://example.com/authenticate',
    sqrlPath: '/sqrl',
    nutTimeout: 60 * 60 * 1000, // 1 hour in ms
    store,
    hmacSecret: 'mysuperSecret!',
    codeSecrets: {
      key: 'abcdefghijklmnopqrst',
      iv: '12345678'
    },
    nutSecrets: {
      key: 'abcdefghijklmnopqrst',
      iv: '12345678'
    }
  });
  expect(sqrlHandler).toBeDefined();
  const result = await sqrlHandler.process('127.0.0.1', 'qaUn_E_IrC4');
  expect(result.body).toEqual(
    'dmVyPTENCnRpZj04MA0KbnV0PXFhVW5fRV9JckM0DQpxcnk9L3Nxcmw_bnV0PXFhVW5fRV9JckM0DQo'
  );
});
