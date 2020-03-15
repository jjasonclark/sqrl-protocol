const sqrlProtocol = require('./sqrl-protocol');
const MemorySqrlStore = require('memory-sqrl-store');

test('creates object', () => {
  const sqrlHandler = sqrlProtocol({
    authenticateUrl: 'https://example.com/authenticate',
    sqrlPath: '/sqrl',
    nutTimeout: 60 * 60 * 1000 // 1 hour in ms
  });
  expect(sqrlHandler).toEqual(
    expect.objectContaining({
      createNut: expect.any(Function),
      process: expect.any(Function),
      useCode: expect.any(Function)
    })
  );
});

test('createNut', async () => {
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
  const nut = await sqrlHandler.createNut('127.0.0.1');
  expect(nut).toEqual(
    expect.objectContaining({
      raw: expect.objectContaining({
        id: '1',
        ip: '127.0.0.1',
        idk: null,
        initial: null,
        user_id: null,
        created: expect.any(String),
        ask: null,
        identified: null,
        issued: null,
        hmac: null
      }),
      nut: expect.any(String),
      code: expect.any(String)
    })
  );
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
  const user = await store.createUser();
  expect(user).toBeTruthy();
  expect(user.id).toEqual('1');
  const nut = await sqrlHandler.createNut('127.0.0.1', user.id);
  nut.raw.identified = new Date().toISOString();
  await store.updateNut(nut.raw);
  const returnUser = await sqrlHandler.useCode('127.0.0.1', nut.code);
  expect(returnUser).toEqual(user);
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
  const result = await sqrlHandler.process('127.0.0.1', 'anything');
  expect(result).toEqual(
    expect.objectContaining({
      body:
        'dmVyPTENCnRpZj04MA0KbnV0PTZNdmFiSGlNV21NDQpxcnk9L3Nxcmw_bnV0PTZNdmFiSGlNV21NDQo',
      clientReturn: expect.objectContaining({
        nut: '6MvabHiMWmM',
        qry: '/sqrl?nut=6MvabHiMWmM',
        tif: '80',
        ver: '1'
      }),
      createdNut: expect.objectContaining({
        id: '1',
        ip: '127.0.0.1',
        idk: null,
        initial: null,
        user_id: null,
        created: expect.any(String),
        ask: null,
        identified: null,
        issued: null,
        hmac: null
      }),
      existingNut: expect.not.anything
    })
  );
});
