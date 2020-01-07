const { createSQRLHandler } = require('./');
const MemorySqrlStore = require('memory-sqrl-store');

test('creates object', () => {
  const sqrlHandler = createSQRLHandler({ baseUrl: 'https://example.com' });
  expect(sqrlHandler).toBeTruthy();
});

test('creates urls', async () => {
  const sqrlHandler = createSQRLHandler({
    baseUrl: 'https://example.com',
    store: new MemorySqrlStore(),
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
  expect(sqrlHandler).toBeTruthy();
  const urls = await sqrlHandler.createUrls('127.0.0.1');
  expect(urls).toBeDefined();
  expect(urls.login).toEqual('sqrl://example.com/sqrl?nut=qaUn_E_IrC4');
  expect(urls.poll).toEqual(
    'https://example.com/authenticate?code=qaUn_E_IrC4'
  );
  expect(urls.success).toEqual('https://example.com/loggedin');
  expect(urls.cps).toEqual(
    'http://localhost:25519/c3FybDovL2V4YW1wbGUuY29tL3Nxcmw_bnV0PXFhVW5fRV9JckM0JmNhbj1MM054Y213'
  );
});

test('creates user', async () => {
  const store = new MemorySqrlStore();
  const sqrlHandler = createSQRLHandler({
    baseUrl: 'https://example.com',
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
  const user = await sqrlHandler.createUser();
  expect(user).toBeTruthy();
  expect(user.id).toEqual(1);
});

test('uses code', async () => {
  const store = new MemorySqrlStore();
  const sqrlHandler = createSQRLHandler({
    baseUrl: 'https://example.com',
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
  const user = await sqrlHandler.createUser();
  expect(user).toBeTruthy();
  expect(user.id).toEqual(1);
  await sqrlHandler.createUrls('127.0.0.1', user.id);
  store.nuts[1].identified = new Date().toISOString();
  const returnUser = await sqrlHandler.useCode('qaUn_E_IrC4', '127.0.0.1');
  expect(returnUser).toBeTruthy();
  expect(returnUser.id).toEqual(user.id);
});

test('handles missing body', async () => {
  const store = new MemorySqrlStore();
  const sqrlHandler = createSQRLHandler({
    baseUrl: 'https://example.com',
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
  const result = await sqrlHandler.handler('127.0.0.1', 'qaUn_E_IrC4', null);
  expect(result).toEqual(
    'dmVyPTENCnRpZj04MA0KbnV0PXFhVW5fRV9JckM0DQpxcnk9L3Nxcmw_bnV0PXFhVW5fRV9JckM0DQo'
  );
});
