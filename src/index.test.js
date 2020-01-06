const { createSQRLHandler } = require('./');
const MemorySqrlStore = require('memory-sqrl-store');
const url = require('url');

test('creates object', () => {
  const sqrlHandler = createSQRLHandler({ baseUrl: 'https://example.com' });
  expect(sqrlHandler).toBeTruthy();
});

test('creates urls', async () => {
  const sqrlHandler = createSQRLHandler({
    baseUrl: 'https://example.com',
    store: new MemorySqrlStore(),
    hmacSecret: 'mysuperSecret!',
    blowfishSecrets: {
      key: 'abcdefghijklmnopqrst',
      iv: '12345678'
    }
  });
  expect(sqrlHandler).toBeTruthy();
  const urls = await sqrlHandler.createUrls('127.0.0.1');
  expect(urls).toBeDefined();
  expect(urls.login).toEqual('sqrl://example.com/sqrl?nut=qaUn_E_IrC4');
  expect(urls.poll).toEqual(
    'https://example.com/authenticate?code=TKUbaas9MTYtJAvkWENuGg'
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
    blowfishSecrets: {
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
    blowfishSecrets: {
      key: 'abcdefghijklmnopqrst',
      iv: '12345678'
    }
  });
  expect(sqrlHandler).toBeDefined();
  const user = await sqrlHandler.createUser();
  expect(user).toBeTruthy();
  expect(user.id).toEqual(1);
  const urls = await sqrlHandler.createUrls('127.0.0.1');
  store.nuts[1].identified = new Date().toISOString();
  store.nuts[1].user_id = 1;
  const parsed = new url.URL(urls.poll);
  const code = parsed.searchParams.get('code');
  expect(code).toBeTruthy();
  const returnUser = await sqrlHandler.useCode(code, '127.0.0.1');
  expect(returnUser).toBeTruthy();
  expect(returnUser.id).toEqual(1);
});

test('handles missing body', async () => {
  const store = new MemorySqrlStore();
  const sqrlHandler = createSQRLHandler({
    baseUrl: 'https://example.com',
    store,
    hmacSecret: 'mysuperSecret!',
    blowfishSecrets: {
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
