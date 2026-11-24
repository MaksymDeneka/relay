import assert from 'node:assert/strict';
import test from 'node:test';
import { parseProxyList, parseProxyToken } from '../lib/proxies.mjs';

test('parses spreadsheet rows with type and provider columns', () => {
  const text = [
    '185\tsocks\tgw.proxy.example:1337:user1-country-us-sid-37067750-ttl-60:secret\tacme',
    'socks  gw.proxy.example:1337:user1-country-us-sid-5394237-ttl-60:secret  acme',
  ].join('\n');
  const { proxies, errors } = parseProxyList(text);
  assert.equal(errors.length, 0);
  assert.equal(proxies.length, 2);
  assert.deepEqual(
    { type: proxies[0].type, host: proxies[0].host, port: proxies[0].port, username: proxies[0].username, password: proxies[0].password },
    { type: 'socks5', host: 'gw.proxy.example', port: 1337, username: 'user1-country-us-sid-37067750-ttl-60', password: 'secret' },
  );
  assert.equal(proxies[0].label, 'sid 37067750');
  assert.equal(proxies[0].country, 'US');
  assert.equal(proxies[0].provider, 'acme');
});

test('parses URL and user:pass@host:port forms', () => {
  assert.equal(parseProxyToken('http://a:b@1.2.3.4:8080').type, 'http');
  const s = parseProxyToken('socks5://us%40er:p:w@host.example:1080');
  assert.equal(s.username, 'us@er');
  assert.equal(s.password, 'p:w');
  const plain = parseProxyToken('user:pass@host.example:9000');
  assert.equal(plain.port, 9000);
  assert.equal(parseProxyToken('user:pass:host.example:9000').host, 'host.example');
  assert.equal(parseProxyToken('host.example:9000').username, '');
});

test('skips duplicates, comments and reports bad lines', () => {
  const { proxies, errors } = parseProxyList('# c\nh.example:1:u:p\nh.example:1:u:p\nnot a proxy\n');
  assert.equal(proxies.length, 1);
  assert.equal(errors.length, 1);
  assert.equal(errors[0].line, 4);
});

test('the same proxy always gets the same id', () => {
  const a = parseProxyToken('h.example:1:u:p');
  const b = parseProxyToken('socks5://u:p@H.example:1');
  assert.equal(a.id, b.id);
});
