'use strict'

const { test } = require('tap')
const proxyaddr = require('..')

test('req should be required', function (t) {
  t.throws(proxyaddr, /req.*required/)
  t.end()
})

test('trust should be required', function (t) {
  const req = createReq('127.0.0.1')
  t.throws(proxyaddr.bind(null, req), /trust.*required/)
  t.end()
})

test('trust should accept a function', function (t) {
  const req = createReq('127.0.0.1')
  t.doesNotThrow(proxyaddr.bind(null, req, all))
  t.end()
})

test('trust should accept an array', function (t) {
  const req = createReq('127.0.0.1')
  t.doesNotThrow(proxyaddr.bind(null, req, []))
  t.end()
})

test('trust should accept a string', function (t) {
  const req = createReq('127.0.0.1')
  t.doesNotThrow(proxyaddr.bind(null, req, '127.0.0.1'))
  t.end()
})

test('trust should reject a number', function (t) {
  const req = createReq('127.0.0.1')
  t.throws(proxyaddr.bind(null, req, 42), /unsupported trust argument/)
  t.end()
})

test('trust should accept IPv4', function (t) {
  const req = createReq('127.0.0.1')
  t.doesNotThrow(proxyaddr.bind(null, req, '127.0.0.1'))
  t.end()
})

test('trust should accept IPv6', function (t) {
  const req = createReq('127.0.0.1')
  t.doesNotThrow(proxyaddr.bind(null, req, '::1'))
  t.end()
})

test('trust should accept IPv4-style IPv6', function (t) {
  const req = createReq('127.0.0.1')
  t.doesNotThrow(proxyaddr.bind(null, req, '::ffff:127.0.0.1'))
  t.end()
})

test('trust should accept pre-defined names', function (t) {
  const req = createReq('127.0.0.1')
  t.doesNotThrow(proxyaddr.bind(null, req, 'loopback'))
  t.end()
})

test('trust should accept pre-defined names in array', function (t) {
  const req = createReq('127.0.0.1')
  t.doesNotThrow(proxyaddr.bind(null, req, ['loopback', '10.0.0.1']))
  t.end()
})

test('trust should not alter input array', function (t) {
  const arr = ['loopback', '10.0.0.1']
  const req = createReq('127.0.0.1')
  t.doesNotThrow(proxyaddr.bind(null, req, arr))
  t.deepEqual(arr, ['loopback', '10.0.0.1'])
  t.end()
})

test('trust should reject non-IP', function (t) {
  const req = createReq('127.0.0.1')
  t.throws(proxyaddr.bind(null, req, 'blargh'), /invalid IP address/)
  t.throws(proxyaddr.bind(null, req, '10.0.300.1'), /invalid IP address/)
  t.throws(proxyaddr.bind(null, req, '::ffff:30.168.1.9000'), /invalid IP address/)
  t.throws(proxyaddr.bind(null, req, '-1'), /invalid IP address/)
  t.end()
})

test('trust should reject bad CIDR', function (t) {
  const req = createReq('127.0.0.1')
  t.throws(proxyaddr.bind(null, req, '10.0.0.1/internet'), /invalid range on address/)
  t.throws(proxyaddr.bind(null, req, '10.0.0.1/6000'), /invalid range on address/)
  t.throws(proxyaddr.bind(null, req, '::1/6000'), /invalid range on address/)
  t.throws(proxyaddr.bind(null, req, '::ffff:a00:2/136'), /invalid range on address/)
  t.throws(proxyaddr.bind(null, req, '::ffff:a00:2/-1'), /invalid range on address/)
  t.end()
})

test('trust should reject bad netmask', function (t) {
  const req = createReq('127.0.0.1')
  t.throws(proxyaddr.bind(null, req, '10.0.0.1/255.0.255.0'), /invalid range on address/)
  t.throws(proxyaddr.bind(null, req, '10.0.0.1/ffc0::'), /invalid range on address/)
  t.throws(proxyaddr.bind(null, req, 'fe80::/ffc0::'), /invalid range on address/)
  t.throws(proxyaddr.bind(null, req, 'fe80::/255.255.255.0'), /invalid range on address/)
  t.throws(proxyaddr.bind(null, req, '::ffff:a00:2/255.255.255.0'), /invalid range on address/)
  t.end()
})

test('trust should be invoked as trust(addr, i)', function (t) {
  const log = []
  const req = createReq('127.0.0.1', {
    'x-forwarded-for': '192.168.0.1, 10.0.0.1'
  })

  proxyaddr(req, function (addr, i) {
    return log.push(Array.prototype.slice.call(arguments))
  })

  t.deepEqual(log, [
    ['127.0.0.1', 0],
    ['10.0.0.1', 1]
  ])

  t.end()
})

test('with all trusted should return socket address wtesth no headers', function (t) {
  const req = createReq('127.0.0.1')
  t.strictEqual(proxyaddr(req, all), '127.0.0.1')
  t.end()
})

test('with all trusted should return header value', function (t) {
  const req = createReq('127.0.0.1', {
    'x-forwarded-for': '10.0.0.1'
  })
  t.strictEqual(proxyaddr(req, all), '10.0.0.1')
  t.end()
})

test('with all trusted should return furthest header value', function (t) {
  const req = createReq('127.0.0.1', {
    'x-forwarded-for': '10.0.0.1, 10.0.0.2'
  })
  t.strictEqual(proxyaddr(req, all), '10.0.0.1')
  t.end()
})

test('with none trusted should return socket address wtesth no headers', function (t) {
  const req = createReq('127.0.0.1')
  t.strictEqual(proxyaddr(req, none), '127.0.0.1')
  t.end()
})

test('with none trusted should return socket address wtesth headers', function (t) {
  const req = createReq('127.0.0.1', {
    'x-forwarded-for': '10.0.0.1, 10.0.0.2'
  })
  t.strictEqual(proxyaddr(req, none), '127.0.0.1')
  t.end()
})

test('with some trusted should return socket address wtesth no headers', function (t) {
  const req = createReq('127.0.0.1')
  t.strictEqual(proxyaddr(req, trust10x), '127.0.0.1')
  t.end()
})

test('with some trusted should return socket address when not trusted', function (t) {
  const req = createReq('127.0.0.1', {
    'x-forwarded-for': '10.0.0.1, 10.0.0.2'
  })
  t.strictEqual(proxyaddr(req, trust10x), '127.0.0.1')
  t.end()
})

test('with some trusted should return header when socket trusted', function (t) {
  const req = createReq('10.0.0.1', {
    'x-forwarded-for': '192.168.0.1'
  })
  t.strictEqual(proxyaddr(req, trust10x), '192.168.0.1')
  t.end()
})

test('with some trusted should return first untrusted after trusted', function (t) {
  const req = createReq('10.0.0.1', {
    'x-forwarded-for': '192.168.0.1, 10.0.0.2'
  })
  t.strictEqual(proxyaddr(req, trust10x), '192.168.0.1')
  t.end()
})

test('with some trusted should not skip untrusted', function (t) {
  const req = createReq('10.0.0.1', {
    'x-forwarded-for': '10.0.0.3, 192.168.0.1, 10.0.0.2'
  })
  t.strictEqual(proxyaddr(req, trust10x), '192.168.0.1')
  t.end()
})

test('when given array should accept ltesteral IP addresses', function (t) {
  const req = createReq('10.0.0.1', {
    'x-forwarded-for': '192.168.0.1, 10.0.0.2'
  })
  t.strictEqual(proxyaddr(req, ['10.0.0.1', '10.0.0.2']), '192.168.0.1')
  t.end()
})

test('when given array should not trust non-IP addresses', function (t) {
  const req = createReq('10.0.0.1', {
    'x-forwarded-for': '192.168.0.1, 10.0.0.2, localhost'
  })
  t.strictEqual(proxyaddr(req, ['10.0.0.1', '10.0.0.2']), 'localhost')
  t.end()
})

test('when given array should return socket address if none match', function (t) {
  const req = createReq('10.0.0.1', {
    'x-forwarded-for': '192.168.0.1, 10.0.0.2'
  })
  t.strictEqual(proxyaddr(req, ['127.0.0.1', '192.168.0.100']), '10.0.0.1')
  t.end()
})

test('when array empty should return socket address ', function (t) {
  const req = createReq('127.0.0.1')
  t.strictEqual(proxyaddr(req, []), '127.0.0.1')
  t.end()
})

test('when array empty should return socket address wtesth headers', function (t) {
  const req = createReq('127.0.0.1', {
    'x-forwarded-for': '10.0.0.1, 10.0.0.2'
  })
  t.strictEqual(proxyaddr(req, []), '127.0.0.1')
  t.end()
})

test('when given IPv4 addresses should accept ltesteral IP addresses', function (t) {
  const req = createReq('10.0.0.1', {
    'x-forwarded-for': '192.168.0.1, 10.0.0.2'
  })
  t.strictEqual(proxyaddr(req, ['10.0.0.1', '10.0.0.2']), '192.168.0.1')
  t.end()
})

test('when given IPv4 addresses should accept CIDR notation', function (t) {
  const req = createReq('10.0.0.1', {
    'x-forwarded-for': '192.168.0.1, 10.0.0.200'
  })
  t.strictEqual(proxyaddr(req, '10.0.0.2/26'), '10.0.0.200')
  t.end()
})

test('when given IPv4 addresses should accept netmask notation', function (t) {
  const req = createReq('10.0.0.1', {
    'x-forwarded-for': '192.168.0.1, 10.0.0.200'
  })
  t.strictEqual(proxyaddr(req, '10.0.0.2/255.255.255.192'), '10.0.0.200')
  t.end()
})

test('when given IPv6 addresses should accept ltesteral IP addresses', function (t) {
  const req = createReq('fe80::1', {
    'x-forwarded-for': '2002:c000:203::1, fe80::2'
  })
  t.strictEqual(proxyaddr(req, ['fe80::1', 'fe80::2']), '2002:c000:203::1')
  t.end()
})

test('when given IPv6 addresses should accept CIDR notation', function (t) {
  const req = createReq('fe80::1', {
    'x-forwarded-for': '2002:c000:203::1, fe80::ff00'
  })
  t.strictEqual(proxyaddr(req, 'fe80::/125'), 'fe80::ff00')
  t.end()
})

test('with IP version mixed should match respective versions', function (t) {
  const req = createReq('::1', {
    'x-forwarded-for': '2002:c000:203::1'
  })
  t.strictEqual(proxyaddr(req, ['127.0.0.1', '::1']), '2002:c000:203::1')
  t.end()
})

test('with IP version mixed should not match IPv4 to IPv6', function (t) {
  const req = createReq('::1', {
    'x-forwarded-for': '2002:c000:203::1'
  })
  t.strictEqual(proxyaddr(req, '127.0.0.1'), '::1')
  t.end()
})

test('when IPv4-mapped IPv6 addresses should match IPv4 trust to IPv6 request', function (t) {
  const req = createReq('::ffff:a00:1', {
    'x-forwarded-for': '192.168.0.1, 10.0.0.2'
  })
  t.strictEqual(proxyaddr(req, ['10.0.0.1', '10.0.0.2']), '192.168.0.1')
  t.end()
})

test('when IPv4-mapped IPv6 addresses should match IPv4 netmask trust to IPv6 request', function (t) {
  const req = createReq('::ffff:a00:1', {
    'x-forwarded-for': '192.168.0.1, 10.0.0.2'
  })
  t.strictEqual(proxyaddr(req, ['10.0.0.1/16']), '192.168.0.1')
  t.end()
})

test('when IPv4-mapped IPv6 addresses should match IPv6 trust to IPv4 request', function (t) {
  const req = createReq('10.0.0.1', {
    'x-forwarded-for': '192.168.0.1, 10.0.0.2'
  })
  t.strictEqual(proxyaddr(req, ['::ffff:a00:1', '::ffff:a00:2']), '192.168.0.1')
  t.end()
})

test('when IPv4-mapped IPv6 addresses should match CIDR notation for IPv4-mapped address', function (t) {
  const req = createReq('10.0.0.1', {
    'x-forwarded-for': '192.168.0.1, 10.0.0.200'
  })
  t.strictEqual(proxyaddr(req, '::ffff:a00:2/122'), '10.0.0.200')
  t.end()
})

test('when IPv4-mapped IPv6 addresses should match CIDR notation for IPv4-mapped address mixed wtesth IPv6 CIDR', function (t) {
  const req = createReq('10.0.0.1', {
    'x-forwarded-for': '192.168.0.1, 10.0.0.200'
  })
  t.strictEqual(proxyaddr(req, ['::ffff:a00:2/122', 'fe80::/125']), '10.0.0.200')
  t.end()
})

test('when IPv4-mapped IPv6 addresses should match CIDR notation for IPv4-mapped address mixed wtesth IPv4 addresses', function (t) {
  const req = createReq('10.0.0.1', {
    'x-forwarded-for': '192.168.0.1, 10.0.0.200'
  })
  t.strictEqual(proxyaddr(req, ['::ffff:a00:2/122', '127.0.0.1']), '10.0.0.200')
  t.end()
})

test('when IPv4-mapped IPv6 trust subnet has a short prefix it should not trust arbitrary IPv4', function (t) {
  const req = createReq('1.1.1.1', {
    'x-forwarded-for': '6.6.6.6'
  })
  t.strictEqual(proxyaddr(req, '::ffff:10.0.0.0/8'), '1.1.1.1')
  t.end()
})

test('when IPv6 trust subnet has zero leading bits it should not trust arbitrary IPv4', function (t) {
  const req = createReq('1.1.1.1', {
    'x-forwarded-for': '6.6.6.6'
  })
  t.strictEqual(proxyaddr(req, '::/1'), '1.1.1.1')
  t.end()
})

test('when IPv4-mapped IPv6 trust subnet is used a native IPv6 address should not match', function (t) {
  const req = createReq('2001:db8::1', {
    'x-forwarded-for': '6.6.6.6'
  })
  t.strictEqual(proxyaddr(req, '::ffff:10.0.0.0/104'), '2001:db8::1')
  t.end()
})

test('when IPv4-mapped IPv6 trust subnet in a list has a short prefix it should not trust arbitrary IPv4', function (t) {
  const req = createReq('1.1.1.1', {
    'x-forwarded-for': '6.6.6.6'
  })
  t.strictEqual(proxyaddr(req, ['::ffff:10.0.0.0/8', '127.0.0.1']), '1.1.1.1')
  t.end()
})

test('when IPv4-mapped IPv6 trust subnet in a list is used a native IPv6 address should not match', function (t) {
  const req = createReq('2001:db8::1', {
    'x-forwarded-for': '6.6.6.6'
  })
  t.strictEqual(proxyaddr(req, ['::ffff:10.0.0.0/104', 'fe80::/125']), '2001:db8::1')
  t.end()
})

test('when IPv6 trust subnet has zero leading bits it should not trust an IPv4-mapped IPv6 address', function (t) {
  const req = createReq('::ffff:1.1.1.1', {
    'x-forwarded-for': '6.6.6.6'
  })
  t.strictEqual(proxyaddr(req, '::/1'), '::ffff:1.1.1.1')
  t.strictEqual(proxyaddr(req, ['::/1', '127.0.0.1']), '::ffff:1.1.1.1')
  t.end()
})

test('when IPv4-mapped IPv6 trust subnet has a short prefix it should not trust an arbitrary IPv4-mapped IPv6 address', function (t) {
  const req = createReq('::ffff:1.1.1.1', {
    'x-forwarded-for': '6.6.6.6'
  })
  t.strictEqual(proxyaddr(req, '::ffff:10.0.0.0/8'), '::ffff:1.1.1.1')
  t.strictEqual(proxyaddr(req, ['::ffff:10.0.0.0/8', '127.0.0.1']), '::ffff:1.1.1.1')
  t.end()
})

test('when IPv4-mapped IPv6 trust subnet has a short prefix a native IPv6 address with zero leading bits should not match', function (t) {
  const req = createReq('ab::1', {
    'x-forwarded-for': '6.6.6.6'
  })
  t.strictEqual(proxyaddr(req, '::ffff:10.0.0.0/8'), 'ab::1')
  t.strictEqual(proxyaddr(req, ['::ffff:10.0.0.0/8', 'fe80::/125']), 'ab::1')
  t.end()
})

test('when IPv4-mapped IPv6 trust subnet covers the mapped marker it should still trust matching addresses', function (t) {
  const req = createReq('::ffff:10.0.0.5', {
    'x-forwarded-for': '6.6.6.6'
  })
  t.strictEqual(proxyaddr(req, '::ffff:10.0.0.0/104'), '6.6.6.6')
  t.strictEqual(proxyaddr(req, ['::ffff:10.0.0.0/104', 'fe80::/125']), '6.6.6.6')
  t.strictEqual(proxyaddr(createReq('10.0.0.5', { 'x-forwarded-for': '6.6.6.6' }), '::ffff:10.0.0.0/104'), '6.6.6.6')
  t.strictEqual(proxyaddr(createReq('10.0.0.5', { 'x-forwarded-for': '6.6.6.6' }), ['::ffff:10.0.0.0/104', 'fe80::/125']), '6.6.6.6')
  t.end()
})

test('when given predefined names should accept single pre-defined name', function (t) {
  const req = createReq('fe80::1', {
    'x-forwarded-for': '2002:c000:203::1, fe80::2'
  })
  t.strictEqual(proxyaddr(req, 'linklocal'), '2002:c000:203::1')
  t.end()
})

test('when given predefined names should accept multiple pre-defined names', function (t) {
  const req = createReq('::1', {
    'x-forwarded-for': '2002:c000:203::1, fe80::2'
  })
  t.strictEqual(proxyaddr(req, ['loopback', 'linklocal']), '2002:c000:203::1')
  t.end()
})

test('when header contains non-ip addresses should stop at first non-ip after trusted', function (t) {
  const req = createReq('127.0.0.1', {
    'x-forwarded-for': 'myrouter, 127.0.0.1, proxy'
  })
  t.strictEqual(proxyaddr(req, '127.0.0.1'), 'proxy')
  t.end()
})

test('when header contains non-ip addresses should stop at first malformed ip after trusted', function (t) {
  const req = createReq('127.0.0.1', {
    'x-forwarded-for': 'myrouter, 127.0.0.1, ::8:8:8:8:8:8:8:8:8'
  })
  t.strictEqual(proxyaddr(req, '127.0.0.1'), '::8:8:8:8:8:8:8:8:8')
  t.end()
})

test('when header contains non-ip addresses should provide all values to function', function (t) {
  const log = []
  const req = createReq('127.0.0.1', {
    'x-forwarded-for': 'myrouter, 127.0.0.1, proxy'
  })

  proxyaddr(req, function (addr, i) {
    return log.push(Array.prototype.slice.call(arguments))
  })

  t.deepEqual(log, [
    ['127.0.0.1', 0],
    ['proxy', 1],
    ['127.0.0.1', 2]
  ])
  t.end()
})

test('when socket address undefined should return undefined as address', function (t) {
  const req = createReq(undefined)
  t.strictEqual(proxyaddr(req, '127.0.0.1'), undefined)
  t.end()
})

test('when socket address undefined should return undefined even wtesth trusted headers', function (t) {
  const req = createReq(undefined, {
    'x-forwarded-for': '127.0.0.1, 10.0.0.1'
  })
  t.strictEqual(proxyaddr(req, '127.0.0.1'), undefined)
  t.end()
})

function createReq (socketAddr, headers) {
  return {
    socket: {
      remoteAddress: socketAddr
    },
    headers: headers || {}
  }
}

function all () { return true }
function none () { return false }
function trust10x (addr) { return /^10\./.test(addr) }
