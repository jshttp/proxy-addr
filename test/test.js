
var assert = require('assert')
var proxyaddr = require('..')

describe('proxyaddr(req, trust)', function () {
  describe('arguments', function () {
    describe('req', function () {
      it('should be required', function () {
        assert.throws(proxyaddr, /req.*required/)
      })
    })

    describe('trust', function () {
      it('should be required', function () {
        var req = createReq('127.0.0.1')
        assert.throws(proxyaddr.bind(null, req), /trust.*required/)
      })

      it('should accept a function', function () {
        var req = createReq('127.0.0.1')
        assert.doesNotThrow(proxyaddr.bind(null, req, all))
      })

      it('should accept an array', function () {
        var req = createReq('127.0.0.1')
        assert.doesNotThrow(proxyaddr.bind(null, req, []))
      })

      it('should accept a string', function () {
        var req = createReq('127.0.0.1')
        assert.doesNotThrow(proxyaddr.bind(null, req, '127.0.0.1'))
      })

      it('should reject a number', function () {
        var req = createReq('127.0.0.1')
        assert.throws(proxyaddr.bind(null, req, 42), /unsupported trust argument/)
      })

      it('should accept IPv4', function () {
        var req = createReq('127.0.0.1')
        assert.doesNotThrow(proxyaddr.bind(null, req, '127.0.0.1'))
      })

      it('should accept IPv6', function () {
        var req = createReq('127.0.0.1')
        assert.doesNotThrow(proxyaddr.bind(null, req, '::1'))
      })

      it('should accept IPv4-style IPv6', function () {
        var req = createReq('127.0.0.1')
        assert.doesNotThrow(proxyaddr.bind(null, req, '::ffff:127.0.0.1'))
      })

      it('should accept pre-defined names', function () {
        var req = createReq('127.0.0.1')
        assert.doesNotThrow(proxyaddr.bind(null, req, 'loopback'))
      })

      it('should accept pre-defined names in array', function () {
        var req = createReq('127.0.0.1')
        assert.doesNotThrow(proxyaddr.bind(null, req, ['loopback', '10.0.0.1']))
      })

      it('should not alter input array', function () {
        var arr = ['loopback', '10.0.0.1']
        var req = createReq('127.0.0.1')
        assert.doesNotThrow(proxyaddr.bind(null, req, arr))
        assert.deepEqual(arr, ['loopback', '10.0.0.1'])
      })

      it('should reject non-IP', function () {
        var req = createReq('127.0.0.1')
        assert.throws(proxyaddr.bind(null, req, 'blargh'), /invalid IP address/)
        assert.throws(proxyaddr.bind(null, req, '10.0.300.1'), /invalid IP address/)
        assert.throws(proxyaddr.bind(null, req, '::ffff:30.168.1.9000'), /invalid IP address/)
        assert.throws(proxyaddr.bind(null, req, '-1'), /invalid IP address/)
      })

      it('should reject bad CIDR', function () {
        var req = createReq('127.0.0.1')
        assert.throws(proxyaddr.bind(null, req, '10.0.0.1/internet'), /invalid range on address/)
        assert.throws(proxyaddr.bind(null, req, '10.0.0.1/6000'), /invalid range on address/)
        assert.throws(proxyaddr.bind(null, req, '::1/6000'), /invalid range on address/)
        assert.throws(proxyaddr.bind(null, req, '::ffff:a00:2/136'), /invalid range on address/)
        assert.throws(proxyaddr.bind(null, req, '::ffff:a00:2/-1'), /invalid range on address/)
      })

      it('should reject bad netmask', function () {
        var req = createReq('127.0.0.1')
        assert.throws(proxyaddr.bind(null, req, '10.0.0.1/255.0.255.0'), /invalid range on address/)
        assert.throws(proxyaddr.bind(null, req, '10.0.0.1/ffc0::'), /invalid range on address/)
        assert.throws(proxyaddr.bind(null, req, 'fe80::/ffc0::'), /invalid range on address/)
        assert.throws(proxyaddr.bind(null, req, 'fe80::/255.255.255.0'), /invalid range on address/)
        assert.throws(proxyaddr.bind(null, req, '::ffff:a00:2/255.255.255.0'), /invalid range on address/)
      })

      it('should be invoked as trust(addr, i)', function () {
        var log = []
        var req = createReq('127.0.0.1', {
          'x-forwarded-for': '192.168.0.1, 10.0.0.1'
        })

        proxyaddr(req, function (addr, i) {
          return log.push(Array.prototype.slice.call(arguments))
        })

        assert.deepEqual(log, [
          ['127.0.0.1', 0],
          ['10.0.0.1', 1]
        ])
      })
    })
  })

  describe('with all trusted', function () {
    it('should return socket address with no headers', function () {
      var req = createReq('127.0.0.1')
      assert.strictEqual(proxyaddr(req, all), '127.0.0.1')
    })

    it('should return header value', function () {
      var req = createReq('127.0.0.1', {
        'x-forwarded-for': '10.0.0.1'
      })
      assert.strictEqual(proxyaddr(req, all), '10.0.0.1')
    })

    it('should return furthest header value', function () {
      var req = createReq('127.0.0.1', {
        'x-forwarded-for': '10.0.0.1, 10.0.0.2'
      })
      assert.strictEqual(proxyaddr(req, all), '10.0.0.1')
    })
  })

  describe('with none trusted', function () {
    it('should return socket address with no headers', function () {
      var req = createReq('127.0.0.1')
      assert.strictEqual(proxyaddr(req, none), '127.0.0.1')
    })

    it('should return socket address with headers', function () {
      var req = createReq('127.0.0.1', {
        'x-forwarded-for': '10.0.0.1, 10.0.0.2'
      })
      assert.strictEqual(proxyaddr(req, none), '127.0.0.1')
    })
  })

  describe('with some trusted', function () {
    it('should return socket address with no headers', function () {
      var req = createReq('127.0.0.1')
      assert.strictEqual(proxyaddr(req, trust10x), '127.0.0.1')
    })

    it('should return socket address when not trusted', function () {
      var req = createReq('127.0.0.1', {
        'x-forwarded-for': '10.0.0.1, 10.0.0.2'
      })
      assert.strictEqual(proxyaddr(req, trust10x), '127.0.0.1')
    })

    it('should return header when socket trusted', function () {
      var req = createReq('10.0.0.1', {
        'x-forwarded-for': '192.168.0.1'
      })
      assert.strictEqual(proxyaddr(req, trust10x), '192.168.0.1')
    })

    it('should return first untrusted after trusted', function () {
      var req = createReq('10.0.0.1', {
        'x-forwarded-for': '192.168.0.1, 10.0.0.2'
      })
      assert.strictEqual(proxyaddr(req, trust10x), '192.168.0.1')
    })

    it('should not skip untrusted', function () {
      var req = createReq('10.0.0.1', {
        'x-forwarded-for': '10.0.0.3, 192.168.0.1, 10.0.0.2'
      })
      assert.strictEqual(proxyaddr(req, trust10x), '192.168.0.1')
    })
  })

  describe('when given array', function () {
    it('should accept literal IP addresses', function () {
      var req = createReq('10.0.0.1', {
        'x-forwarded-for': '192.168.0.1, 10.0.0.2'
      })
      assert.strictEqual(proxyaddr(req, ['10.0.0.1', '10.0.0.2']), '192.168.0.1')
    })

    it('should not trust non-IP addresses', function () {
      var req = createReq('10.0.0.1', {
        'x-forwarded-for': '192.168.0.1, 10.0.0.2, localhost'
      })
      assert.strictEqual(proxyaddr(req, ['10.0.0.1', '10.0.0.2']), 'localhost')
    })

    it('should return socket address if none match', function () {
      var req = createReq('10.0.0.1', {
        'x-forwarded-for': '192.168.0.1, 10.0.0.2'
      })
      assert.strictEqual(proxyaddr(req, ['127.0.0.1', '192.168.0.100']), '10.0.0.1')
    })

    describe('when array empty', function () {
      it('should return socket address ', function () {
        var req = createReq('127.0.0.1')
        assert.strictEqual(proxyaddr(req, []), '127.0.0.1')
      })

      it('should return socket address with headers', function () {
        var req = createReq('127.0.0.1', {
          'x-forwarded-for': '10.0.0.1, 10.0.0.2'
        })
        assert.strictEqual(proxyaddr(req, []), '127.0.0.1')
      })
    })
  })

  describe('when given IPv4 addresses', function () {
    it('should accept literal IP addresses', function () {
      var req = createReq('10.0.0.1', {
        'x-forwarded-for': '192.168.0.1, 10.0.0.2'
      })
      assert.strictEqual(proxyaddr(req, ['10.0.0.1', '10.0.0.2']), '192.168.0.1')
    })

    it('should accept CIDR notation', function () {
      var req = createReq('10.0.0.1', {
        'x-forwarded-for': '192.168.0.1, 10.0.0.200'
      })
      assert.strictEqual(proxyaddr(req, '10.0.0.2/26'), '10.0.0.200')
    })

    it('should accept netmask notation', function () {
      var req = createReq('10.0.0.1', {
        'x-forwarded-for': '192.168.0.1, 10.0.0.200'
      })
      assert.strictEqual(proxyaddr(req, '10.0.0.2/255.255.255.192'), '10.0.0.200')
    })
  })

  describe('when given IPv6 addresses', function () {
    it('should accept literal IP addresses', function () {
      var req = createReq('fe80::1', {
        'x-forwarded-for': '2002:c000:203::1, fe80::2'
      })
      assert.strictEqual(proxyaddr(req, ['fe80::1', 'fe80::2']), '2002:c000:203::1')
    })

    it('should accept CIDR notation', function () {
      var req = createReq('fe80::1', {
        'x-forwarded-for': '2002:c000:203::1, fe80::ff00'
      })
      assert.strictEqual(proxyaddr(req, 'fe80::/125'), 'fe80::ff00')
    })
  })

  describe('when IP versions mixed', function () {
    it('should match respective versions', function () {
      var req = createReq('::1', {
        'x-forwarded-for': '2002:c000:203::1'
      })
      assert.strictEqual(proxyaddr(req, ['127.0.0.1', '::1']), '2002:c000:203::1')
    })

    it('should not match IPv4 to IPv6', function () {
      var req = createReq('::1', {
        'x-forwarded-for': '2002:c000:203::1'
      })
      assert.strictEqual(proxyaddr(req, '127.0.0.1'), '::1')
    })
  })

  describe('when IPv4-mapped IPv6 addresses', function () {
    it('should match IPv4 trust to IPv6 request', function () {
      var req = createReq('::ffff:a00:1', {
        'x-forwarded-for': '192.168.0.1, 10.0.0.2'
      })
      assert.strictEqual(proxyaddr(req, ['10.0.0.1', '10.0.0.2']), '192.168.0.1')
    })

    it('should match IPv4 netmask trust to IPv6 request', function () {
      var req = createReq('::ffff:a00:1', {
        'x-forwarded-for': '192.168.0.1, 10.0.0.2'
      })
      assert.strictEqual(proxyaddr(req, ['10.0.0.1/16']), '192.168.0.1')
    })

    it('should match IPv6 trust to IPv4 request', function () {
      var req = createReq('10.0.0.1', {
        'x-forwarded-for': '192.168.0.1, 10.0.0.2'
      })
      assert.strictEqual(proxyaddr(req, ['::ffff:a00:1', '::ffff:a00:2']), '192.168.0.1')
    })

    it('should match CIDR notation for IPv4-mapped address', function () {
      var req = createReq('10.0.0.1', {
        'x-forwarded-for': '192.168.0.1, 10.0.0.200'
      })
      assert.strictEqual(proxyaddr(req, '::ffff:a00:2/122'), '10.0.0.200')
    })

    it('should match CIDR notation for IPv4-mapped address mixed with IPv6 CIDR', function () {
      var req = createReq('10.0.0.1', {
        'x-forwarded-for': '192.168.0.1, 10.0.0.200'
      })
      assert.strictEqual(proxyaddr(req, ['::ffff:a00:2/122', 'fe80::/125']), '10.0.0.200')
    })

    it('should match CIDR notation for IPv4-mapped address mixed with IPv4 addresses', function () {
      var req = createReq('10.0.0.1', {
        'x-forwarded-for': '192.168.0.1, 10.0.0.200'
      })
      assert.strictEqual(proxyaddr(req, ['::ffff:a00:2/122', '127.0.0.1']), '10.0.0.200')
    })
  })

  describe('when given pre-defined names', function () {
    it('should accept single pre-defined name', function () {
      var req = createReq('fe80::1', {
        'x-forwarded-for': '2002:c000:203::1, fe80::2'
      })
      assert.strictEqual(proxyaddr(req, 'linklocal'), '2002:c000:203::1')
    })

    it('should accept multiple pre-defined names', function () {
      var req = createReq('::1', {
        'x-forwarded-for': '2002:c000:203::1, fe80::2'
      })
      assert.strictEqual(proxyaddr(req, ['loopback', 'linklocal']), '2002:c000:203::1')
    })
  })

  describe('when header contains non-ip addresses', function () {
    it('should stop at first non-ip after trusted', function () {
      var req = createReq('127.0.0.1', {
        'x-forwarded-for': 'myrouter, 127.0.0.1, proxy'
      })
      assert.strictEqual(proxyaddr(req, '127.0.0.1'), 'proxy')
    })

    it('should stop at first malformed ip after trusted', function () {
      var req = createReq('127.0.0.1', {
        'x-forwarded-for': 'myrouter, 127.0.0.1, ::8:8:8:8:8:8:8:8:8'
      })
      assert.strictEqual(proxyaddr(req, '127.0.0.1'), '::8:8:8:8:8:8:8:8:8')
    })

    it('should provide all values to function', function () {
      var log = []
      var req = createReq('127.0.0.1', {
        'x-forwarded-for': 'myrouter, 127.0.0.1, proxy'
      })

      proxyaddr(req, function (addr, i) {
        return log.push(Array.prototype.slice.call(arguments))
      })

      assert.deepEqual(log, [
        ['127.0.0.1', 0],
        ['proxy', 1],
        ['127.0.0.1', 2]
      ])
    })
  })

  describe('when socket address undefined', function () {
    it('should return undefined as address', function () {
      var req = createReq(undefined)
      assert.strictEqual(proxyaddr(req, '127.0.0.1'), undefined)
    })

    it('should return undefined even with trusted headers', function () {
      var req = createReq(undefined, {
        'x-forwarded-for': '127.0.0.1, 10.0.0.1'
      })
      assert.strictEqual(proxyaddr(req, '127.0.0.1'), undefined)
    })
  })
})

describe('proxyaddr.all(req, [trust])', function () {
  describe('arguments', function () {
    describe('req', function () {
      it('should be required', function () {
        assert.throws(proxyaddr.all, /req.*required/)
      })
    })

    describe('trust', function () {
      it('should be optional', function () {
        var req = createReq('127.0.0.1')
        assert.doesNotThrow(proxyaddr.all.bind(null, req))
      })
    })
  })

  describe('with no headers', function () {
    it('should return socket address', function () {
      var req = createReq('127.0.0.1')
      assert.deepEqual(proxyaddr.all(req), ['127.0.0.1'])
    })
  })

  describe('with x-forwarded-for header', function () {
    it('should include x-forwarded-for', function () {
      var req = createReq('127.0.0.1', {
        'x-forwarded-for': '10.0.0.1'
      })
      assert.deepEqual(proxyaddr.all(req), ['127.0.0.1', '10.0.0.1'])
    })

    it('should include x-forwarded-for in correct order', function () {
      var req = createReq('127.0.0.1', {
        'x-forwarded-for': '10.0.0.1, 10.0.0.2'
      })
      assert.deepEqual(proxyaddr.all(req), ['127.0.0.1', '10.0.0.2', '10.0.0.1'])
    })
  })

  describe('with trust argument', function () {
    it('should stop at first untrusted', function () {
      var req = createReq('127.0.0.1', {
        'x-forwarded-for': '10.0.0.1, 10.0.0.2'
      })
      assert.deepEqual(proxyaddr.all(req, '127.0.0.1'), ['127.0.0.1', '10.0.0.2'])
    })

    it('should be only socket address for no trust', function () {
      var req = createReq('127.0.0.1', {
        'x-forwarded-for': '10.0.0.1, 10.0.0.2'
      })
      assert.deepEqual(proxyaddr.all(req, []), ['127.0.0.1'])
    })
  })
})

describe('proxyaddr.compile(trust)', function () {
  describe('arguments', function () {
    describe('trust', function () {
      it('should be required', function () {
        assert.throws(proxyaddr.compile, /argument.*required/)
      })

      it('should accept an array', function () {
        assert.strictEqual(typeof proxyaddr.compile([]), 'function')
      })

      it('should accept a string', function () {
        assert.strictEqual(typeof proxyaddr.compile('127.0.0.1'), 'function')
      })

      it('should reject a number', function () {
        assert.throws(proxyaddr.compile.bind(null, 42), /unsupported trust argument/)
      })

      it('should accept IPv4', function () {
        assert.strictEqual(typeof proxyaddr.compile('127.0.0.1'), 'function')
      })

      it('should accept IPv6', function () {
        assert.strictEqual(typeof proxyaddr.compile('::1'), 'function')
      })

      it('should accept IPv4-style IPv6', function () {
        assert.strictEqual(typeof proxyaddr.compile('::ffff:127.0.0.1'), 'function')
      })

      it('should accept pre-defined names', function () {
        assert.strictEqual(typeof proxyaddr.compile('loopback'), 'function')
      })

      it('should accept pre-defined names in array', function () {
        assert.strictEqual(typeof proxyaddr.compile(['loopback', '10.0.0.1']), 'function')
      })

      it('should reject non-IP', function () {
        assert.throws(proxyaddr.compile.bind(null, 'blargh'), /invalid IP address/)
        assert.throws(proxyaddr.compile.bind(null, '-1'), /invalid IP address/)
      })

      it('should reject bad CIDR', function () {
        assert.throws(proxyaddr.compile.bind(null, '10.0.0.1/6000'), /invalid range on address/)
        assert.throws(proxyaddr.compile.bind(null, '::1/6000'), /invalid range on address/)
        assert.throws(proxyaddr.compile.bind(null, '::ffff:a00:2/136'), /invalid range on address/)
        assert.throws(proxyaddr.compile.bind(null, '::ffff:a00:2/-46'), /invalid range on address/)
      })

      it('should not alter input array', function () {
        var arr = ['loopback', '10.0.0.1']
        assert.strictEqual(typeof proxyaddr.compile(arr), 'function')
        assert.deepEqual(arr, ['loopback', '10.0.0.1'])
      })
    })
  })
})

function createReq (socketAddr, headers) {
  return {
    connection: {
      remoteAddress: socketAddr
    },
    headers: headers || {}
  }
}

function all () { return true }
function none () { return false }
function trust10x (addr) { return /^10\./.test(addr) }
