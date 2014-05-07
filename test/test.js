
var proxyaddr = require('..');
var should = require('should');

describe('proxyaddr(req, trust)', function () {
  describe('arguments', function () {
    describe('req', function () {
      it('should be required', function () {
        proxyaddr.bind().should.throw(/req.*required/);
      });
    });

    describe('trust', function () {
      it('should be required', function () {
        var req = createReq('127.0.0.1');
        proxyaddr.bind(null, req).should.throw(/trust.*required/);
      });

      it('should accept a function', function () {
        var req = createReq('127.0.0.1');
        proxyaddr.bind(null, req, all).should.not.throw();
      });

      it('should accept an array', function () {
        var req = createReq('127.0.0.1');
        proxyaddr.bind(null, req, []).should.not.throw();
      });

      it('should reject non-IP', function () {
        var req = createReq('127.0.0.1');
        proxyaddr.bind(null, req, ['blargh']).should.throw(/invalid IP address/);
      });

      it('should reject bad CIDR', function () {
        var req = createReq('127.0.0.1');
        proxyaddr.bind(null, req, ['10.0.0.1/6000']).should.throw(/invalid range on address/);
        proxyaddr.bind(null, req, ['::1/6000']).should.throw(/invalid range on address/);
        proxyaddr.bind(null, req, ['::ffff:a00:2/136']).should.throw(/invalid range on address/);
        proxyaddr.bind(null, req, ['::ffff:a00:2/46']).should.throw(/invalid range on address/);
      });
    });
  });

  describe('with all trusted', function () {
    it('should return socket address with no headers', function () {
      var req = createReq('127.0.0.1');
      proxyaddr(req, all).should.equal('127.0.0.1');
    });

    it('should return header value', function () {
      var req = createReq('127.0.0.1', {
        'x-forwarded-for': '10.0.0.1'
      });
      proxyaddr(req, all).should.equal('10.0.0.1');
    });

    it('should return furthest header value', function () {
      var req = createReq('127.0.0.1', {
        'x-forwarded-for': '10.0.0.1, 10.0.0.2'
      });
      proxyaddr(req, all).should.equal('10.0.0.1');
    });
  });

  describe('with none trusted', function () {
    it('should return socket address with no headers', function () {
      var req = createReq('127.0.0.1');
      proxyaddr(req, none).should.equal('127.0.0.1');
    });

    it('should return socket address with headers', function () {
      var req = createReq('127.0.0.1', {
        'x-forwarded-for': '10.0.0.1, 10.0.0.2'
      });
      proxyaddr(req, none).should.equal('127.0.0.1');
    });
  });

  describe('with some trusted', function () {
    it('should return socket address with no headers', function () {
      var req = createReq('127.0.0.1');
      proxyaddr(req, trust10x).should.equal('127.0.0.1');
    });

    it('should return socket address when not trusted', function () {
      var req = createReq('127.0.0.1', {
        'x-forwarded-for': '10.0.0.1, 10.0.0.2'
      });
      proxyaddr(req, trust10x).should.equal('127.0.0.1');
    });

    it('should return header when socket trusted', function () {
      var req = createReq('10.0.0.1', {
        'x-forwarded-for': '192.168.0.1'
      });
      proxyaddr(req, trust10x).should.equal('192.168.0.1');
    });

    it('should return first untrusted after trusted', function () {
      var req = createReq('10.0.0.1', {
        'x-forwarded-for': '192.168.0.1, 10.0.0.2'
      });
      proxyaddr(req, trust10x).should.equal('192.168.0.1');
    });

    it('should not skip untrusted', function () {
      var req = createReq('10.0.0.1', {
        'x-forwarded-for': '10.0.0.3, 192.168.0.1, 10.0.0.2'
      });
      proxyaddr(req, trust10x).should.equal('192.168.0.1');
    });
  });

  describe('when given array', function () {
    it('should accept literal IP addresses', function () {
      var req = createReq('10.0.0.1', {
        'x-forwarded-for': '192.168.0.1, 10.0.0.2'
      });
      proxyaddr(req, ['10.0.0.1', '10.0.0.2']).should.equal('192.168.0.1');
    });

    describe('when array empty', function () {
      it('should return socket address ', function () {
        var req = createReq('127.0.0.1');
        proxyaddr(req, []).should.equal('127.0.0.1');
      });

      it('should return socket address with headers', function () {
        var req = createReq('127.0.0.1', {
          'x-forwarded-for': '10.0.0.1, 10.0.0.2'
        });
        proxyaddr(req, []).should.equal('127.0.0.1');
      });
    });
  });

  describe('when given IPv4 addresses', function () {
    it('should accept literal IP addresses', function () {
      var req = createReq('10.0.0.1', {
        'x-forwarded-for': '192.168.0.1, 10.0.0.2'
      });
      proxyaddr(req, ['10.0.0.1', '10.0.0.2']).should.equal('192.168.0.1');
    });

    it('should accept CIDR notation', function () {
      var req = createReq('10.0.0.1', {
        'x-forwarded-for': '192.168.0.1, 10.0.0.200'
      });
      proxyaddr(req, ['10.0.0.2/26']).should.equal('10.0.0.200');
    });

    it('should accept netmask notation', function () {
      var req = createReq('10.0.0.1', {
        'x-forwarded-for': '192.168.0.1, 10.0.0.200'
      });
      proxyaddr(req, ['10.0.0.2/255.255.255.192']).should.equal('10.0.0.200');
    });
  });

  describe('when given IPv6 addresses', function () {
    it('should accept literal IP addresses', function () {
      var req = createReq('fe80::1', {
        'x-forwarded-for': '2002:c000:203::1, fe80::2'
      });
      proxyaddr(req, ['fe80::1', 'fe80::2']).should.equal('2002:c000:203::1');
    });

    it('should accept CIDR notation', function () {
      var req = createReq('fe80::1', {
        'x-forwarded-for': '2002:c000:203::1, fe80::ff00'
      });
      proxyaddr(req, ['fe80::/125']).should.equal('fe80::ff00');
    });

    it('should accept netmask notation', function () {
      var req = createReq('fe80::1', {
        'x-forwarded-for': '2002:c000:203::1, fe80::ff00'
      });
      proxyaddr(req, ['fe80::/ffff:ffff:ffff:ffff:ffff:ffff:ffff:fff8']).should.equal('fe80::ff00');
    });
  });

  describe('when IP versions mixed', function () {
    it('should match respective versions', function () {
      var req = createReq('::1', {
        'x-forwarded-for': '2002:c000:203::1'
      });
      proxyaddr(req, ['127.0.0.1', '::1']).should.equal('2002:c000:203::1');
    });
  });

  describe('when IPv4-mapped IPv6 addresses', function () {
    it('should match IPv4 trust to IPv6 request', function () {
      var req = createReq('::ffff:a00:1', {
        'x-forwarded-for': '192.168.0.1, 10.0.0.2'
      });
      proxyaddr(req, ['10.0.0.1', '10.0.0.2']).should.equal('192.168.0.1');
    });

    it('should match IPv6 trust to IPv4 request', function () {
      var req = createReq('10.0.0.1', {
        'x-forwarded-for': '192.168.0.1, 10.0.0.2'
      });
      proxyaddr(req, ['::ffff:a00:1', '::ffff:a00:2']).should.equal('192.168.0.1');
    });

    it('should match CIDR notation for IPv4-mapped address', function () {
      var req = createReq('10.0.0.1', {
        'x-forwarded-for': '192.168.0.1, 10.0.0.200'
      });
      proxyaddr(req, ['::ffff:a00:2/122']).should.equal('10.0.0.200');
    });

    it('should match subnet notation for IPv4-mapped address', function () {
      var req = createReq('10.0.0.1', {
        'x-forwarded-for': '192.168.0.1, 10.0.0.200'
      });
      proxyaddr(req, ['::ffff:a00:2/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffc0']).should.equal('10.0.0.200');
    });
  });
});

describe('proxyaddr.all(req)', function () {
  describe('arguments', function () {
    describe('req', function () {
      it('should be required', function () {
        proxyaddr.all.bind().should.throw(/req.*required/);
      });
    });
  });

  describe('with no headers', function () {
    it('should return socket address', function () {
      var req = createReq('127.0.0.1');
      proxyaddr.all(req, all).should.eql(['127.0.0.1']);
    });
  });

  describe('with x-forwarded-for header', function () {
    it('should include x-forwarded-for', function () {
      var req = createReq('127.0.0.1', {
        'x-forwarded-for': '10.0.0.1'
      });
      proxyaddr.all(req, all).should.eql(['127.0.0.1', '10.0.0.1']);
    });

    it('should include x-forwarded-for in correct order', function () {
      var req = createReq('127.0.0.1', {
        'x-forwarded-for': '10.0.0.1, 10.0.0.2'
      });
      proxyaddr.all(req, all).should.eql(['127.0.0.1', '10.0.0.2', '10.0.0.1']);
    });
  });
});

function createReq(socketAddr, headers) {
  return {
    connection: {
      remoteAddress: socketAddr
    },
    headers: headers || {}
  };
}

function all() { return true; }
function none() { return false; }
function trust10x(addr) { return /^10\./.test(addr); }
