
var proxyaddr = require('..');
var should = require('should');

describe('proxyaddr(req)', function () {
  describe('arguments', function () {
    describe('req', function () {
      it('should be required', function () {
        proxyaddr.bind().should.throw(/req.*required/);
      });
    });
  });

  describe('with no headers', function () {
    it('should return socket address', function () {
      var req = createReq('127.0.0.1');
      proxyaddr(req).should.equal('127.0.0.1');
    });
  });

  describe('with x-forwarded-for header', function () {
    describe('single', function () {
      it('should return x-forwarded-for', function () {
        var req = createReq('127.0.0.1', {
          'x-forwarded-for': '10.0.0.1'
        });
        proxyaddr(req).should.equal('10.0.0.1');
      });
    });

    describe('multiple', function () {
      it('should return left-most', function () {
        var req = createReq('127.0.0.1', {
          'x-forwarded-for': '10.0.0.1, 10.0.0.2'
        });
        proxyaddr(req).should.equal('10.0.0.1');
      });
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
      proxyaddr.all(req).should.eql(['127.0.0.1']);
    });
  });

  describe('with x-forwarded-for header', function () {
    describe('single', function () {
      it('should include x-forwarded-for', function () {
        var req = createReq('127.0.0.1', {
          'x-forwarded-for': '10.0.0.1'
        });
        proxyaddr.all(req).should.eql(['127.0.0.1', '10.0.0.1']);
      });
    });

    describe('multiple', function () {
      it('should include x-forwarded-for', function () {
        var req = createReq('127.0.0.1', {
          'x-forwarded-for': '10.0.0.1, 10.0.0.2'
        });
        proxyaddr.all(req).should.eql(['127.0.0.1', '10.0.0.2', '10.0.0.1']);
      });
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
