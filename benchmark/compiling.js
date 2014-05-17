
/**
 * Globals for benchmark.js
 */
global.proxyaddr = require('..');
global.createReq = createReq;

/**
 * Module dependencies.
 */
var benchmark = require('benchmark');
var benchmarks = require('beautify-benchmark');

var suite = new benchmark.Suite;

suite.add({
  'name': 're-compiling',
  'minSamples': 100,
  'fn': 'proxyaddr(req, "loopback")',
  'setup': 'req = createReq("127.0.0.1", "10.0.0.1")'
});

suite.add({
  'name': 'pre-compiling',
  'minSamples': 100,
  'fn': 'proxyaddr(req, trust)',
  'setup': 'req = createReq("127.0.0.1", "10.0.0.1"); trust = proxyaddr.compile("loopback")'
});

suite.on('cycle', function onCycle(event) {
  benchmarks.add(event.target);
});

suite.on('complete', function onComplete() {
  benchmarks.log();
});

suite.run({'async': false});

function createReq(socketAddr, forwardedFor) {
  return {
    connection: {
      remoteAddress: socketAddr
    },
    headers: {
      'x-forwarded-for': (forwardedFor || '')
    }
  };
}
