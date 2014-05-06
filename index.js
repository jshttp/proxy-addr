/*!
 * proxy-addr
 * Copyright(c) 2014 Douglas Christopher Wilson
 * MIT Licensed
 */

/**
 * Module exports.
 */

module.exports = proxyaddr;
module.exports.all = alladdrs;

/**
 * Module dependencies.
 */

var ipaddr = require('ipaddr.js');

/**
 * Variables.
 */

var digitre = /^[0-9]+$/;
var isip = ipaddr.isValid;
var parseip = ipaddr.parse;

/**
 * Get all addresses in the request.
 *
 * @param {Object} request
 * @api public
 */

function alladdrs(req) {
  if (!req) throw new TypeError('req argument is required');

  var proxyAddrs = (req.headers['x-forwarded-for'] || '')
    .split(/ *, */)
    .filter(Boolean)
    .reverse();
  var socketAddr = req.connection.remoteAddress;

  return [socketAddr].concat(proxyAddrs);
}

/**
 * Compile argument into trust function.
 *
 * @param {Array} arg
 * @api private
 */

function compile(arg) {
  if (!Array.isArray(arg)) {
    throw new TypeError('unsupported trust argument');
  }

  return compileTrust(compileRangeSubnets(arg));
}

/**
 * Compile `arr` elements into range subnets.
 *
 * @param {Array} arr
 * @api private
 */

function compileRangeSubnets(arr) {
  var rangeSubnets = new Array(arr.length);

  for (var i = 0; i < arr.length; i++) {
    rangeSubnets[i] = parseipNotation(arr[i]);
  }

  return rangeSubnets;
}

/**
 * Compile range subnet array into trust function.
 *
 * @param {Array} rangeSubnets
 * @api private
 */

function compileTrust(rangeSubnets) {
  return function trust(addr) {
    if (!isip(addr)) return false;

    var ip = parseip(addr);
    var subnet;

    for (var i = 0; i < rangeSubnets.length; i++) {
      subnet = rangeSubnets[i];
      if (ip.match.apply(ip, subnet)) return true;
    }

    return false;
  };
}

/**
 * Parse IP notation string into range subnet.
 *
 * @param {String} note
 * @api private
 */

function parseipNotation(note) {
  var ip;
  var kind;
  var max;
  var pos = note.lastIndexOf('/');
  var range;

  ip = pos !== -1
    ? note.substring(0, pos)
    : note;

  if (!isip(ip)) {
    throw new TypeError('invalid IP address: ' + ip);
  }

  ip = parseip(ip);

  kind = ip.kind();
  max = kind === 'ipv4' ? 32
    : kind === 'ipv6' ? 128
    : 0;

  range = pos !== -1
    ? note.substring(pos + 1, note.length)
    : max;

  if (typeof range !== 'number') {
    range = digitre.test(range)
      ? parseInt(range, 10)
      : 0;
  }

  if (range <= 0 || range > max) {
    throw new TypeError('invalid range on address: ' + note);
  }

  return [ip, range];
}

/**
 * Determine address of proxied request.
 *
 * @param {Object} request
 * @param {Function|Array} trust
 * @api public
 */

function proxyaddr(req, trust) {
  var addrs = alladdrs(req);
  var addr = addrs[0];

  if (!trust) {
    throw new TypeError('trust argument is required');
  }

  if (typeof trust !== 'function') {
    trust = compile(trust);
  }

  for (var i = 0; i < addrs.length - 1; i++) {
    if (!trust(addrs[i])) break;
    addr = addrs[i + 1];
  }

  return addr;
}
