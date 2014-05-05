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
 * Determine address of proxied request.
 *
 * @param {Object} request
 * @param {Function} trust
 * @api public
 */

function proxyaddr(req, trust) {
  var addrs = alladdrs(req);
  var addr = addrs[0];

  if (typeof trust !== 'function') throw new TypeError('trust argument is required');

  for (var i = 0; i < addrs.length - 1; i++) {
    if (!trust(addrs[i])) break;
    addr = addrs[i + 1];
  }

  return addr;
}
