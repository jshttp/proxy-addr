/*!
 * proxy-addr
 * Copyright(c) 2014 Douglas Christopher Wilson
 * MIT Licensed
 */

/**
 * Module exports.
 */

module.exports = proxyaddr;
module.exports.all = proxyaddrs;

/**
 * Determine IP of proxied request.
 *
 * @param {Object} request
 * @api public
 */

function proxyaddr(req) {
  var addrs = proxyaddrs(req);

  return addrs[addrs.length - 1];
}

/**
 * Get all addresses in the request.
 *
 * @param {Object} request
 * @api public
 */

function proxyaddrs(req) {
  if (!req) throw new TypeError('req argument is required');

  var proxyAddrs = (req.headers['x-forwarded-for'] || '')
    .split(/ *, */)
    .filter(isTruthy)
    .reverse();
  var socketAddr = req.connection.remoteAddress;

  return [socketAddr].concat(proxyAddrs);
}

function isTruthy(val) {
  return Boolean(val);
}
