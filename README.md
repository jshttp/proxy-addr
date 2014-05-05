# proxy-addr [![Build Status](https://travis-ci.org/expressjs/proxy-addr.svg?branch=master)](https://travis-ci.org/expressjs/proxy-addr) [![NPM version](https://badge.fury.io/js/proxy-addr.svg)](http://badge.fury.io/js/proxy-addr)

Determine address of proxied request

## Install

    npm install proxy-addr

## API

    var proxyaddr = require('proxy-addr');

### proxyaddr(req, trust)

Return the address of the request, using the given `trust` parameter.
The `trust` argument is a function that returns `true` if you trust
the address, `false` if you don't. The closest untrusted address is
returned.

### proxyaddr.all(req, trust)

Return all the addresses of the request. This array is ordered from
closest to furthest (i.e. `arr[0] === req.connection.remoteAddress`).

## License

[MIT](LICENSE)
