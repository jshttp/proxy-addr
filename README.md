# proxy-addr [![Build Status](https://travis-ci.org/expressjs/proxy-addr.svg?branch=master)](https://travis-ci.org/expressjs/proxy-addr) [![NPM version](https://badge.fury.io/js/proxy-addr.svg)](http://badge.fury.io/js/proxy-addr)

Determine address of proxied request

## Install

    npm install proxy-addr

## API

    var proxyaddr = require('proxy-addr');

### proxyaddr(req)

Return the address of the request. This returns the furthest-away
address.

### proxyaddr.all(req)

Return all the addresses of the request. This array is ordered from
closest to furthest (i.e. `arr[0] === req.connection.remoteAddress`).

## License

[MIT](LICENSE)
