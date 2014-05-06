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

    proxyaddr(req, function(addr){ return addr === '127.0.0.1' })

The `trust` argument may also be an array of trusted addresses, as
plain IP addresses, CIDR-formatted strings, or IP/netmask strings.

    proxyaddr(req, ['127.0.0.1'])
    proxyaddr(req, ['127.0.0.0/8', '10.0.0.0/8'])
    proxyaddr(req, ['127.0.0.0/255.0.0.0', '192.168.0.0/255.255.0.0'])

### proxyaddr.all(req, trust)

Return all the addresses of the request. This array is ordered from
closest to furthest (i.e. `arr[0] === req.connection.remoteAddress`).

## License

[MIT](LICENSE)
