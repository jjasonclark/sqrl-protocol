# SQRL-Protocol

[![License][license-badge]][license-url]

A [SQRL authentication][sqrl] protocol handler package

## Installation

```bash
$ npm install sqrl-protocol
```

## Usage

```javascript
const sqrlProtocol = require('sqrl-protocol')({
  /* config */
});

// Start a login
const nut = await sqrlProtocol.createNut(req.connection.remoteAddress);
// Process a login
const sqrlResult = await sqrlProtocol.process(
  req.connection.remoteAddress,
  req.query.nut,
  req.body
);
// Finish a login
const user = await sqrlProtocol.useCode(
  req.connection.remoteAddress,
  req.query.code
);
```

## License

[MIT](https://github.com/jjasonclark/sqrl-protocol/LICENSE)

[license-badge]: https://img.shields.io/github/license/jjasonclark/sqrl-protocol.svg
[license-url]: https://opensource.org/licenses/MIT
[sqrl]: https://www.grc.com/sqrl/sqrl.htm
