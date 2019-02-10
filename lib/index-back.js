"use strict";

var cryptian = module.exports = require('bindings')('cryptian');

var padding = cryptian.padding = {
  Null: require('./padding/null.js'),
  Pkcs5: require('./padding/pkcs5.js'),
  Pkcs7: require('./padding/pkcs7.js'),
  Space: require('./padding/space.js'),
  Iso7816: require('./padding/iso-7816.js'),
  Iso10126: require('./padding/iso-10126.js'),
  AnsiX923: require('./padding/ansi-x923.js')
};

var block = require('./transform/block.js');

var stream = require('./transform/stream.js');

var _require = require('./stream.js'),
    prepareStream = _require.prepareStream;

cryptian.createEncryptStream = prepareStream(cryptian, stream.StreamEncrypt, block.BlockEncrypt);
cryptian.createDecryptStream = prepareStream(cryptian, stream.StreamDecrypt, block.BlockDecrypt);