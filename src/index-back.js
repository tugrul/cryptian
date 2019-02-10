

const cryptian = module.exports = require('bindings')('cryptian');

const padding = cryptian.padding = {
    Null:  require('./padding/null.js'),
    Pkcs5: require('./padding/pkcs5.js'),
    Pkcs7: require('./padding/pkcs7.js'),
    Space:  require('./padding/space.js'),
    Iso7816: require('./padding/iso-7816.js'),
    Iso10126: require('./padding/iso-10126.js'),
    AnsiX923: require('./padding/ansi-x923.js')
};

const block = require('./transform/block.js');
const stream = require('./transform/stream.js');

const {prepareStream} = require('./stream.js');

cryptian.createEncryptStream = prepareStream(cryptian, stream.StreamEncrypt, block.BlockEncrypt);
cryptian.createDecryptStream = prepareStream(cryptian, stream.StreamDecrypt, block.BlockDecrypt);




