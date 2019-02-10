
const util = require('util');
const Padding = require('../padding.js');
const Pkcs5 = require('./pkcs5.js');

util.inherits(Pkcs7, Pkcs5);

function Pkcs7(blockSize) {

    if (blockSize > 255) {
        throw new Error('PKCS7 block size can be up to 255 bytes');
    }

    Padding.call(this, blockSize);
}

module.exports = Pkcs7;
