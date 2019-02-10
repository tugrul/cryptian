
const util = require('util');
const Padding = require('../padding.js');

util.inherits(Pkcs5, Padding);

function Pkcs5(blockSize) {

    if (blockSize !== 8) {
        throw new Error('PKCS5 allows only 8 bytes block size');
    }

    Padding.call(this, blockSize);
}

Pkcs5.prototype.pad = function (chunk) {

    const padSize = this._blockSize - (chunk.length % this._blockSize);

    return Buffer.concat([chunk, Buffer.alloc(padSize, padSize)]);
};

Pkcs5.prototype.unpad = function (chunk) {

    let length = chunk.length;

    while (length--) {

        let size = chunk.length - length;

        if ((chunk[length] === chunk[length - 1]) && (size < this._blockSize)) {
            continue;
        }

        if (chunk[length] === size) {
            return chunk.slice(0, length);
        }

        throw new Error('Invalid padding byte by padding size');
    }

};

module.exports = Pkcs5;
