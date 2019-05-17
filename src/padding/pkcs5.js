
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

    const paddingByte = chunk[chunk.length - 1];

    if (paddingByte > this._blockSize) {
        throw new Error('Invalid padding byte by padding size');
    }
    
    for (let i = 1; i < paddingByte; i++) {
        
        if (chunk[chunk.length - i] !== paddingByte) {
            throw new Error('Padding byte array not same');
        }
        
    }
    
    return chunk.slice(0, chunk.length - paddingByte);

};

module.exports = Pkcs5;
