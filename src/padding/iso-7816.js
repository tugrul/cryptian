
const crypto = require('crypto');
const util = require('util');
const Padding = require('../padding.js');

util.inherits(Iso7816, Padding);

function Iso7816(blockSize) {
    Padding.call(this, blockSize);
}

Iso7816.prototype.pad = function (chunk) {

    const padSize = this._blockSize - (chunk.length % this._blockSize);

    const padding = Buffer.alloc(padSize, 0);
    padding[0] = 0x80;

    return Buffer.concat([chunk, padding]);
};

Iso7816.prototype.unpad = function (chunk) {

    let length = chunk.length;

    while (length--) {

        let size = chunk.length - length;

        if (size > this._blockSize) {
            throw new Error('Padding size exceeded block size');
        }

        if (chunk[length] === 0x80) {
            return chunk.slice(0, length);
        }

        if (chunk[length] !== 0) {
            throw new Error('Padding byte is not null');
        }

    }

};

module.exports = Iso7816;
