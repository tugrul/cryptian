
const util = require('util');
const Padding = require('../padding.js');

util.inherits(AnsiX923, Padding);

function AnsiX923(blockSize) {
    Padding.call(this, blockSize);
}

AnsiX923.prototype.pad = function (chunk) {

    const padSize = this._blockSize - (chunk.length % this._blockSize);

    const padding = Buffer.alloc(padSize, 0);
    padding[padSize - 1] = padSize;

    return Buffer.concat([chunk, padding]);
};

AnsiX923.prototype.unpad = function (chunk) {

    const size = chunk[chunk.length - 1];

    if (size > this._blockSize) {
        throw new Error('Invalid block size or last byte not indicating the padding size');
    }

    const limit = chunk.length - size;
    const padding = chunk.slice(limit);

    for (let i = 0; i < size - 1; i++) {
        if (padding[i] !== 0) {
            throw new Error('Padding byte should be zero');
        }
    }

    return chunk.slice(0, limit);

};

module.exports = AnsiX923;
