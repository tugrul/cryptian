
const crypto = require('crypto');
const util = require('util');
const Padding = require('../padding.js');

util.inherits(Iso10126, Padding);

function Iso10126(blockSize) {
    Padding.call(this, blockSize);
}

Iso10126.prototype.pad = function (chunk) {

    const padSize = this._blockSize - (chunk.length % this._blockSize);

    const padding = crypto.randomBytes(padSize);
    padding[padSize - 1] = padSize;

    return Buffer.concat([chunk, padding]);
};

Iso10126.prototype.unpad = function (chunk) {

    const size = chunk[chunk.length - 1];

    if (size > this._blockSize) {
        throw new Error('Invalid block size or last byte not indicating the padding size');
    }

    return chunk.slice(0, chunk.length - size);

};

module.exports = Iso10126;
