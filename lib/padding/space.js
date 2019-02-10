"use strict";

var util = require('util');

var Padding = require('../padding.js');

util.inherits(Space, Padding);

function Space(blockSize) {
  Padding.call(this, blockSize);
}

Space.prototype.pad = function (chunk) {
  var padSize = this._blockSize - chunk.length % this._blockSize;
  return Buffer.concat([chunk, Buffer.alloc(padSize, 0x20)]);
};

Space.prototype.unpad = function (chunk) {
  var length = chunk.length;

  while (length--) {
    var size = chunk.length - length;

    if (chunk[length] === 0x20 && size <= this._blockSize) {
      continue;
    }

    return chunk.slice(0, length + 1);
  }
};

module.exports = Space;