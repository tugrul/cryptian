"use strict";

var util = require('util');

var Padding = require('../padding.js');

util.inherits(Null, Padding);

function Null(blockSize) {
  Padding.call(this, blockSize);
}

Null.prototype.pad = function (chunk) {
  var padSize = this._blockSize - chunk.length % this._blockSize;
  return Buffer.concat([chunk, Buffer.alloc(padSize, 0)]);
};

Null.prototype.unpad = function (chunk) {
  var length = chunk.length;

  while (length--) {
    var size = chunk.length - length;

    if (chunk[length] === 0 && size <= this._blockSize) {
      continue;
    }

    return chunk.slice(0, length + 1);
  }
};

module.exports = Null;