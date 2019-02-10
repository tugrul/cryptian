"use strict";

var _require = require('./error.js'),
    NotImplementedError = _require.NotImplementedError;

function Padding(blockSize) {
  this._blockSize = blockSize;
}

Padding.prototype.pad = function (chunk) {
  throw new NotImplementedError('pad function should be implemented');
};

Padding.prototype.unpad = function (chunk) {
  throw new NotImplementedError('unpad function should be implemented');
};

module.exports = Padding;