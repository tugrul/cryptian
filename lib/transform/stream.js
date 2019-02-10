"use strict";

var _require = require('stream'),
    Transform = _require.Transform;

var util = require('util');

util.inherits(Stream, Transform);
util.inherits(StreamEncrypt, Stream);
util.inherits(StreamDecrypt, Stream);

function Stream(options, cipher) {
  if (!(this instanceof Stream)) {
    return new Stream(options, cipher);
  }

  Transform.call(this, options);
  this._cipher = cipher;
}

Stream.prototype._flush = function flush(callback) {
  return callback(null, Buffer.alloc(0));
};

function StreamEncrypt(options, cipher) {
  if (!(this instanceof StreamEncrypt)) {
    return new StreamEncrypt(options, cipher);
  }

  Stream.call(this, options, cipher);
}

StreamEncrypt.prototype._transform = function encryptTransform(data, encoding, callback) {
  try {
    return callback(null, this._cipher.encrypt(Buffer.from(data, encoding)));
  } catch (err) {
    return callback(err);
  }
};

function StreamDecrypt(options, cipher) {
  if (!(this instanceof StreamDecrypt)) {
    return new StreamDecrypt(options, cipher);
  }

  Stream.call(this, options, cipher);
}

StreamDecrypt.prototype._transform = function decryptTransform(data, encoding, callback) {
  try {
    return callback(null, this._cipher.decrypt(Buffer.from(data, encoding)));
  } catch (err) {
    return callback(err);
  }
};

exports.Stream = Stream;
exports.StreamEncrypt = StreamEncrypt;
exports.StreamDecrypt = StreamDecrypt;