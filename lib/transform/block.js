
const { Transform } = require('stream');
const util = require('util');

util.inherits(Block, Transform);
util.inherits(BlockEncrypt, Block);
util.inherits(BlockDecrypt, Block);

function Block(options, cipher, padder) {

    if (!(this instanceof Block)) {
        return new Block(options, cipher, padder);
    }

    Transform.call(this, options);  

    this._cipher = cipher;
    this._padder = padder; 
    this._tail = Buffer.alloc(0);
}

Block.prototype._transform = function transform(data, encoding, callback) {
    
    const blockSize = this._cipher.getBlockSize();

    data = Buffer.concat([this._tail, Buffer.from(data, encoding)]);
    
    const remain = blockSize + ((data.length % blockSize) || blockSize);    
    const align = data.length > remain ? data.length - remain : 0;

    this._tail = data.slice(align);

    try {
        return callback(null, this._cipher.transform(data.slice(0, align))); 
    } catch (err) {
        return callback(err);
    }
};


function BlockEncrypt(options, cipher, padder) {

    if (!(this instanceof BlockEncrypt)) {
        return new BlockEncrypt(options, cipher, padder);
    }
    
    Block.call(this, options, cipher, padder);
}


BlockEncrypt.prototype._flush = function encryptFlush(callback) {
    
    try {
        return callback(null, this._cipher.transform(this._cipher.isPaddingRequired() ? 
            this._padder.pad(this._tail) : this._tail));
    } catch (err) {
        return callback(err);
    }
};


function BlockDecrypt(options, cipher, padder) {

    if (!(this instanceof BlockDecrypt)) {
        return new BlockDecrypt(options, cipher, padder);
    }
    
    Block.call(this, options, cipher, padder);
}


BlockDecrypt.prototype._flush = function decryptFlush(callback) {
    
    const target = this._cipher.transform(this._tail);
    
    try {
        return callback(null, this._cipher.isPaddingRequired() ? 
            this._padder.unpad(target) : target);
    } catch (err) {
        return callback(err);
    }
};


exports.Block = Block;
exports.BlockEncrypt = BlockEncrypt;
exports.BlockDecrypt = BlockDecrypt;


