
import { Transform, TransformCallback, TransformOptions } from 'stream';

import type Padding from '../padding';
import type { Mode } from '../mode';

export class Block extends Transform {

    _cipher: Mode;
    _padder?: Padding
    _tail: Buffer;

    constructor(options: TransformOptions|undefined, cipher: Mode, padder?: Padding) {
    
        super(options);
    
        this._cipher = cipher;
        this._padder = padder; 
        this._tail = Buffer.alloc(0);

    }

    _transform(data: Buffer, encoding: BufferEncoding, callback: TransformCallback) {
    
        const blockSize = this._cipher.getBlockSize();
    
        if (typeof data === 'string') {
            data = Buffer.from(data, encoding);
        }

        data = Buffer.concat([this._tail, data]);
        
        const remain = blockSize + ((data.length % blockSize) || blockSize);    
        const align = data.length > remain ? data.length - remain : 0;
    
        this._tail = data.slice(align);
    
        try {
            return callback(null, this._cipher.transform(data.slice(0, align))); 
        } catch (err) {
            return callback(err as Error | null | undefined);
        }
    }

    
}

export class BlockEncrypt extends Block {

    _flush(callback: TransformCallback) {
        try {
            this._tail.length > 0 && this.push(this._cipher.transform(this._pad(this._tail)));
            return callback(null);
        } catch (err) {
            return callback(err as Error | null | undefined);
        }
    }

    _pad(tail: Buffer): Buffer {

        if (!this._cipher.isPaddingRequired()) {
            return tail;
        }

        if (!this._padder) {
            throw new Error('padding is required but padding algorithm is not provided');
        }

        return this._padder.pad(tail);
    }
}

export class BlockDecrypt extends Block {

    _flush(callback: TransformCallback) {
    
        const target = this._cipher.transform(this._tail);
        
        try {
            this._tail.length > 0 && this.push(this._unpad(target));
            return callback(null);
        } catch (err) {
            return callback(err as Error | null | undefined);
        }
    }

    _unpad(tail: Buffer): Buffer {

        if (!this._cipher.isPaddingRequired()) {
            return tail;
        }

        if (!this._padder) {
            throw new Error('padding is required but padding algorithm is not provided');
        }

        return this._padder.unpad(tail);
    }
}
