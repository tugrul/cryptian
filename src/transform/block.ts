
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

    calculateRemain(length: number, blockSize: number): number {
        return length % blockSize;
    }

    _transform(data: Buffer, encoding: BufferEncoding, callback: TransformCallback) {
    
        const blockSize = this._cipher.getBlockSize();
    
        if (typeof data === 'string') {
            data = Buffer.from(data, encoding);
        }

        data = Buffer.concat([this._tail, data]);
        
        if (data.length < blockSize) {
            // The chunk is smaller than the block size, and the algorithm can't handle this case. 
            // We should pass the current chunk to the next transformation operation to concatenate it 
            // and attempt processing in the next step.
            this._tail = data.subarray();
            return callback();
        }

        const remain = this.calculateRemain(data.length, blockSize);

        if (remain === 0) {
            // Perfectly fitting the data size to the block size eliminates the need to pass 
            // the remaining data to the next transformation.
            this._tail = Buffer.alloc(0);
        } else {
            this._tail = data.subarray(-remain);
            data = data.subarray(0, -remain);
        }
    
        try {
            return callback(null, this._cipher.transform(data)); 
        } catch (err) {
            return callback(err as Error | null | undefined);
        }
    }
}

export class BlockEncrypt extends Block {

    _flush(callback: TransformCallback) {
        try {
            this.push(this._cipher.transform(this._pad(this._tail)));
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

    calculateRemain(length: number, blockSize: number): number {
        // This is necessary because the stream data length is indefinite, 
        // and we must ensure that the stream finishes in time. 
        // We also need to process the last bytes of data separately to remove padding from the decrypted data.
        return (length % blockSize) || blockSize;
    }

    _flush(callback: TransformCallback) {

        if (this._tail.length === 0) {
            return callback(new Error('Finishing data cannot be empty'));
        }

        if ((this._tail.length % this._cipher.getBlockSize()) !== 0 
            && this._cipher.isPaddingRequired()) {
            return callback(new Error('Finishing data does not match the block size'));
        }

        const target = this._cipher.transform(this._tail);
        
        try {
            this.push(this._unpad(target));
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
