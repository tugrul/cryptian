
import { Transform, TransformCallback, TransformOptions } from 'stream';

import type { AlgorithmStream } from '../algorithm/stream';

export class Stream extends Transform {

    _cipher: AlgorithmStream;

    constructor(options: TransformOptions|undefined, cipher: AlgorithmStream) {
        super(options);
        
        this._cipher = cipher;
        
    }

    _flush(callback: TransformCallback) {
    
        return callback(null, Buffer.alloc(0));
    
    }
}

export class StreamEncrypt extends Stream {
    _transform(data: Buffer, encoding: BufferEncoding, callback: TransformCallback) {
    
        try {
            return callback(null, this._cipher.encrypt(typeof data === 'string' ? Buffer.from(data, encoding) : data));
        } catch (err) {
            return callback(err as Error | null | undefined);
        }
        
    }
}

export class StreamDecrypt extends Stream {
    _transform(data: Buffer, encoding: BufferEncoding, callback: TransformCallback) {
    
        try {
            return callback(null, this._cipher.decrypt(typeof data === 'string' ? Buffer.from(data, encoding) : data));
        } catch (err) {
            return callback(err as Error | null | undefined);
        }
        
    }
}
