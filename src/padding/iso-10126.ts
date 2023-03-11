
import {randomBytes} from 'crypto';

import Padding from '../padding';

export default class Iso10126 extends Padding {

    pad (chunk: Buffer): Buffer {

        const padSize = this._blockSize - (chunk.length % this._blockSize);
    
        const padding = randomBytes(padSize);
        padding[padSize - 1] = padSize;
    
        return Buffer.concat([chunk, padding]);
    }

    unpad (chunk: Buffer): Buffer {

        const size = chunk[chunk.length - 1];
    
        if (size > this._blockSize) {
            throw new Error('Invalid block size or last byte not indicating the padding size');
        }
    
        return chunk.slice(0, chunk.length - size);
    
    }
}

