
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

        // The padding bytes themselves are random and cannot be verified, so
        // the trailing count is the only thing that can be checked. A zero
        // count would leave the chunk untouched while reporting success.
        if (size === 0) {
            throw new Error('Invalid block size or last byte not indicating the padding size');
        }

        if (size > this._blockSize) {
            throw new Error('Invalid block size or last byte not indicating the padding size');
        }

        if (size > chunk.length) {
            throw new Error('Invalid block size or last byte not indicating the padding size');
        }

        return chunk.slice(0, chunk.length - size);
    
    }
}

