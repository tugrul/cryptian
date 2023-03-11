
import Padding from "../padding";

export default class Iso7816 extends Padding {

    pad (chunk: Buffer): Buffer {

        const padSize = this._blockSize - (chunk.length % this._blockSize);
    
        const padding = Buffer.alloc(padSize, 0);
        padding[0] = 0x80;
    
        return Buffer.concat([chunk, padding]);
    }

    unpad (chunk: Buffer): Buffer {

        let length = chunk.length;
    
        while (length--) {
    
            const size = chunk.length - length;
    
            if (size > this._blockSize) {
                throw new Error('Padding size exceeded block size');
            }
    
            if (chunk[length] === 0x80) {
                return chunk.slice(0, length);
            }
    
            if (chunk[length] !== 0) {
                throw new Error('Padding byte is not null');
            }
    
        }
    
        return Buffer.alloc(0);
    }
}

