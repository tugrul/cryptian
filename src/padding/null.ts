
import Padding from '../padding';



export default class Null extends Padding {
    pad (chunk: Buffer): Buffer {

        const padSize = this._blockSize - (chunk.length % this._blockSize);
    
        return Buffer.concat([chunk, Buffer.alloc(padSize, 0)]);
    }

    unpad(chunk: Buffer): Buffer {
        let length = chunk.length;

        while (length--) {

            const size = chunk.length - length;

            if ((chunk[length] === 0) && (size <= this._blockSize)) {
                continue;
            }

            return chunk.slice(0, length + 1);
        }

        return Buffer.alloc(0);
    }
}
