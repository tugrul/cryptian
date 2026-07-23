
import Padding from '../padding';

export default class Pkcs5 extends Padding {

    constructor(blockSize: number) {
        super(blockSize);

        this.validateBlockSize(blockSize);
    }

    validateBlockSize(blockSize: number): void {
        if (blockSize !== 8) {
            throw new Error('PKCS5 allows only 8 bytes block size');
        }
    }

    pad (chunk: Buffer): Buffer {

        const padSize = this._blockSize - (chunk.length % this._blockSize);
    
        return Buffer.concat([chunk, Buffer.alloc(padSize, padSize)]);
    }

    unpad (chunk: Buffer): Buffer {

        const paddingByte = chunk[chunk.length - 1];

        // A zero byte cannot describe a valid padding length. Without this
        // check the loop below never runs and the whole chunk is returned as
        // though the padding had been verified.
        if (paddingByte === 0) {
            throw new Error('Invalid padding byte by padding size');
        }

        if (paddingByte > this._blockSize) {
            throw new Error('Invalid padding byte by padding size');
        }

        if (paddingByte > chunk.length) {
            throw new Error('Invalid padding byte by padding size');
        }

        // The loop is inclusive because the padding spans paddingByte bytes.
        // Stopping one short left the deepest padding byte unverified.
        for (let i = 1; i <= paddingByte; i++) {

            if (chunk[chunk.length - i] !== paddingByte) {
                throw new Error('Padding byte array not same');
            }

        }

        return chunk.slice(0, chunk.length - paddingByte);
    
    }
}
