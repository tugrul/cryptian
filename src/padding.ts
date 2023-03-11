

import { NotImplementedError } from "./error";

export default class Padding {

    _blockSize: number;

    constructor(blockSize: number) {
        this._blockSize = blockSize;
    }

    pad (chunk: Buffer) : Buffer {
        throw new NotImplementedError('pad function should be implemented');
    }

    unpad (chunk: Buffer) : Buffer {
        throw new NotImplementedError('unpad function should be implemented');
    }
}


