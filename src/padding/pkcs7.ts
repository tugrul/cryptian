
import Pkcs5 from './pkcs5';

export default class Pkcs7 extends Pkcs5 {
    validateBlockSize(blockSize: number): void {
        if (blockSize > 255) {
            throw new Error('PKCS7 block size can be up to 255 bytes');
        }
    }
}

