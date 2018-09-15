
const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

describe('cast-256 transform nofb mode', () => {

    it('should be constructor', () => {
        assert(typeof algorithm.Blowfish === 'function', 'there is no constructor');
    });

    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '334daf0c9bda196dfa930c91e905035d6c93bf19d4ab10c7de' +
        'b1d76a6795001c2710859011c9e6f9a6cc86992bd55b5f4364', 'hex');

    const iv = Buffer.from('c1a404bcdab25ab78cfe2f52259c544b', 'hex');



    const ciphertext = Buffer.from(
        '03760d9f9944cfe7d7ddcefe4d157d8896df2b3c11c8982488' +
        '02cca4ccd555937c1731c6a8cd4d1233e7b797848e36cf051b', 'hex');

    it('should encrypt', () => {
    
        const cast256 = new algorithm.Cast256();
        cast256.setKey(key);

        const cipher = new mode.nofb.Cipher(cast256, iv);

        const transform = createEncryptStream(cipher);
        const buffer = transform.pipe(new streamBuffers.WritableStreamBuffer());

        buffer.on('finish', () => {
            assert(ciphertext.equals(buffer.getContents()), 'encrypted plaintext should be equal to ciphertext');
        });

        transform.write(plaintext.slice(0, 22));
        transform.write(plaintext.slice(22, 39));
        transform.end(plaintext.slice(39));
        
    });

    it('should decrypt', () => {

        const cast256 = new algorithm.Cast256();
        cast256.setKey(key);
        
        const decipher = new mode.nofb.Decipher(cast256, iv);

        const transform = createDecryptStream(decipher);
        const buffer = transform.pipe(new streamBuffers.WritableStreamBuffer());

        buffer.on('finish', () => {
            assert(plaintext.equals(buffer.getContents()), 'decrypted ciphertext should be equal to plaintext');
        });

        transform.write(ciphertext.slice(0, 27));
        transform.write(ciphertext.slice(27, 42));
        transform.end(ciphertext.slice(42));
        
    });

    

});

