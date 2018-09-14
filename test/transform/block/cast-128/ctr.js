
const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

describe('blowfish transform ctr mode', () => {

    it('should be constructor', () => {
        assert(typeof algorithm.Blowfish === 'function', 'there is no constructor');
    });

    const key = Buffer.alloc(16, 0);

    for (let i = 0; i < 16; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '9907d61dcfc9456b237d002ce859b5a1d7bc92747b9cc9d76e' +
        '968442060fa16c9a2f3dd1d2205e19a92c2ad56d12e927224e', 'hex');

    const iv = Buffer.from('8f45b675b98a45ad', 'hex');



    const ciphertext = Buffer.from(
        '0945137cff02b5de9965790ba1293070cb4ebd3f3ec23c80bd' +
        'a15e25de66b89973fc252b81ffbd9c44a60d492f21ee650908', 'hex');

    it('should encrypt', () => {
    
        const cast128 = new algorithm.Cast128();
        cast128.setKey(key);

        const cipher = new mode.ctr.Cipher(cast128, iv);

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

        const cast128 = new algorithm.Cast128();
        cast128.setKey(key);

        const decipher = new mode.ctr.Decipher(cast128, iv);

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

