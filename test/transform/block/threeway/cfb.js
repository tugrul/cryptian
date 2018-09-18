
const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

(typeof algorithm.Threeway === 'function' && typeof mode.cfb === 'object' ? describe : describe.skip)
('threeway transform cfb mode', () => {

    const key = Buffer.alloc(12, 0);

    for (let i = 0; i < 12; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        'a4eb7e8ac2774e6557c9ad1d4032aa6dce0b86851c86b88e2c' +
        '460bc2a1a69d6fb193d4cee0fc0efaee0e41b7aa7420d98f42', 'hex');

    const iv = Buffer.from('610af686c2883e3f78daffa4', 'hex');



    const ciphertext = Buffer.from(
        '3dad071dfcc58caaf99d5f7a1dc21f49e554c01a8fe355ee0c' +
        '1cce1ae8eb7c201934616f0dcd0b6cc7e21930cf04bb3b8a47', 'hex');

    it('should encrypt', () => {
    
        const threeway = new algorithm.Threeway();
        threeway.setKey(key);

        const cipher = new mode.cfb.Cipher(threeway, iv);

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

        const threeway = new algorithm.Threeway();
        threeway.setKey(key);
        
        const decipher = new mode.cfb.Decipher(threeway, iv);

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

