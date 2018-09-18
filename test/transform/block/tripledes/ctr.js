
const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

(typeof algorithm.Tripledes === 'function' && typeof mode.ctr === 'object' ? describe : describe.skip)
('tripledes transform ctr mode', () => {

    const key = Buffer.alloc(24, 0);

    for (let i = 0; i < 24; i++) {
        key[i] = i % 256;
    }

    const plaintext = Buffer.from(
        '2ba18f6b020b1f13107e4f8e2ea03fa246eee78c2ac4c532e0' +
        '56fa0bac17acf25d3343cdcda789b5551df6b1545e7c712159', 'hex');

    const iv = Buffer.from('7042e953eebd586f', 'hex');



    const ciphertext = Buffer.from(
        '5c71b08e5b7197f4512f208e0f728b7d30dff347ba82a7599b' +
        'f31aab166859c4b56fbacfed54e626a4e88944bea3b320e8e4', 'hex');

    it('should encrypt', () => {
    
        const tripledes = new algorithm.Tripledes();
        tripledes.setKey(key);

        const cipher = new mode.ctr.Cipher(tripledes, iv);

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

        const tripledes = new algorithm.Tripledes();
        tripledes.setKey(key);

        const decipher = new mode.ctr.Decipher(tripledes, iv);

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

