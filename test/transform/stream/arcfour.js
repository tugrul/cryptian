
const {algorithm, 
    createEncryptStream, 
    createDecryptStream} = require('../../..');

const assert = require('assert');

const streamBuffers = require('stream-buffers');

(typeof algorithm.Arcfour === 'function' ? describe : describe.skip)
('arcfour transform', () => {

    const key = Buffer.alloc(256, 0);

    for (let i = 0; i < 256; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    // ciphertext & plaintext from mcrypt test rule
    const ciphertext = Buffer.from('3abaa03a286e24c4196d292ab72934d6854c3eee', 'hex');
    const plaintext  = Buffer.from('000102030405060708090a0b0c0d0e0f10111213', 'hex');


    it('should encrypt', () => {
        const arcfour = new algorithm.Arcfour();
        arcfour.setKey(key);

        const transform = createEncryptStream(arcfour);
        const buffer = transform.pipe(new streamBuffers.WritableStreamBuffer());
        
        buffer.on('finish', () => {
            assert(ciphertext.equals(buffer.getContents()), 'encrypted plaintext should be equal to ciphertext');
        });

        transform.write(plaintext.slice(0, 7));
        transform.write(plaintext.slice(7, 13));
        transform.end(plaintext.slice(13));
        
    });

    it('should decrypt', () => {
        const arcfour = new algorithm.Arcfour();
        arcfour.setKey(key);

        const transform = createDecryptStream(arcfour);
        const buffer = transform.pipe(new streamBuffers.WritableStreamBuffer());
        
        buffer.on('finish', () => {
            assert(plaintext.equals(buffer.getContents()), 'decrypted ciphertext should be equal to plaintext');
        });

        transform.write(ciphertext.slice(0, 5));
        transform.write(ciphertext.slice(5, 17));
        transform.end(ciphertext.slice(17));
        
    });



});

