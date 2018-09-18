
const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

(typeof algorithm.Threeway === 'function' && typeof mode.ncfb === 'object' ? describe : describe.skip)
('threeway transform ncfb mode', () => {

    const key = Buffer.alloc(12, 0);

    for (let i = 0; i < 12; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '6af063691f45b41f74ea14ff9c2db52bc21dde839b1ab2ef11' +
        '533bf304722876be27b488654d9ab169d7c6e4d71bb2f64371', 'hex');

    const iv = Buffer.from('aa20a53fca0667351f66ee20', 'hex');



    const ciphertext = Buffer.from(
        '2e9a56eff26f39435937d98e260d742397e9881e1a2ca7cbcb' +
        '170d50ad474abfb8dc79d38600494c6eadb3f5439acc058002', 'hex');

    it('should encrypt', () => {
    
        const threeway = new algorithm.Threeway();
        threeway.setKey(key);

        const cipher = new mode.ncfb.Cipher(threeway, iv);

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
        
        const decipher = new mode.ncfb.Decipher(threeway, iv);

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

