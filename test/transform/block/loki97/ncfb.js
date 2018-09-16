

const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

(typeof algorithm.Loki97 === 'function' && typeof mode.ncfb === 'object' ? describe : describe.skip)
('loki97 transform ncfb mode', () => {


    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        'd3dda85c61756af631404dc6b88418359db15969627e90fb78' +
        'dadf8834fe89636a7332bca6c9efd1cb078f3a45454e16902f', 'hex');

    const iv = Buffer.from('b11a0ef0bda8b30eb0d343c4661a910f', 'hex');


    const ciphertext = Buffer.from(
        '5e6adab31c1a9b6accb46c139c658a079e81a3525003ba7e6c' +
        '1eb7a69ecec0b3c7cf0e011a0fadd14b20fd4490ef71325bd5', 'hex');

    it('should encrypt', () => {
    
        const loki97 = new algorithm.Loki97();
        loki97.setKey(key);

        const cipher = new mode.ncfb.Cipher(loki97, iv);

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

        const loki97 = new algorithm.Loki97();
        loki97.setKey(key);
        
        const decipher = new mode.ncfb.Decipher(loki97, iv);

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

