

const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

(typeof algorithm.Loki97 === 'function' && typeof mode.ofb === 'object' ? describe : describe.skip)
('loki97 transform ofb mode', () => {


    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        'd3dda85c61756af631404dc6b88418359db15969627e90fb78' +
        'dadf8834fe89636a7332bca6c9efd1cb078f3a45454e16902f', 'hex');

    const iv = Buffer.from('b11a0ef0bda8b30eb0d343c4661a910f', 'hex');


    const ciphertext = Buffer.from(
        '5eb898a10f3466582fee8c614e11748022b486c89c0b26d028' +
        '9a26c4379c942903586f17b9d5b949ac36fbe0f74e21856ab2', 'hex');

    it('should encrypt', () => {
    
        const loki97 = new algorithm.Loki97();
        loki97.setKey(key);

        const cipher = new mode.ofb.Cipher(loki97, iv);

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
        
        const decipher = new mode.ofb.Decipher(loki97, iv);

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

