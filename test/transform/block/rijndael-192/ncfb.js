
const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

(typeof algorithm.Rijndael192 === 'function' && typeof mode.ncfb === 'object' ? describe : describe.skip)
('rijndael-192 transform ncfb mode', () => {

    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '9da95b6b9fc781e83a42ee20962053c7808ffe5b520ce93ee6' +
        'ed34a272a2f304084ec3f26424a17bbd54d68424e7bbba9d09', 'hex');

    const iv = Buffer.from('dd5a4acb0329f13e56fc7c8946cd8596da044c914caab8b5', 'hex');



    const ciphertext = Buffer.from(
        'db234a51ac5275a3df7eaef089991d9356ba600e4a11c198e9' +
        'b2a80f1e91432a5f9d0aeee522b979e687136b7054b20d8653', 'hex');

    it('should encrypt', () => {
    
        const rijndael = new algorithm.Rijndael192();
        rijndael.setKey(key);

        const cipher = new mode.ncfb.Cipher(rijndael, iv);

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

        const rijndael = new algorithm.Rijndael192();
        rijndael.setKey(key);
        
        const decipher = new mode.ncfb.Decipher(rijndael, iv);

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

