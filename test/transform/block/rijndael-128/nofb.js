
const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

(typeof algorithm.Rijndael128 === 'function' && typeof mode.nofb === 'object' ? describe : describe.skip)
('rijndael-128 transform nofb mode', () => {

    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '0bd7d4ba98efb4b903faa1d5a34b1b1d4410e8ff88626dd8b5' +
        '734fcc4c7b76e29e31af5e2346d037607cc5a4529a16288332', 'hex');

    const iv = Buffer.from('e4e8e1ed7fd8e70793db9abde83a3ffc', 'hex');


    const ciphertext = Buffer.from(
        '87a8840b4702870e46286a2b3a416f0fdbdfc8c40188361e4e' +
        '9ec5768a5c896462d89f539ec7fd15c412d6c02cdbfff027b3', 'hex');

    it('should encrypt', () => {
    
        const rijndael = new algorithm.Rijndael128();
        rijndael.setKey(key);

        const cipher = new mode.nofb.Cipher(rijndael, iv);

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

        const rijndael = new algorithm.Rijndael128();
        rijndael.setKey(key);
        
        const decipher = new mode.nofb.Decipher(rijndael, iv);

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

