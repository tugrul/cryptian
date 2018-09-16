
const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

(typeof algorithm.Cast128 === 'function' && typeof mode.cfb === 'object' ? describe : describe.skip)
('cast-128 transform cfb mode', () => {

    const key = Buffer.alloc(16, 0);

    for (let i = 0; i < 16; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '9907d61dcfc9456b237d002ce859b5a1d7bc92747b9cc9d76e' +
        '968442060fa16c9a2f3dd1d2205e19a92c2ad56d12e927224e', 'hex');

    const iv = Buffer.from('8f45b675b98a45ad', 'hex');



    const ciphertext = Buffer.from(
        '095b8088fe8e653d1387827ae8ccb9644f910c74e487931ac9' +
        '040400eb17c60ea5d19031ed3ed7b6db2f2191428af4bb1708', 'hex');

    it('should encrypt', () => {
    
        const cast128 = new algorithm.Cast128();
        cast128.setKey(key);

        const cipher = new mode.cfb.Cipher(cast128, iv);

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

        const decipher = new mode.cfb.Decipher(cast128, iv);

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

