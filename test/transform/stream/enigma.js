
const {algorithm, 
    createEncryptStream, 
    createDecryptStream} = require('../../..');

const assert = require('assert');

const streamBuffers = require('stream-buffers');

describe('enigma transform', () => {

    it('should be constructor', () => {
        assert(typeof algorithm.Enigma === 'function', 'there is no constructor');
    });


    const key = Buffer.from('enadyotr', 'ascii');

    // ciphertext & plaintext from mcrypt test rule
    const ciphertext = Buffer.from('f3edda7da20f8975884600f014d32c7a08e59d7b', 'hex');
    const plaintext  = Buffer.from('000102030405060708090a0b0c0d0e0f10111213', 'hex');


    it('should encrypt', () => {
        const enigma = new algorithm.Enigma();
        enigma.setKey(key);

        const transform = createEncryptStream(enigma);
        const buffer = transform.pipe(new streamBuffers.WritableStreamBuffer());
        
        buffer.on('finish', () => {
            assert(ciphertext.equals(buffer.getContents()), 'encrypted plaintext should be equal to ciphertext');
        });
        
        transform.write(plaintext.slice(0, 6));
        transform.write(plaintext.slice(6, 15));
        transform.end(plaintext.slice(15));
    });

    it('should decrypt', () => {
        const enigma = new algorithm.Enigma();
        enigma.setKey(key);

        const transform = createDecryptStream(enigma);
        const buffer = transform.pipe(new streamBuffers.WritableStreamBuffer());
        
        buffer.on('finish', () => {
            assert(plaintext.equals(buffer.getContents()), 'decrypted ciphertext should be equal to plaintext');
        });
        
        transform.write(ciphertext.slice(0, 4));
        transform.write(ciphertext.slice(4, 12));
        transform.end(ciphertext.slice(12));
    });


});