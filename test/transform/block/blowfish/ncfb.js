
const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

describe('blowfish transform ncfb mode', () => {

    it('should be constructor', () => {
        assert(typeof algorithm.Blowfish === 'function', 'there is no constructor');
    });

    const key = Buffer.alloc(56, 0);

    for (let i = 0; i < 56; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        'f321a0b6bdd0f6400a04800871ed0cdb6180c9d91267aaadc3' +
        'e1237dfbfe013cb2a2edbaddf8e59bb67635018e635f41573a', 'hex');

    const iv = Buffer.from('999b2160c293ee2e', 'hex');

    describe('standard', () => {

        const ciphertext = Buffer.from(
            '86d8b621ed3a887bf47753921beee1f7e259ced3797d70728c' +
            '255f199e60d5750e78e69c6017c6fb76894b238265c06d93fb', 'hex');


        it('should encrypt', () => {
        
            const blowfish = new algorithm.Blowfish();
            blowfish.setKey(key);

            const cipher = new mode.cfb.Cipher(blowfish, iv);

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

            const blowfish = new algorithm.Blowfish();
            blowfish.setKey(key);
            
            const decipher = new mode.cfb.Decipher(blowfish, iv);

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

    describe('endian compat', () => {
        
        const ciphertext = Buffer.from(
            '3b5b5f51e26d9d6eea0c4cd5de2eae7f0b1028cca35b068df8' +
            '97b2a26234989fd1b080c64264ab700365f93f67580e569713', 'hex');


        it('should encrypt', () => {
        
            const blowfish = new algorithm.Blowfish();
            blowfish.setKey(key);
            blowfish.setEndianCompat(true);
            
            const cipher = new mode.cfb.Cipher(blowfish, iv);

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

            const blowfish = new algorithm.Blowfish();
            blowfish.setKey(key);
            blowfish.setEndianCompat(true);
            
            const decipher = new mode.cfb.Decipher(blowfish, iv);

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
    

});

