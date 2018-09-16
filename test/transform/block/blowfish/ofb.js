

const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

(typeof algorithm.Blowfish === 'function' && typeof mode.ofb === 'object' ? describe : describe.skip)
('blowfish transform ofb mode', () => {

    const key = Buffer.alloc(56, 0);

    for (let i = 0; i < 56; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        'f6888ed9643982d42dade5cbb9d628cf617fcfa23fe7b4f6d7' +
        'bf57ebbeb348f128ce69295dae1ee2b70cb769ae62fbedd3d0', 'hex');

    const iv = Buffer.from('025cd945aecffcff', 'hex');

    describe('standard', () => {

        const ciphertext = Buffer.from(
            'd68a79bd47abe1b7a20cf2282adde00db8efb1b99f75b2cffc' +
            'ad2c984c967c6fe9cc8e6d7582f789bd8cf91b7a173c49463b', 'hex');

        it('should encrypt', () => {
        
            const blowfish = new algorithm.Blowfish();
            blowfish.setKey(key);

            const cipher = new mode.ofb.Cipher(blowfish, iv);

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
            
            const decipher = new mode.ofb.Decipher(blowfish, iv);

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
            'be3618de0ec560568c7839cd357f218a8b94d56791ad618616' +
            'f9e7c91f8c11b30b4efbfd6093e985becbfff1e923ecb8c48d', 'hex');
            
        it('should encrypt', () => {
        
            const blowfish = new algorithm.Blowfish();
            blowfish.setKey(key);
            blowfish.setEndianCompat(true);
            
            const cipher = new mode.ofb.Cipher(blowfish, iv);

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
            
            const decipher = new mode.ofb.Decipher(blowfish, iv);

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

