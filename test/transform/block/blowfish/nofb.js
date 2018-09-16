


const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

(typeof algorithm.Blowfish === 'function' && typeof mode.nofb === 'object' ? describe : describe.skip)
('blowfish transform nofb mode', () => {

    const key = Buffer.alloc(56, 0);

    for (let i = 0; i < 56; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        'cb47cd1172c191ba6331bac60a85697f76e0656306ac5bd9c0' +
        '05179a364f013e107284e403226b56ee1b980e7d7ca132fabe', 'hex');

    const iv = Buffer.from('999b2160c293ee2e', 'hex');

    describe('standard', () => {

        const ciphertext = Buffer.from(
            'beffc86ea67770e5203cd074bd1ca4c4e6af51e3f93e783c91' +
            'fa6fe410fbe4b12d741083e89a73649015965b981bc4f17349', 'hex');


        it('should encrypt', () => {
        
            const blowfish = new algorithm.Blowfish();
            blowfish.setKey(key);

            const cipher = new mode.nofb.Cipher(blowfish, iv);

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
            
            const decipher = new mode.nofb.Decipher(blowfish, iv);

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
            '03147b6487d62e8a434e426f3698a5944749f6246c615ba118' +
            'aa7a6d1500996a5694ae997baee947bac65a9c2f6ea157103a', 'hex');


            
        it('should encrypt', () => {
        
            const blowfish = new algorithm.Blowfish();
            blowfish.setKey(key);
            blowfish.setEndianCompat(true);
            
            const cipher = new mode.nofb.Cipher(blowfish, iv);

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
            
            const decipher = new mode.nofb.Decipher(blowfish, iv);

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

