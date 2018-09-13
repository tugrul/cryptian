


const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

describe('blowfish transform nofb mode', () => {

    it('should be constructor', () => {
        assert(typeof algorithm.Blowfish === 'function', 'there is no constructor');
    });

    const key = new Buffer(56);

    for (let i = 0; i < 56; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = new Buffer(
        'cb47cd1172c191ba6331bac60a85697f76e0656306ac5bd9c0' +
        '05179a364f013e107284e403226b56ee1b980e7d7ca132fabe', 'hex');

    const iv = new Buffer('999b2160c293ee2e', 'hex');

    describe('standard', () => {

        const ciphertext = new Buffer(
            'be61bab48631f64524a620e11a90f0cc497a251ab716dbe82d' +
            'd34a636b31a56db0e4505c404f70f2d599ea64c37ed8538313', 'hex');

        it('should do encrypt and decrypt operations', () => {

            describe('encrypt', () => {
            
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

            describe('decrypt', () => {

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
    

    });

    describe('endian compat', () => {
        
        const ciphertext = new Buffer(
            '03e44fedb361ec75e25e51652dc23f4a63f206fdf21dc6d67a' +
            '8ce3e98c3073df33b39114e1cfcc5383df774c83f59df1edd3', 'hex');

        it('should do encrypt and decrypt operations', () => {
            
            describe('encrypt', () => {
            
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
            
            describe('decrypt', () => {

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
    

});

