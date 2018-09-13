
const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

describe('blowfish transform ctr mode', () => {

    it('should be constructor', () => {
        assert(typeof algorithm.Blowfish === 'function', 'there is no constructor');
    });

    const key = new Buffer(56);

    for (let i = 0; i < 56; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = new Buffer(
        '5517d3d450db0be089159c6557e423575dd2c021671edc9c90' +
        '018a43772cd5ce3c1bc89e54a0c10b37745938f07bfd460f35', 'hex');

    const iv = new Buffer('c144b13252edff4d', 'hex');

    describe('standard', () => {

        const ciphertext = new Buffer(
            'e28f355ab3067e38fdfb5c16243b8ca063d2997f5ac5c08d80' +
            '42697ecc3b385abe54804658350ec79524c7346cce746c88a9', 'hex');

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
            '1d399d39093af94e923e8c60787c5e725ae4a3628d40284a99' +
            '36ccc708ab1773bb6451c9b4b81709cf76d1e75e86d60236ec', 'hex');

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

