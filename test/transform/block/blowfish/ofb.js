

const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

describe('blowfish transform ofb mode', () => {

    it('should be constructor', () => {
        assert(typeof algorithm.Blowfish === 'function', 'there is no constructor');
    });

    const key = new Buffer(56);

    for (let i = 0; i < 56; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = new Buffer(
        'f6888ed9643982d42dade5cbb9d628cf617fcfa23fe7b4f6d7' +
        'bf57ebbeb348f128ce69295dae1ee2b70cb769ae62fbedd3d0', 'hex');

    const iv = new Buffer('025cd945aecffcff', 'hex');

    describe('standard', () => {

        const ciphertext = new Buffer(
            'd670a1b03242d436a9e7ca3c1662f6f3c845bf206e4ada6f8a' +
            '12cc59dcc79c604730a921bd9565243682d3b603517906d7c2', 'hex');

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
            'be053bc422c00da24e7160c66b1952a2329a823ff494233973' +
            '22c57dcb85857af0bcd5dc1a56e005e4be11d36f97797d0908', 'hex');

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

