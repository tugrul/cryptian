
const {algorithm, 
    createEncryptStream, 
    createDecryptStream} = require('../../..');

const assert = require('assert');

const streamBuffers = require('stream-buffers');

describe('wake transform', () => {

    it('should be constructor', () => {
        assert(typeof algorithm.Wake === 'function', 'there is no constructor');
    });


    const key = new Buffer(32);

    for (let i = 0; i < 32; i++) {
        key[i] = (i * 5 + 10) & 0xff;
    }

    // ciphertext & plaintext from mcrypt test rule
    const ciphertext = new Buffer('434d575db053acfe6e4076f05298bedbd5f4f000be555d029b1367cffc7cd51bba61c76aa17da3530fb7d9', 'hex');
    const plaintext  = new Buffer('05060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f', 'hex');


    it('should do encrypt and decrypt operations', () => {

        describe('encrypt', () => {
            const wake = new algorithm.Wake();
            wake.setKey(key);

            const transform = createEncryptStream(wake);
            const buffer = transform.pipe(new streamBuffers.WritableStreamBuffer());
            
            buffer.on('finish', () => {
                assert(ciphertext.equals(buffer.getContents()), 'encrypted plaintext should be equal to ciphertext');
            });

            transform.write(plaintext.slice(0, 15));
            transform.write(plaintext.slice(15, 23));
            transform.end(plaintext.slice(23));
        });

        describe('decrypt', () => {
            const wake = new algorithm.Wake();
            wake.setKey(key);

            const transform = createDecryptStream(wake);
            const buffer = transform.pipe(new streamBuffers.WritableStreamBuffer());
            
            buffer.on('finish', () => {
                assert(plaintext.equals(buffer.getContents()), 'decrypted ciphertext should be equal to plaintext');
            });

            transform.write(ciphertext.slice(0, 17));
            transform.write(ciphertext.slice(17, 22));
            transform.end(ciphertext.slice(22));
        });

    });


});

