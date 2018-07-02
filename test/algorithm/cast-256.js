
const {algorithm} = require('../..');
const assert = require('assert');

describe('cast 256', () => {

    it('should be constructor', () => {
        assert(typeof algorithm.Cast256 === 'function', 'there is no constructor');
    });

    const key = new Buffer(32);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    // ciphertext & plaintext from mcrypt test rule
    const ciphertext = new Buffer('5db4dd765f1d3835615a14afcb5dc2f5', 'hex');
    const plaintext  = new Buffer('000102030405060708090a0b0c0d0e0f', 'hex');

    it('should do encrypt and decrypt operations', () => {

        describe('encrypt', () => {
            const cast256 = new algorithm.Cast256();
            cast256.setKey(key);

            assert(ciphertext.equals(cast256.encrypt(plaintext)), 'encrypted plaintext should be equal to ciphertext');
        });

        describe('decrypt', () => {
            const cast256 = new algorithm.Cast256();
            cast256.setKey(key);

            assert(plaintext.equals(cast256.decrypt(ciphertext)), 'decrypted ciphertext should be equal to plaintext');
        });

    });


});