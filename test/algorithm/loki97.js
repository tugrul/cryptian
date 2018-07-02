
const {algorithm} = require('../..');
const assert = require('assert');

describe('loki97', () => {

    it('should be constructor', () => {
        assert(typeof algorithm.Loki97 === 'function', 'there is no constructor');
    });

    const key = new Buffer(32);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    // ciphertext & plaintext from mcrypt test rule
    const ciphertext = new Buffer('8cb28c958024bae27a94c698f96f12a9', 'hex');
    const plaintext  = new Buffer('000102030405060708090a0b0c0d0e0f', 'hex');

    it('should do encrypt and decrypt operations', () => {

        describe('encrypt', () => {
            const loki97 = new algorithm.Loki97();
            loki97.setKey(key);

            assert(ciphertext.equals(loki97.encrypt(plaintext)), 'encrypted plaintext should be equal to ciphertext');
        });

        describe('decrypt', () => {
            const loki97 = new algorithm.Loki97();
            loki97.setKey(key);

            assert(plaintext.equals(loki97.decrypt(ciphertext)), 'decrypted ciphertext should be equal to plaintext');
        });

    });


});