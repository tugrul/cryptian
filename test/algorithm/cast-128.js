
const {algorithm} = require('../..');
const assert = require('assert');

describe('cast 128', () => {

    it('should be constructor', () => {
        assert(typeof algorithm.Cast128 === 'function', 'there is no constructor');
    });


    const key = new Buffer(16);

    for (let i = 0; i < 16; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    // ciphertext & plaintext from mcrypt test rule
    const ciphertext = new Buffer('434e25460c8c9525', 'hex');
    const plaintext  = new Buffer('0001020304050607', 'hex');

    it('should do encrypt and decrypt operations', () => {

        describe('encrypt', () => {
            const cast128 = new algorithm.Cast128();
            cast128.setKey(key);

            assert(ciphertext.equals(cast128.encrypt(plaintext)), 'encrypted plaintext should be equal to ciphertext');
        });

        describe('decrypt', () => {
            const cast128 = new algorithm.Cast128();
            cast128.setKey(key);

            assert(plaintext.equals(cast128.decrypt(ciphertext)), 'decrypted ciphertext should be equal to plaintext');
        });

    });


});