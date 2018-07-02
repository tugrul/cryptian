
const {algorithm} = require('../..');
const assert = require('assert');

describe('arcfour', () => {

    it('should be constructor', () => {
        assert(typeof algorithm.Arcfour === 'function', 'there is no constructor');
    });


    const key = new Buffer(256);

    for (let i = 0; i < 256; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    // ciphertext & plaintext from mcrypt test rule
    const ciphertext = new Buffer('3abaa03a286e24c4196d292ab72934d6854c3eee', 'hex');
    const plaintext  = new Buffer('000102030405060708090a0b0c0d0e0f10111213', 'hex');


    it('should do encrypt and decrypt operations', () => {

        describe('encrypt', () => {
            const arcfour = new algorithm.Arcfour();
            arcfour.setKey(key);

            assert(ciphertext.equals(arcfour.encrypt(plaintext)), 'encrypted plaintext should be equal to ciphertext');
        });

        describe('decrypt', () => {
            const arcfour = new algorithm.Arcfour();
            arcfour.setKey(key);

            assert(plaintext.equals(arcfour.decrypt(ciphertext)), 'decrypted ciphertext should be equal to plaintext');
        });

    });


});

