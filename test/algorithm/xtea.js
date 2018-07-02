
const {algorithm} = require('../..');
const assert = require('assert');

describe('xtea', () => {

    it('should be constructor', () => {
        assert(typeof algorithm.Xtea === 'function', 'there is no constructor');
    });

    const key = new Buffer(16);

    for (let i = 0; i < 16; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    // ciphertext & plaintext from mcrypt test rule
    const ciphertext = new Buffer('f61e7ff6da7cdb27', 'hex');
    const plaintext  = new Buffer('0001020304050607', 'hex');

    it('should do encrypt and decrypt operations', () => {

        describe('encrypt', () => {
            const xtea = new algorithm.Xtea();
            xtea.setKey(key);


            assert(ciphertext.equals(xtea.encrypt(plaintext)), 'encrypted plaintext should be equal to ciphertext');
        });

        describe('decrypt', () => {
            const xtea = new algorithm.Xtea();
            xtea.setKey(key);

            assert(plaintext.equals(xtea.decrypt(ciphertext)), 'decrypted ciphertext should be equal to plaintext');
        });

    });


});