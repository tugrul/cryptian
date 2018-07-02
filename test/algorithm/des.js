
const {algorithm} = require('../..');
const assert = require('assert');

describe('des', () => {

    it('should be constructor', () => {
        assert(typeof algorithm.Des === 'function', 'there is no constructor');
    });

    const key = new Buffer(8);

    for (let i = 0; i < 8; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    // ciphertext & plaintext from mcrypt test rule
    const ciphertext = new Buffer('a1502d70ba1320c8', 'hex');
    const plaintext  = new Buffer('0001020304050607', 'hex');

    it('should do encrypt and decrypt operations', () => {

        describe('encrypt', () => {
            const des = new algorithm.Des();
            des.setKey(key);


            assert(ciphertext.equals(des.encrypt(plaintext)), 'encrypted plaintext should be equal to ciphertext');
        });

        describe('decrypt', () => {
            const des = new algorithm.Des();
            des.setKey(key);

            assert(plaintext.equals(des.decrypt(ciphertext)), 'decrypted ciphertext should be equal to plaintext');
        });

    });


});