
const {algorithm} = require('../..');
const assert = require('assert');

describe('dummy', () => {

    it('should be constructor', () => {
        assert(typeof algorithm.Dummy === 'function', 'there is no constructor');
    });


    const ciphertext = new Buffer('a1502d70ba1320c8', 'hex');
    const plaintext  = new Buffer('0001020304050607', 'hex');

    it('should do encrypt and decrypt operations', () => {

        describe('encrypt', () => {
            const dummy = new algorithm.Dummy();

            assert(ciphertext.equals(dummy.encrypt(ciphertext)), 'encrypted plaintext should be equal to ciphertext');
        });

        describe('decrypt', () => {
            const dummy = new algorithm.Dummy();

            assert(plaintext.equals(dummy.decrypt(plaintext)), 'decrypted ciphertext should be equal to plaintext');
        });

    });


});