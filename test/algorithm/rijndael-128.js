
const {algorithm} = require('../..');
const assert = require('assert');

describe('rijndael-128', () => {

    it('should be constructor', () => {
        assert(typeof algorithm.Rijndael128 === 'function', 'there is no constructor');
    });


    const key = new Buffer(16);
    key.fill(0);
    key[0] = 1;


    // ciphertext & plaintext from mcrypt test rule
    const ciphertext = new Buffer('5352e43763eec1a8502433d6d520b1f0', 'hex');
    const plaintext  = new Buffer('000102030405060708090a0b0c0d0e0f', 'hex');


    it('should do encrypt and decrypt operations', () => {

        describe('encrypt', () => {
            const rijndael = new algorithm.Rijndael128();
            rijndael.setKey(key);

            assert(ciphertext.equals(rijndael.encrypt(plaintext)), 'encrypted plaintext should be equal to ciphertext');
        });

        describe('decrypt', () => {
            const rijndael = new algorithm.Rijndael128();
            rijndael.setKey(key);

            assert(plaintext.equals(rijndael.decrypt(ciphertext)), 'decrypted ciphertext should be equal to plaintext');
        });

    });


});

