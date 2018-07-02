
const {algorithm} = require('../..');
const assert = require('assert');

describe('enigma', () => {

    it('should be constructor', () => {
        assert(typeof algorithm.Enigma === 'function', 'there is no constructor');
    });


    const key = new Buffer("enadyotr");

    // ciphertext & plaintext from mcrypt test rule
    const ciphertext = new Buffer('f3edda7da20f8975884600f014d32c7a08e59d7b', 'hex');
    const plaintext  = new Buffer('000102030405060708090a0b0c0d0e0f10111213', 'hex');


    it('should do encrypt and decrypt operations', () => {

        describe('encrypt', () => {
            const enigma = new algorithm.Enigma();
            enigma.setKey(key);

            assert(ciphertext.equals(enigma.encrypt(plaintext)), 'encrypted plaintext should be equal to ciphertext');
        });

        describe('decrypt', () => {
            const enigma = new algorithm.Enigma();
            enigma.setKey(key);

            assert(plaintext.equals(enigma.decrypt(ciphertext)), 'decrypted ciphertext should be equal to plaintext');
        });

    });


});