
const {algorithm} = require('../..');
const assert = require('assert');

describe('safer-64', () => {

    it('should be constructor', () => {
        assert(typeof algorithm.Safer === 'function', 'there is no constructor');
    });


    const key = new Buffer(8);

    for (let i = 0; i < 8; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    // ciphertext & plaintext from mcrypt test rule
    const ciphertext = new Buffer('e490eebffd908f34', 'hex');
    const plaintext  = new Buffer('0001020304050607', 'hex');


    it('should do encrypt and decrypt operations', () => {

        describe('encrypt', () => {
            const safer = new algorithm.Safer();
            safer.setKey(key);

            assert(ciphertext.equals(safer.encrypt(plaintext)), 'encrypted plaintext should be equal to ciphertext');
        });

        describe('decrypt', () => {
            const safer = new algorithm.Safer();
            safer.setKey(key);

            assert(plaintext.equals(safer.decrypt(ciphertext)), 'decrypted ciphertext should be equal to plaintext');
        });

    });


});

