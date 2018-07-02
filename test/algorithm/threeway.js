
const {algorithm} = require('../..');
const assert = require('assert');

describe('threeway', () => {

    it('should be constructor', () => {
        assert(typeof algorithm.Threeway === 'function', 'there is no constructor');
    });


    const key = new Buffer(12);

    for (let i = 0; i < 12; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    // ciphertext & plaintext from mcrypt test rule
    const ciphertext = new Buffer('46823287358d68f6e034ca62', 'hex');
    const plaintext  = new Buffer('000102030405060708090a0b', 'hex');


    it('should do encrypt and decrypt operations', () => {

        describe('encrypt', () => {
            const threeway = new algorithm.Threeway();
            threeway.setKey(key);

            assert(ciphertext.equals(threeway.encrypt(plaintext)), 'encrypted plaintext should be equal to ciphertext');
        });

        describe('decrypt', () => {
            const threeway = new algorithm.Threeway();
            threeway.setKey(key);

            assert(plaintext.equals(threeway.decrypt(ciphertext)), 'decrypted ciphertext should be equal to plaintext');
        });

    });


});