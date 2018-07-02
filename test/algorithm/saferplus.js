
const {algorithm} = require('../..');
const assert = require('assert');

describe('saferplus', () => {

    it('should be constructor', () => {
        assert(typeof algorithm.Saferplus === 'function', 'there is no constructor');
    });


    const key = new Buffer(32);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    // ciphertext & plaintext from mcrypt test rule
    const ciphertext = new Buffer('97fa76704bf6b578549f65c6f75b228b', 'hex');
    const plaintext  = new Buffer('000102030405060708090a0b0c0d0e0f', 'hex');


    it('should do encrypt and decrypt operations', () => {

        describe('encrypt', () => {
            const saferplus = new algorithm.Saferplus();
            saferplus.setKey(key);

            assert(ciphertext.equals(saferplus.encrypt(plaintext)), 'encrypted plaintext should be equal to ciphertext');
        });

        describe('decrypt', () => {
            const saferplus = new algorithm.Saferplus();
            saferplus.setKey(key);

            assert(plaintext.equals(saferplus.decrypt(ciphertext)), 'decrypted ciphertext should be equal to plaintext');
        });

    });


});

