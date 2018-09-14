
const {algorithm} = require('../..');
const assert = require('assert');

describe('rijndael-256', () => {

    it('should be constructor', () => {
        assert(typeof algorithm.Rijndael256 === 'function', 'there is no constructor');
    });

    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    // ciphertext & plaintext from mcrypt test rule
    const ciphertext = Buffer.from('45af6c269326fd935edd24733cff74fc1aa358841a6cd80b79f242d983f8ff2e', 'hex');
    const plaintext  = Buffer.from('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 'hex');


    it('should encrypt', () => {

        const rijndael = new algorithm.Rijndael256();
        
        rijndael.setKey(key);

        assert(ciphertext.equals(rijndael.encrypt(plaintext)), 'encrypted plaintext should equal to ciphertext');

    });

    it('should decrypt', () => {

        const rijndael = new algorithm.Rijndael256();
        
        rijndael.setKey(key);

        assert(plaintext.equals(rijndael.decrypt(ciphertext)), 'decrypted ciphertext should equal to plaintext');

    });
    

});

