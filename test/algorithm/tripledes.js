
const {algorithm} = require('../..');
const assert = require('assert');

describe('tripledes', () => {

    it('should be constructor', () => {
        assert(typeof algorithm.Tripledes === 'function', 'there is no constructor');
    });

    const key = Buffer.alloc(24, 0);

    for (let i = 0; i < 24; i++) {
        key[i] = i % 256;
    }

    // ciphertext & plaintext from mcrypt test rule
    const ciphertext = Buffer.from('58ed248f77f6b19e', 'hex');
    const plaintext  = Buffer.from('0001020304050607', 'hex');

    it('should encrypt', () => {

        const tripledes = new algorithm.Tripledes();
        
        tripledes.setKey(key);

        assert(ciphertext.equals(tripledes.encrypt(plaintext)), 'encrypted plaintext should equal to ciphertext');

    });

    
    it('should decrypt', () => {

        const tripledes = new algorithm.Tripledes();

        tripledes.setKey(key);

        assert(plaintext.equals(tripledes.decrypt(ciphertext)), 'decrypted ciphertext should equal to plaintext');

    });

});