
import assert from "assert";

import cryptian from '../..';

const {Tripledes} = cryptian.algorithm;

(typeof Tripledes === 'function' ? describe : describe.skip) ('tripledes', () => {

    const key = Buffer.alloc(24, 0);

    for (let i = 0; i < 24; i++) {
        key[i] = i % 256;
    }

    // ciphertext & plaintext from mcrypt test rule
    const ciphertext = Buffer.from('58ed248f77f6b19e', 'hex');

    const plaintext  = Buffer.from('0001020304050607', 'hex');

    it('should encrypt', () => {

        const tripledes = new Tripledes();
        
        tripledes.setKey(key);

        assert(ciphertext.equals(tripledes.encrypt(plaintext)), 'encrypted plaintext should equal to ciphertext');

    });

    
    it('should decrypt', () => {

        const tripledes = new Tripledes();

        tripledes.setKey(key);

        assert(plaintext.equals(tripledes.decrypt(ciphertext)), 'decrypted ciphertext should equal to plaintext');

    });

});