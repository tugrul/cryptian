
import assert from "assert";

import cryptian from '../..';

const {Threeway} = cryptian.algorithm;

(typeof Threeway === 'function'? describe : describe.skip)
('threeway', () => {


    const key = Buffer.alloc(12, 0);

    for (let i = 0; i < 12; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    // ciphertext & plaintext from mcrypt test rule
    const ciphertext = Buffer.from('46823287358d68f6e034ca62', 'hex');

    const plaintext  = Buffer.from('000102030405060708090a0b', 'hex');


    it('should encrypt', () => {

        const threeway = new Threeway();

        // original implementation do not have byteswap but mcrypt implementation have byteswap
        // i reversed byteswap from LE to BE. in this case results same with original implementation
        threeway.setEndianCompat(true); 
        
        threeway.setKey(key);

        assert(ciphertext.equals(threeway.encrypt(plaintext)), 'encrypted plaintext should equal to ciphertext');

    });
    
    it('should decrypt', () => {

        const threeway = new Threeway();

        // original implementation do not have byteswap but mcrypt implementation have byteswap
        // i reversed byteswap from LE to BE. in this case results same with original implementation
        threeway.setEndianCompat(true);
        
        threeway.setKey(key);

        assert(plaintext.equals(threeway.decrypt(ciphertext)), 'decrypted ciphertext should equal to plaintext');

    });


});