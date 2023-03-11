
import assert from "assert";

import cryptian from '../..';

const {Rijndael128} = cryptian.algorithm;


(typeof Rijndael128 === 'function'? describe : describe.skip)
('rijndael-128', () => {

    const key = Buffer.alloc(16, 0); 
    key[0] = 1;

    // ciphertext & plaintext from mcrypt test rule
    const ciphertext = Buffer.from('5352e43763eec1a8502433d6d520b1f0', 'hex');

    const plaintext  = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');


    it('should encrypt', () => {

        const rijndael = new Rijndael128();

        rijndael.setKey(key);

        assert(ciphertext.equals(rijndael.encrypt(plaintext)), 'encrypted plaintext should equal to ciphertext');

    });
    
    it('should decrypt', () => {

        const rijndael = new Rijndael128();

        rijndael.setKey(key);

        assert(plaintext.equals(rijndael.decrypt(ciphertext)), 'decrypted ciphertext should equal to plaintext');

    });


});

