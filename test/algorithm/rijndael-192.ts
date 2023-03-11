
import assert from "assert";

import cryptian from '../..';

const {Rijndael192} = cryptian.algorithm;


(typeof Rijndael192 === 'function'? describe : describe.skip)
('rijndael-192', () => {

    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    // ciphertext & plaintext from mcrypt test rule
    const ciphertext = Buffer.from('380ee49a5de1dbd4b9cc11af60b8c8ff669e367af8948a8a', 'hex');

    const plaintext  = Buffer.from('000102030405060708090a0b0c0d0e0f1011121314151617', 'hex');


    it('should encrypt', () => {
            
        const rijndael = new Rijndael192();
        
        rijndael.setKey(key);

        assert(ciphertext.equals(rijndael.encrypt(plaintext)), 'encrypted plaintext should equal to ciphertext');

    });
    
    it('should decrypt', () => {
            
        const rijndael = new Rijndael192();
        
        rijndael.setKey(key);

        assert(plaintext.equals(rijndael.decrypt(ciphertext)), 'decrypted ciphertext should equal to plaintext');

    });


});

