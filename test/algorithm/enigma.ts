
import assert from "assert";

import cryptian from '../..';

const {Enigma} = cryptian.algorithm;


(typeof Enigma === 'function' ? describe : describe.skip) ('enigma', () => {

    const key = Buffer.from('enadyotr', 'ascii');

    // ciphertext & plaintext from mcrypt test rule
    const ciphertext = Buffer.from('f3edda7da20f8975884600f014d32c7a08e59d7b', 'hex');

    const plaintext  = Buffer.from('000102030405060708090a0b0c0d0e0f10111213', 'hex');


    it('should encrypt', () => {

        const enigma = new Enigma();

        enigma.setKey(key);

        assert(ciphertext.equals(enigma.encrypt(plaintext)), 'encrypted plaintext should equal to ciphertext');

    });
    
    
    it('should decrypt', () => {

        const enigma = new Enigma();
        
        enigma.setKey(key);

        assert(plaintext.equals(enigma.decrypt(ciphertext)), 'decrypted ciphertext should equal to plaintext');

    });


});