
const {algorithm} = require('../..');
const assert = require('assert');

describe('safer-128', () => {

    it('should be constructor', () => {
        assert(typeof algorithm.Safer === 'function', 'there is no constructor');
    });


    const key = Buffer.alloc(16, 0);

    for (let i = 0; i < 16; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    // ciphertext & plaintext from mcrypt test rule
    const ciphertext = Buffer.from('35ed856e2cf90947', 'hex');
    const plaintext  = Buffer.from('0001020304050607', 'hex');


    it('should encrypt', () => {

        const safer = new algorithm.Safer();
        
        safer.setKey(key);

        assert(ciphertext.equals(safer.encrypt(plaintext)), 'encrypted plaintext should equal to ciphertext');

    });
    
    
    it('should decrypt', () => {
        
        const safer = new algorithm.Safer();
        
        safer.setKey(key);

        assert(plaintext.equals(safer.decrypt(ciphertext)), 'decrypted ciphertext should equal to plaintext');

    });


});

