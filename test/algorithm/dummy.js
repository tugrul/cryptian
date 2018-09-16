
const {algorithm} = require('../..');
const assert = require('assert');

(typeof algorithm.Dummy === 'function'? describe : describe.skip)
('dummy', () => {

    const ciphertext = Buffer.from('a1502d70ba1320c8', 'hex');
    const plaintext  = Buffer.from('0001020304050607', 'hex');

    it('should encrypt', () => {

        const dummy = new algorithm.Dummy();

        assert(ciphertext.equals(dummy.encrypt(ciphertext)), 'encrypted plaintext should equal to ciphertext');

    });
    
    it('should decrypt', () => {

        const dummy = new algorithm.Dummy();

        assert(plaintext.equals(dummy.decrypt(plaintext)), 'decrypted ciphertext should equal to plaintext');

    });


});