import assert from "assert";

import cryptian from '../..';

const {Dummy} = cryptian.algorithm;

(typeof Dummy === 'function'? describe : describe.skip) ('dummy', () => {

    const ciphertext = Buffer.from('a1502d70ba1320c8', 'hex');
    const plaintext  = Buffer.from('0001020304050607', 'hex');

    it('should encrypt', () => {

        const dummy = new Dummy();

        assert(ciphertext.equals(dummy.encrypt(ciphertext)), 'encrypted plaintext should equal to ciphertext');

    });
    
    it('should decrypt', () => {

        const dummy = new Dummy();

        assert(plaintext.equals(dummy.decrypt(plaintext)), 'decrypted ciphertext should equal to plaintext');

    });


});