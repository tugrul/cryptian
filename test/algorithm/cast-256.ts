import assert from "assert";

import cryptian from '../..';

const {Cast256} = cryptian.algorithm;

(typeof Cast256 === 'function'? describe : describe.skip) ('cast 256', () => {

    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    // ciphertext & plaintext from mcrypt test rule
    const ciphertext = Buffer.from('5db4dd765f1d3835615a14afcb5dc2f5', 'hex');

    const plaintext  = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');

    it('should encrypt', () => {

        const cast256 = new Cast256();

        cast256.setKey(key);

        assert(ciphertext.equals(cast256.encrypt(plaintext)), 'encrypted plaintext should equal to ciphertext');

    });

    it('should decrypt', () => {

        const cast256 = new Cast256();

        cast256.setKey(key);

        assert(plaintext.equals(cast256.decrypt(ciphertext)), 'decrypted ciphertext should equal to plaintext');

    });

});