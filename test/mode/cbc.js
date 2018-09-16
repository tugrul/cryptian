
const {algorithm, mode} = require('../..');
const assert = require('assert');
const crypto = require('crypto');

(typeof mode.cbc === 'object' ? describe : describe.skip)
('cbc', () => {

    const plaintext  = Buffer.from('88cc3d134aee5660f7623cf475fe9df20f773180bd70b0ef2aae00910ba087a1', 'hex');
    const ciphertext = Buffer.from('ace98b99e6803c445b8bb76d937ea1b654fc86ed2e0e11597e52867c25ae96f8', 'hex');

    const iv = Buffer.from('2425b68aac6e6a24', 'hex');
    const dummy = new algorithm.Dummy();


    describe('cipher', () => {

        it('undivided', () => {
            const cipher = new mode.cbc.Cipher(dummy, iv);

            assert(ciphertext.equals(cipher.transform(plaintext)), 'transformed plaintext should be equal to ciphertext');
        });

        it('divided', () => {
            const cipher = new mode.cbc.Cipher(dummy, iv);
            const part = Buffer.concat([
                cipher.transform(plaintext.slice(0, 8)),
                cipher.transform(plaintext.slice(8))
            ]);

            assert(ciphertext.equals(part), 'transformed plaintext should be equal to ciphertext');
        });
        
        describe('throw padding exception', () => {
            
            it('getBlockSize', () => {
                const cipher = new mode.cbc.Cipher(dummy, iv);
                assert.equal(cipher.getBlockSize(), dummy.getBlockSize(), 'cipher.getBlockSize() should equal algorithm.getBlockSize()');
            });
            
            it('transform using 5 bytes', () => {
                const cipher = new mode.cbc.Cipher(dummy, iv);

                assert.throws(() => {
                    cipher.transform(crypto.randomBytes(5));
                }, Error, 'Data size should be aligned to algorithm block size.');

            });
            
            it('transform using 12 bytes', () => {
                const cipher = new mode.cbc.Cipher(dummy, iv);

                assert.throws(() => {
                    cipher.transform(crypto.randomBytes(12));
                }, Error, 'Data size should be aligned to algorithm block size.');

            });
            
        });

    });

    
    describe('decipher', () => {


        it('undivided', () => {
            const decipher = new mode.cbc.Decipher(dummy, iv);

            assert(plaintext.equals(decipher.transform(ciphertext)), 'transformed ciphertext should be equal to plaintext');
        });


        it('divided', () => {
            const decipher = new mode.cbc.Decipher(dummy, iv);
            const part = Buffer.concat([
                decipher.transform(ciphertext.slice(0, 8)),
                decipher.transform(ciphertext.slice(8))
            ]);

            assert(plaintext.equals(part), 'transformed ciphertext should be equal to plaintext');
        });

        
        describe('throw padding exception', () => {
        
            it('getBlockSize', () => {
                const decipher = new mode.cbc.Decipher(dummy, iv);
                assert.equal(decipher.getBlockSize(), dummy.getBlockSize(), 'decipher.getBlockSize() should equal algorithm.getBlockSize()');
            });


            it('transform using 5 bytes', () => {
                const decipher = new mode.cbc.Decipher(dummy, iv);

                assert.throws(() => {
                    decipher.transform(crypto.randomBytes(5));
                }, Error, 'Data size should be aligned to algorithm block size.');
            });


            it('transform using 12 bytes', () => {
                const decipher = new mode.cbc.Decipher(dummy, iv);

                assert.throws(() => {
                    decipher.transform(crypto.randomBytes(12));
                }, Error, 'Data size should be aligned to algorithm block size.');
            });

        });
        
    });

});