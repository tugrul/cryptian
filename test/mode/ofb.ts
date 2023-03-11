
import assert from 'assert';
import cryptian from '../..';

const {algorithm: {Dummy}, mode: {ofb}} = cryptian;


(typeof ofb === 'object' ? describe : describe.skip) ('ofb', () => {

    // ace98b99e6803c44d3d4909e5152b9d6bf7b4582bd70b0ef0aae00910ba087a1

    const plaintext  = Buffer.from('88cc3d134aee5660f7623cf475fe9df20f773180bd70b0ef2aae00910ba087a1', 'hex');
    const ciphertext = Buffer.from('ace98b99e6803c44d3478a7ed990f7d62b52870a111edacb0e8bb61ba7ceed85', 'hex');

    const iv = Buffer.from('2425b68aac6e6a24', 'hex');
    const dummy = new Dummy();

    describe('cipher', () => {
        
        it('getBlockSize', () => {
            const cipher = new ofb.Cipher(dummy, iv);

            assert.equal(cipher.getBlockSize(), dummy.getBlockSize(), 'cipher.getBlockSize() should equal algorithm.getBlockSize()');
        });
        
        it('undivided', () => {
            const cipher = new ofb.Cipher(dummy, iv);

            assert(ciphertext.equals(cipher.transform(plaintext)), 'transformed plaintext should be equal to ciphertext');
        });
        
        it('size 5', () => {
            const cipher = new ofb.Cipher(dummy, iv);

            assert(ciphertext.slice(0, 5).equals(cipher.transform(plaintext.slice(0, 5))), 'transformed plaintext should be equal to ciphertext');
        });
        
        it('size 13', () => {
            const cipher = new ofb.Cipher(dummy, iv);

            assert(ciphertext.slice(0, 13).equals(cipher.transform(plaintext.slice(0, 13))), 'transformed plaintext should be equal to ciphertext');
        });
        
        it('divided 5', () => {
            const cipher = new ofb.Cipher(dummy, iv);

            const part = Buffer.concat([
                cipher.transform(plaintext.slice(0, 5)),
                cipher.transform(plaintext.slice(5))
            ]);

            assert(ciphertext.equals(part), 'transformed plaintext should be equal to ciphertext');
        });
        
        it('divided 13', () => {
            const cipher = new ofb.Cipher(dummy, iv);

            const part = Buffer.concat([
                cipher.transform(plaintext.slice(0, 13)),
                cipher.transform(plaintext.slice(13, 26)),
                cipher.transform(plaintext.slice(26)),
            ]);

            assert(ciphertext.equals(part), 'transformed plaintext should be equal to ciphertext');
        });
        
    });

    describe('decipher', () => {

        it('getBlockSize', () => {
            const decipher = new ofb.Decipher(dummy, iv);

            assert.equal(decipher.getBlockSize(), dummy.getBlockSize(), 'decipher.getBlockSize() should equal algorithm.getBlockSize()');
        });

        it('undivided', () => {
            const decipher = new ofb.Decipher(dummy, iv);

            assert(plaintext.equals(decipher.transform(ciphertext)), 'transformed ciphertext should be equal to plaintext');
        });

        it('size 5', () => {
            const decipher = new ofb.Decipher(dummy, iv);

            assert(plaintext.slice(0, 5).equals(decipher.transform(ciphertext.slice(0, 5))), 'transformed plaintext should be equal to ciphertext');
        });

        it('size 13', () => {
            const decipher = new ofb.Decipher(dummy, iv);

            assert(plaintext.slice(0, 13).equals(decipher.transform(ciphertext.slice(0, 13))), 'transformed plaintext should be equal to ciphertext');
        });

        it('divided 5', () => {
            const decipher = new ofb.Decipher(dummy, iv);

            const part = Buffer.concat([
                decipher.transform(ciphertext.slice(0, 5)),
                decipher.transform(ciphertext.slice(5))
            ]);

            assert(plaintext.equals(part), 'transformed ciphertext should be equal to plaintext');
        });

        it('divided 13', () => {
            const decipher = new ofb.Decipher(dummy, iv);

            const part = Buffer.concat([
                decipher.transform(ciphertext.slice(0, 13)),
                decipher.transform(ciphertext.slice(13, 26)),
                decipher.transform(ciphertext.slice(26)),
            ]);

            assert(plaintext.equals(part), 'transformed ciphertext should be equal to plaintext');
        });


    });


});
