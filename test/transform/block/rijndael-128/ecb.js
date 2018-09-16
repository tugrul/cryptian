


const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

(typeof algorithm.Rijndael128 === 'function' && typeof mode.ecb === 'object' ? describe : describe.skip)
('rijndael-128 transform ecb mode', () => {


    const key = Buffer.alloc(16, 0); 
    key[0] = 1;

    const plaintext = Buffer.from(
        'fd7cf4c594a0c015bb185ae73f2784228fbcc5f987e90b8784' +
        '4f91fbde4313f96a4e4d6da11ceb316cfd06b95ed4ed64da8d', 'hex');

    const iv = Buffer.from('93be555198049a619ba7739c0cda01b8', 'hex');


    const fixture = [
        {
            title: 'null padding',
            ciphertext: 'c792c5d2f49752d2bde3110a83c8908abfdb348927fc69931306e2731f609cc1' +
                        'afbcf49bb095badeed1d0709ab32765c7c5b0b1390e1e884eda44e2624a8887b',
            padding: padding.Null
        },
        {
            title: 'space padding',
            ciphertext: 'c792c5d2f49752d2bde3110a83c8908abfdb348927fc69931306e2731f609cc1' +
                        'afbcf49bb095badeed1d0709ab32765ce13927c8c5bac90bd9fc29385bfdb47a',
            padding: padding.Space
        },
        {
            title: 'ansi-x923 padding',
            ciphertext: 'c792c5d2f49752d2bde3110a83c8908abfdb348927fc69931306e2731f609cc1' +
                        'afbcf49bb095badeed1d0709ab32765cef934f79ea852778a36e0233530ac662',
            padding: padding.AnsiX923
        },
        {
            title: 'iso-10126 padding',
            ciphertext: 'c792c5d2f49752d2bde3110a83c8908abfdb348927fc69931306e2731f609cc1' +
                        'afbcf49bb095badeed1d0709ab32765c19e4ef5f2fa1f7ec9aa50a28a6ce29cc',
            padding: padding.Iso10126,
            skipEncrypt: true // because there are random bytes in padding and not match
        },
        {
            title: 'iso-7816 padding',
            ciphertext: 'c792c5d2f49752d2bde3110a83c8908abfdb348927fc69931306e2731f609cc1' +
                        'afbcf49bb095badeed1d0709ab32765cf23cab7665ea2c0d63d54325491c8227',
            padding: padding.Iso7816
        },
        {
            title: 'PKCS7 padding',
            ciphertext: 'c792c5d2f49752d2bde3110a83c8908abfdb348927fc69931306e2731f609cc1' +
                        'afbcf49bb095badeed1d0709ab32765cb81ec47b7af49fc817dfa072de360e26',
            padding: padding.Pkcs7
        }
    ];

    fixture.forEach(target => {

        describe(target.title, () => {

            const ciphertext = Buffer.from(target.ciphertext, 'hex');


            (target.skipEncrypt ? xit : it)
            ('should encrypt', () => {
            
                const rijndael = new algorithm.Rijndael128();
                rijndael.setKey(key);

                const cipher = new mode.ecb.Cipher(rijndael, iv);

                const transform = createEncryptStream(cipher, target.padding);
                const buffer = transform.pipe(new streamBuffers.WritableStreamBuffer());

                buffer.on('finish', () => {
                    assert(ciphertext.equals(buffer.getContents()), 'encrypted plaintext should be equal to ciphertext');
                });

                transform.write(plaintext.slice(0, 22));
                transform.write(plaintext.slice(22, 39));
                transform.end(plaintext.slice(39));
                
            });

            it('should decrypt', () => {

                const rijndael = new algorithm.Rijndael128();
                rijndael.setKey(key);
                
                const decipher = new mode.ecb.Decipher(rijndael, iv);

                const transform = createDecryptStream(decipher, target.padding);
                const buffer = transform.pipe(new streamBuffers.WritableStreamBuffer());

                buffer.on('finish', () => {
                    assert(plaintext.equals(buffer.getContents()), 'decrypted ciphertext should be equal to plaintext');
                });

                transform.write(ciphertext.slice(0, 27));
                transform.write(ciphertext.slice(27, 42));
                transform.end(ciphertext.slice(42));
                
            });
        
        });

    });
    
    describe('PKCS5 throw exception', () => {
        
        it('should create encrypt stream', () => {
            
            const rijndael = new algorithm.Rijndael128();
            rijndael.setKey(key);

            const cipher = new mode.ecb.Cipher(rijndael, iv);

            assert.throws(() => {
                const transform = createEncryptStream(cipher, padding.Pkcs5);
            }, Error, 'PKCS5 allows only 8 bytes block size');
            
        });
        
        it('should create decrypt stream', () => {
            
            const rijndael = new algorithm.Rijndael128();
            rijndael.setKey(key);

            const decipher = new mode.ecb.Decipher(rijndael, iv);

            assert.throws(() => {
                const transform = createDecryptStream(decipher, padding.Pkcs5);
            }, Error, 'PKCS5 allows only 8 bytes block size');
            
        });
        
    });
    

});

