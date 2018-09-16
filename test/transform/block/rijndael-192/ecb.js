


const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

(typeof algorithm.Rijndael192 === 'function' && typeof mode.ecb === 'object' ? describe : describe.skip)
('rijndael-192 transform ecb mode', () => {


    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '96055b31ef6b8835dc356fe77dcec2246993176ff04c040a11' +
        'ab065650b7d2591a7df83875c9f29188760f4257b8e7cc34a9', 'hex');

    const iv = Buffer.alloc(0);


    const fixture = [
        {
            title: 'null padding',
            ciphertext: 'acf60d9589f1d3f83f81d879ce3f0733d41804493f6d0cdbbcd2a311a0a0bc58193a8ee4' +
                        'f620ca6423f3d7209e2faa8c84649051602bb199fa3a9c4d47e908fbe3dd5f30d837cfad',
            padding: padding.Null
        },
        {
            title: 'space padding',
            ciphertext: 'acf60d9589f1d3f83f81d879ce3f0733d41804493f6d0cdbbcd2a311a0a0bc58193a8ee4' +
                        'f620ca6423f3d7209e2faa8cf71a24870c4cf96d5e5e02982e1e4688ec4f6bd65441d7f2',
            padding: padding.Space
        },
        {
            title: 'ansi-x923 padding',
            ciphertext: 'acf60d9589f1d3f83f81d879ce3f0733d41804493f6d0cdbbcd2a311a0a0bc58193a8ee4' +
                        'f620ca6423f3d7209e2faa8c200d4e67019d9bfd55c81aa1e0ae6e6d7bdc38ca92f868ad',
            padding: padding.AnsiX923
        },
        {
            title: 'iso-10126 padding',
            ciphertext: 'acf60d9589f1d3f83f81d879ce3f0733d41804493f6d0cdbbcd2a311a0a0bc58193a8ee4' +
                        'f620ca6423f3d7209e2faa8cc37cc3f6af48fe50196d8186a4de1fd974c68e8818380484',
            padding: padding.Iso10126,
            skipEncrypt: true // because there are random bytes in padding and not match
        },
        {
            title: 'iso-7816 padding',
            ciphertext: 'acf60d9589f1d3f83f81d879ce3f0733d41804493f6d0cdbbcd2a311a0a0bc58193a8ee4' +
                        'f620ca6423f3d7209e2faa8c59bc4e25dbb107a759c453da8d5314395476b220d813607f',
            padding: padding.Iso7816
        },
        {
            title: 'PKCS7 padding',
            ciphertext: 'acf60d9589f1d3f83f81d879ce3f0733d41804493f6d0cdbbcd2a311a0a0bc58193a8ee4' +
                        'f620ca6423f3d7209e2faa8ca7bc4a1266fe73df70341c8d9e93515ac4e57ce357eb2e0a',
            padding: padding.Pkcs7
        }
    ];

    fixture.forEach(target => {

        describe(target.title, () => {

            const ciphertext = Buffer.from(target.ciphertext, 'hex');


            (target.skipEncrypt ? xit : it)
            ('should encrypt', () => {
            
                const rijndael = new algorithm.Rijndael192();
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

                const rijndael = new algorithm.Rijndael192();
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
            
            const rijndael = new algorithm.Rijndael192();
            rijndael.setKey(key);

            const cipher = new mode.ecb.Cipher(rijndael, iv);

            assert.throws(() => {
                const transform = createEncryptStream(cipher, padding.Pkcs5);
            }, Error, 'PKCS5 allows only 8 bytes block size');
            
        });
        
        it('should create decrypt stream', () => {
            
            const rijndael = new algorithm.Rijndael192();
            rijndael.setKey(key);

            const decipher = new mode.ecb.Decipher(rijndael, iv);

            assert.throws(() => {
                const transform = createDecryptStream(decipher, padding.Pkcs5);
            }, Error, 'PKCS5 allows only 8 bytes block size');
            
        });
        
    });
    

});

