


const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

(typeof algorithm.Cast256 === 'function' && typeof mode.ecb === 'object' ? describe : describe.skip)
('cast-256 transform ecb mode', () => {


    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        'b526f95f43eb90120e60789e6ac55775a2cfb005b28d6eeba8' +
        'ce30a31b2a8a60bd8d3e6beea93a6ac3b353b705dd316a49b0', 'hex');

    const iv = Buffer.alloc(0);


    const fixture = [
        {
            title: 'null padding',
            ciphertext: '90aee066ee67a795cbed0a89e3318b64d22b85f5063bf3540c69d652a6e67bf1' +
                        '59b3dfb133ef8844c46988badf3dbfca7d6e3ae581fa94012bf794487a0316ab',
            padding: padding.Null
        },
        {
            title: 'space padding',
            ciphertext: '90aee066ee67a795cbed0a89e3318b64d22b85f5063bf3540c69d652a6e67bf1' +
                        '59b3dfb133ef8844c46988badf3dbfca911cc2d4574b7e6c01c06875b0ebbef1',
            padding: padding.Space
        },
        {
            title: 'ansi-x923 padding',
            ciphertext: '90aee066ee67a795cbed0a89e3318b64d22b85f5063bf3540c69d652a6e67bf1' +
                        '59b3dfb133ef8844c46988badf3dbfca272164833e4f55e32ddb570c9ae45867',
            padding: padding.AnsiX923
        },
        {
            title: 'iso-10126 padding',
            ciphertext: '90aee066ee67a795cbed0a89e3318b64d22b85f5063bf3540c69d652a6e67bf1' +
                        '59b3dfb133ef8844c46988badf3dbfcaf2d40c073cd8a118b110be630dc9434e',
            padding: padding.Iso10126,
            skipEncrypt: true // because there are random bytes in padding and not match
        },
        {
            title: 'iso-7816 padding',
            ciphertext: '90aee066ee67a795cbed0a89e3318b64d22b85f5063bf3540c69d652a6e67bf1' +
                        '59b3dfb133ef8844c46988badf3dbfcab7a5aec31ebeac1551a003d27a1c312b',
            padding: padding.Iso7816
        },
        {
            title: 'PKCS7 padding',
            ciphertext: '90aee066ee67a795cbed0a89e3318b64d22b85f5063bf3540c69d652a6e67bf1' +
                        '59b3dfb133ef8844c46988badf3dbfca027ffc127cb7818f83fb221c799f53b5',
            padding: padding.Pkcs7
        }
    ];

    fixture.forEach(target => {

        describe(target.title, () => {

            const ciphertext = Buffer.from(target.ciphertext, 'hex');


            (target.skipEncrypt ? xit : it)
            ('should encrypt', () => {
            
                const cast256 = new algorithm.Cast256();
                cast256.setKey(key);

                const cipher = new mode.ecb.Cipher(cast256, iv);

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

                const cast256 = new algorithm.Cast256();
                cast256.setKey(key);
                
                const decipher = new mode.ecb.Decipher(cast256, iv);

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
    
    describe('throw exception', () => {
        
        it('should create encrypt stream', () => {
            
            const cast256 = new algorithm.Cast256();
            cast256.setKey(key);

            const cipher = new mode.ecb.Cipher(cast256, iv);
            
            assert.throws(() => {
                const transform = createEncryptStream(cipher, padding.Pkcs5);
            }, Error, 'PKCS5 allows only 8 bytes block size');
            
        });
        
        it('should create decrypt stream', () => {
            
            const cast256 = new algorithm.Cast256();
            cast256.setKey(key);

            const decipher = new mode.ecb.Decipher(cast256, iv);
            
            assert.throws(() => {
                const transform = createDecryptStream(decipher, padding.Pkcs5);
            }, Error, 'PKCS5 allows only 8 bytes block size');
            
        });
        
    });


});

