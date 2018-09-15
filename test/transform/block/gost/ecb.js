

const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

describe('gost transform ecb mode', () => {

    it('should be constructor', () => {
        assert(typeof algorithm.Blowfish === 'function', 'there is no constructor');
    });


    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        'c0790510ed07deff6ad217428ccbfa7d39eec02247812e0ca9' +
        '87e67eb0e03e7ef175f117fbe59491bb52075449fa64b2365c', 'hex');

    const iv = Buffer.alloc(0);


    const fixture = [
        {
            title: 'null padding',
            ciphertext: 'ef2effe1a6f57f886b1374b9f5b992f35b41362312789aa48afaa63b' +
                        '047de46fb1ce2a9e572702d17fd947726012379cdb025627cd50a4d1',
            padding: padding.Null
        },
        {
            title: 'space padding',
            ciphertext: 'ef2effe1a6f57f886b1374b9f5b992f35b41362312789aa48afaa63b' +
                        '047de46fb1ce2a9e572702d17fd947726012379cf91da743ea6f4f11',
            padding: padding.Space
        },
        {
            title: 'ansi-x923 padding',
            ciphertext: 'ef2effe1a6f57f886b1374b9f5b992f35b41362312789aa48afaa63b' +
                        '047de46fb1ce2a9e572702d17fd947726012379c066e93b434dcdfdd',
            padding: padding.AnsiX923
        },
        {
            title: 'iso-10126 padding',
            ciphertext: 'ef2effe1a6f57f886b1374b9f5b992f35b41362312789aa48afaa63b' +
                        '047de46fb1ce2a9e572702d17fd947726012379c73fcf1ba7a58eff0',
            padding: padding.Iso10126,
            skipEncrypt: true // because there are random bytes in padding and not match
        },
        {
            title: 'iso-7816 padding',
            ciphertext: 'ef2effe1a6f57f886b1374b9f5b992f35b41362312789aa48afaa63b' +
                        '047de46fb1ce2a9e572702d17fd947726012379cbf250651b7c1e7a0',
            padding: padding.Iso7816
        },
        {
            title: 'PKCS5 padding',
            ciphertext: 'ef2effe1a6f57f886b1374b9f5b992f35b41362312789aa48afaa63b' +
                        '047de46fb1ce2a9e572702d17fd947726012379c51a8ce17f6109e70',
            padding: padding.Pkcs5
        },
        {
            title: 'PKCS7 padding',
            ciphertext: 'ef2effe1a6f57f886b1374b9f5b992f35b41362312789aa48afaa63b' +
                        '047de46fb1ce2a9e572702d17fd947726012379c51a8ce17f6109e70',
            padding: padding.Pkcs7
        }
    ];

    fixture.forEach(target => {

        describe(target.title, () => {

            const ciphertext = Buffer.from(target.ciphertext, 'hex');


            it('should encrypt', () => {
            
                if (target.skipEncrypt) {
                    return;
                }
            
                const gost = new algorithm.Gost();
                gost.setKey(key);

                const cipher = new mode.ecb.Cipher(gost, iv);

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

                const gost = new algorithm.Gost();
                gost.setKey(key);
                
                const decipher = new mode.ecb.Decipher(gost, iv);

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


});

