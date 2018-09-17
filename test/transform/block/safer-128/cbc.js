


const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

(typeof algorithm.Safer === 'function' && typeof mode.cbc === 'object' ? describe : describe.skip)
('safer-128 transform cbc mode', () => {

    const key = Buffer.alloc(16, 0);

    for (let i = 0; i < 16; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        'aae6968a24fc0b376990e3ca826e39fe242e9641176daffd5b' +
        '65bbb552989a884ee69719335b3de1a54cc05136f433cc1d6a', 'hex');

    const iv = Buffer.from('27e4f1d57a36c8f4', 'hex');


    const fixture = [
        {
            title: 'null padding',
            ciphertext: 'd2952e9251a530edcc9b262c954a310d1e6058269cbde0c497440559' +
                        '66169cfda5100c33a1ba45626ee0a442ad530ecbe25aa7ee516fcf7d',
            padding: padding.Null
        },
        {
            title: 'space padding',
            ciphertext: 'd2952e9251a530edcc9b262c954a310d1e6058269cbde0c497440559' +
                        '66169cfda5100c33a1ba45626ee0a442ad530ecb4ae9f581ada19cd2',
            padding: padding.Space
        },
        {
            title: 'ansi-x923 padding',
            ciphertext: 'd2952e9251a530edcc9b262c954a310d1e6058269cbde0c497440559' +
                        '66169cfda5100c33a1ba45626ee0a442ad530ecb29a52d35507252ea',
            padding: padding.AnsiX923
        },
        {
            title: 'iso-10126 padding',
            ciphertext: 'd2952e9251a530edcc9b262c954a310d1e6058269cbde0c497440559' +
                        '66169cfda5100c33a1ba45626ee0a442ad530ecbfa91ca981d8d2600',
            padding: padding.Iso10126,
            skipEncrypt: true // because there are random bytes in padding and not match
        },
        {
            title: 'iso-7816 padding',
            ciphertext: 'd2952e9251a530edcc9b262c954a310d1e6058269cbde0c497440559' +
                        '66169cfda5100c33a1ba45626ee0a442ad530ecbfe65ccdb307741a3',
            padding: padding.Iso7816
        },
        {
            title: 'PKCS5 padding',
            ciphertext: 'd2952e9251a530edcc9b262c954a310d1e6058269cbde0c497440559' +
                        '66169cfda5100c33a1ba45626ee0a442ad530ecbe9857ff835d68acd',
            padding: padding.Pkcs5
        },
        {
            title: 'PKCS7 padding',
            ciphertext: 'd2952e9251a530edcc9b262c954a310d1e6058269cbde0c497440559' +
                        '66169cfda5100c33a1ba45626ee0a442ad530ecbe9857ff835d68acd',
            padding: padding.Pkcs7
        }
    ];

    fixture.forEach(target => {

        describe(target.title, () => {

            const ciphertext = Buffer.from(target.ciphertext, 'hex');


            (target.skipEncrypt ? xit : it)
            ('should encrypt', () => {
            
                const safer = new algorithm.Safer();
                safer.setKey(key);

                const cipher = new mode.cbc.Cipher(safer, iv);

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

                const safer = new algorithm.Safer();
                safer.setKey(key);
                
                const decipher = new mode.cbc.Decipher(safer, iv);

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

