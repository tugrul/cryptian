



const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

describe('gost transform cbc mode', () => {

    it('should be constructor', () => {
        assert(typeof algorithm.Blowfish === 'function', 'there is no constructor');
    });


    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '5e681299d48b3a20b3172b041e33b461ff342334ca7d7cfa52' +
        '6206067a5fd76fb543c83caf0265b8fc9cfea5f55d0fe19c84', 'hex');

    const iv = Buffer.from('f67137ddbe4640bb', 'hex');


    const fixture = [
        {
            title: 'null padding',
            ciphertext: 'eb953ca4949b47797d93ba2f7db605f449169735256bccf8c3411ba6' +
                        '9b3726bb8cfbe2c67ee6c966d4b618ed2ac423b68c0f126704561b46',
            padding: padding.Null
        },
        {
            title: 'space padding',
            ciphertext: 'eb953ca4949b47797d93ba2f7db605f449169735256bccf8c3411ba6' +
                        '9b3726bb8cfbe2c67ee6c966d4b618ed2ac423b68daece092324ee10',
            padding: padding.Space
        },
        {
            title: 'ansi-x923 padding',
            ciphertext: 'eb953ca4949b47797d93ba2f7db605f449169735256bccf8c3411ba6' +
                        '9b3726bb8cfbe2c67ee6c966d4b618ed2ac423b6b835df4e8c777e60',
            padding: padding.AnsiX923
        },
        {
            title: 'iso-10126 padding',
            ciphertext: 'eb953ca4949b47797d93ba2f7db605f449169735256bccf8c3411ba6' +
                        '9b3726bb8cfbe2c67ee6c966d4b618ed2ac423b6c5c5a8a728cc5f64',
            padding: padding.Iso10126,
            skipEncrypt: true // because there are random bytes in padding and not match
        },
        {
            title: 'iso-7816 padding',
            ciphertext: 'eb953ca4949b47797d93ba2f7db605f449169735256bccf8c3411ba6' +
                        '9b3726bb8cfbe2c67ee6c966d4b618ed2ac423b6302765aa5b40b373',
            padding: padding.Iso7816
        },
        {
            title: 'PKCS5 padding',
            ciphertext: 'eb953ca4949b47797d93ba2f7db605f449169735256bccf8c3411ba6' +
                        '9b3726bb8cfbe2c67ee6c966d4b618ed2ac423b69925bde3b3b8693c',
            padding: padding.Pkcs5
        },
        {
            title: 'PKCS7 padding',
            ciphertext: 'eb953ca4949b47797d93ba2f7db605f449169735256bccf8c3411ba6' +
                        '9b3726bb8cfbe2c67ee6c966d4b618ed2ac423b69925bde3b3b8693c',
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

                const cipher = new mode.cbc.Cipher(gost, iv);

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
                
                const decipher = new mode.cbc.Decipher(gost, iv);

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

