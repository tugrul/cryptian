

const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

describe('des transform cbc mode', () => {

    it('should be constructor', () => {
        assert(typeof algorithm.Blowfish === 'function', 'there is no constructor');
    });


    const key = Buffer.alloc(8, 0);

    for (let i = 0; i < 8; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '3dae2891af8e6ba9de92ec5a8a0c0127949984605cc96eb125' +
        '8e3fdf0cf2a50bdea7649d908171bacb29b060aaa70c27cde1', 'hex');

    const iv = Buffer.from('ca40f5af0b1aeea2', 'hex');


    const fixture = [
        {
            title: 'null padding',
            ciphertext: '5ac7451e0b00ea8ede24bc224831d99377c4e381bcb3b380cd10553d' +
                        '608669c0cbc4688675d84d26651c047e624384270c8f96f523f0147f',
            padding: padding.Null
        },
        {
            title: 'space padding',
            ciphertext: '5ac7451e0b00ea8ede24bc224831d99377c4e381bcb3b380cd10553d' +
                        '608669c0cbc4688675d84d26651c047e62438427435d69793fe220e4',
            padding: padding.Space
        },
        {
            title: 'ansi-x923 padding',
            ciphertext: '5ac7451e0b00ea8ede24bc224831d99377c4e381bcb3b380cd10553d' +
                        '608669c0cbc4688675d84d26651c047e62438427df8f4b8fa3dff79f',
            padding: padding.AnsiX923
        },
        {
            title: 'iso-10126 padding',
            ciphertext: '5ac7451e0b00ea8ede24bc224831d99377c4e381bcb3b380cd10553d' +
                        '608669c0cbc4688675d84d26651c047e624384279e5c8c1380be49fe',
            padding: padding.Iso10126,
            skipEncrypt: true // because there are random bytes in padding and not match
        },
        {
            title: 'iso-7816 padding',
            ciphertext: '5ac7451e0b00ea8ede24bc224831d99377c4e381bcb3b380cd10553d' +
                        '608669c0cbc4688675d84d26651c047e624384279e3a816503e92574',
            padding: padding.Iso7816
        },
        {
            title: 'PKCS5 padding',
            ciphertext: '5ac7451e0b00ea8ede24bc224831d99377c4e381bcb3b380cd10553d' +
                        '608669c0cbc4688675d84d26651c047e62438427de1786a8c1836aa1',
            padding: padding.Pkcs5
        },
        {
            title: 'PKCS7 padding',
            ciphertext: '5ac7451e0b00ea8ede24bc224831d99377c4e381bcb3b380cd10553d' +
                        '608669c0cbc4688675d84d26651c047e62438427de1786a8c1836aa1',
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
            
                const des = new algorithm.Des();
                des.setKey(key);

                const cipher = new mode.cbc.Cipher(des, iv);

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

                const des = new algorithm.Des();
                des.setKey(key);
                
                const decipher = new mode.cbc.Decipher(des, iv);

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

