

const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

describe('des transform ecb mode', () => {

    it('should be constructor', () => {
        assert(typeof algorithm.Blowfish === 'function', 'there is no constructor');
    });


    const key = Buffer.alloc(8, 0);

    for (let i = 0; i < 8; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        'ee589cccaead5766cf0b5898b498bfcbfa95bcc935f39a1b37' +
        '9fe979cf6600cd10e7f45fb931f178f6a6c0213257fb3990b2', 'hex');

    const iv = Buffer.alloc(0);


    const fixture = [
        {
            title: 'null padding',
            ciphertext: '5e6016cf3646c497401c6904e43828516ae53cf86a75cfb173be8562' +
                        '0208c0b4470a6a36542a44168d680ce1f5b068b66d6cdedff270d8fc',
            padding: padding.Null
        },
        {
            title: 'space padding',
            ciphertext: '5e6016cf3646c497401c6904e43828516ae53cf86a75cfb173be8562' +
                        '0208c0b4470a6a36542a44168d680ce1f5b068b6d3bdc085ce55d3e7',
            padding: padding.Space
        },
        {
            title: 'ansi-x923 padding',
            ciphertext: '5e6016cf3646c497401c6904e43828516ae53cf86a75cfb173be8562' +
                        '0208c0b4470a6a36542a44168d680ce1f5b068b601a277c9bc642828',
            padding: padding.AnsiX923
        },
        {
            title: 'iso-10126 padding',
            ciphertext: '5e6016cf3646c497401c6904e43828516ae53cf86a75cfb173be8562' +
                        '0208c0b4470a6a36542a44168d680ce1f5b068b6cc896039da0a146e',
            padding: padding.Iso10126,
            skipEncrypt: true // because there are random bytes in padding and not match
        },
        {
            title: 'iso-7816 padding',
            ciphertext: '5e6016cf3646c497401c6904e43828516ae53cf86a75cfb173be8562' +
                        '0208c0b4470a6a36542a44168d680ce1f5b068b632793ce61b339401',
            padding: padding.Iso7816
        },
        {
            title: 'PKCS5 padding',
            ciphertext: '5e6016cf3646c497401c6904e43828516ae53cf86a75cfb173be8562' +
                        '0208c0b4470a6a36542a44168d680ce1f5b068b62400c88e729c13dc',
            padding: padding.Pkcs5
        },
        {
            title: 'PKCS7 padding',
            ciphertext: '5e6016cf3646c497401c6904e43828516ae53cf86a75cfb173be8562' +
                        '0208c0b4470a6a36542a44168d680ce1f5b068b62400c88e729c13dc',
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

                const cipher = new mode.ecb.Cipher(des, iv);

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
                
                const decipher = new mode.ecb.Decipher(des, iv);

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

