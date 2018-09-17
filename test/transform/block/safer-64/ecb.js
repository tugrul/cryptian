


const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

(typeof algorithm.Safer === 'function' && typeof mode.ecb === 'object' ? describe : describe.skip)
('safer-64 transform ecb mode', () => {

    const key = Buffer.alloc(8, 0);

    for (let i = 0; i < 8; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '07b2860fc0bf86aef063ce651412a541f5f108606093443507' +
        '872b2e6e1da25f8c117d45269f5471008898fdb724f67baff2', 'hex');

    const iv = Buffer.alloc(0);


    const fixture = [
        {
            title: 'null padding',
            ciphertext: '714d9ec323c2da393c62013fc995795b8d2219f4b59e3a86085c1e9e' +
                        'eb3aa26047eff821a254dea26dbd0c511d8434d3e85c22763dadc5ce',
            padding: padding.Null
        },
        {
            title: 'space padding',
            ciphertext: '714d9ec323c2da393c62013fc995795b8d2219f4b59e3a86085c1e9e' +
                        'eb3aa26047eff821a254dea26dbd0c511d8434d360ba672fb91f84ee',
            padding: padding.Space
        },
        {
            title: 'ansi-x923 padding',
            ciphertext: '714d9ec323c2da393c62013fc995795b8d2219f4b59e3a86085c1e9e' +
                        'eb3aa26047eff821a254dea26dbd0c511d8434d3dd6692358e283776',
            padding: padding.AnsiX923
        },
        {
            title: 'iso-10126 padding',
            ciphertext: '714d9ec323c2da393c62013fc995795b8d2219f4b59e3a86085c1e9e' +
                        'eb3aa26047eff821a254dea26dbd0c511d8434d371ba7097121e0408',
            padding: padding.Iso10126,
            skipEncrypt: true // because there are random bytes in padding and not match
        },
        {
            title: 'iso-7816 padding',
            ciphertext: '714d9ec323c2da393c62013fc995795b8d2219f4b59e3a86085c1e9e' +
                        'eb3aa26047eff821a254dea26dbd0c511d8434d304d4b304c4358744',
            padding: padding.Iso7816
        },
        {
            title: 'PKCS5 padding',
            ciphertext: '714d9ec323c2da393c62013fc995795b8d2219f4b59e3a86085c1e9e' +
                        'eb3aa26047eff821a254dea26dbd0c511d8434d318b41669df8bb66d',
            padding: padding.Pkcs5
        },
        {
            title: 'PKCS7 padding',
            ciphertext: '714d9ec323c2da393c62013fc995795b8d2219f4b59e3a86085c1e9e' +
                        'eb3aa26047eff821a254dea26dbd0c511d8434d318b41669df8bb66d',
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

                const cipher = new mode.ecb.Cipher(safer, iv);

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
                
                const decipher = new mode.ecb.Decipher(safer, iv);

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

