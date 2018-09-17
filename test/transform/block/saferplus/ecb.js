


const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

(typeof algorithm.Saferplus === 'function' && typeof mode.ecb === 'object' ? describe : describe.skip)
('saferplus transform ecb mode', () => {


    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '3f143f5712644d275202e11214dca9ddd28b1741216bb3a1ee' +
        '25767b44cea971856801bcff1a7826850534d52b123693d1c7', 'hex');

    const iv = Buffer.alloc(0);


    const fixture = [
        {
            title: 'null padding',
            ciphertext: '4decd93cf93d0ce8c689e946cd15247e2485fd947d81dd9389345316d1ce2976' +
                        '4273490435ea2269af56c0c353bb947cc2116b13fadd7468ad056acd5ef9d4df',
            padding: padding.Null
        },
        {
            title: 'space padding',
            ciphertext: '4decd93cf93d0ce8c689e946cd15247e2485fd947d81dd9389345316d1ce2976' +
                        '4273490435ea2269af56c0c353bb947cb17045d2af82011dd8ff0da80d8da230',
            padding: padding.Space
        },
        {
            title: 'ansi-x923 padding',
            ciphertext: '4decd93cf93d0ce8c689e946cd15247e2485fd947d81dd9389345316d1ce2976' +
                        '4273490435ea2269af56c0c353bb947cdb7c409eca2210bf4a5ba996f9375253',
            padding: padding.AnsiX923
        },
        {
            title: 'iso-10126 padding',
            ciphertext: '4decd93cf93d0ce8c689e946cd15247e2485fd947d81dd9389345316d1ce2976' +
                        '4273490435ea2269af56c0c353bb947cf2b1c117b6902e4ae9a65229aa6875d9',
            padding: padding.Iso10126,
            skipEncrypt: true // because there are random bytes in padding and not match
        },
        {
            title: 'iso-7816 padding',
            ciphertext: '4decd93cf93d0ce8c689e946cd15247e2485fd947d81dd9389345316d1ce2976' +
                        '4273490435ea2269af56c0c353bb947c65978e450cc994b2fcd25f5e2e09a490',
            padding: padding.Iso7816
        },
        {
            title: 'PKCS7 padding',
            ciphertext: '4decd93cf93d0ce8c689e946cd15247e2485fd947d81dd9389345316d1ce2976' +
                        '4273490435ea2269af56c0c353bb947cb6c76f5b1abd65716521441e927635bc',
            padding: padding.Pkcs7
        }
    ];

    fixture.forEach(target => {

        describe(target.title, () => {

            const ciphertext = Buffer.from(target.ciphertext, 'hex');


            (target.skipEncrypt ? xit : it)
            ('should encrypt', () => {
            
                const saferplus = new algorithm.Saferplus();
                saferplus.setKey(key);

                const cipher = new mode.ecb.Cipher(saferplus, iv);

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

                const saferplus = new algorithm.Saferplus();
                saferplus.setKey(key);
                
                const decipher = new mode.ecb.Decipher(saferplus, iv);

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
            
            const saferplus = new algorithm.Saferplus();
            saferplus.setKey(key);

            const cipher = new mode.ecb.Cipher(saferplus, iv);
            
            assert.throws(() => {
                const transform = createEncryptStream(cipher, padding.Pkcs5);
            }, Error, 'PKCS5 allows only 8 bytes block size');
            
        });
        
        it('should create decrypt stream', () => {
            
            const saferplus = new algorithm.Saferplus();
            saferplus.setKey(key);

            const decipher = new mode.ecb.Decipher(saferplus, iv);
            
            assert.throws(() => {
                const transform = createDecryptStream(decipher, padding.Pkcs5);
            }, Error, 'PKCS5 allows only 8 bytes block size');
            
        });
        
    });


});

