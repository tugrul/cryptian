


const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

(typeof algorithm.Rijndael256 === 'function' && typeof mode.ecb === 'object' ? describe : describe.skip)
('rijndael-256 transform ecb mode', () => {


    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        'cc5cb97bba4d749b214d4a4702db536a159229e81898633f81' +
        'b718d4b0ae1ba1b3891024c5c6553c1b1e2cae05c7fa835b21', 'hex');

    const iv = Buffer.alloc(0);


    const fixture = [
        {
            title: 'null padding',
            ciphertext: 'b3d70276ce3d8018f2dad026d92616346859aeee3c78a7182243bf37c4a378d7' +
                        '6878832928388bf3e05e82b2ee2d210bce30351ab4c87408fb70a92bf8646cf8',
            padding: padding.Null
        },
        {
            title: 'space padding',
            ciphertext: 'b3d70276ce3d8018f2dad026d92616346859aeee3c78a7182243bf37c4a378d7' +
                        'f2d3f7b0160c379c08bbe8a4536e0a779adf00fb9a0c0182060cd7130c4e9120',
            padding: padding.Space
        },
        {
            title: 'ansi-x923 padding',
            ciphertext: 'b3d70276ce3d8018f2dad026d92616346859aeee3c78a7182243bf37c4a378d7' +
                        '9e278189412d3cd1b8947880513719ea669e151c4605ec8bfb56df51ea9834c6',
            padding: padding.AnsiX923
        },
        {
            title: 'iso-10126 padding',
            ciphertext: 'b3d70276ce3d8018f2dad026d92616346859aeee3c78a7182243bf37c4a378d7' +
                        'b796ddd517c8af9035edf678dc8b5acaea448281477aad7d6b84ae73745b90d4',
            padding: padding.Iso10126,
            skipEncrypt: true // because there are random bytes in padding and not match
        },
        {
            title: 'iso-7816 padding',
            ciphertext: 'b3d70276ce3d8018f2dad026d92616346859aeee3c78a7182243bf37c4a378d7' +
                        '9d66104d28435498971569fb80d11207e77f0d1bcd7c8d898083f067865eb844',
            padding: padding.Iso7816
        },
        {
            title: 'PKCS7 padding',
            ciphertext: 'b3d70276ce3d8018f2dad026d92616346859aeee3c78a7182243bf37c4a378d7' +
                        '7f846489a6a290bdc441d606c3e22775463427db9b241fa04d63671da2fe3fbb',
            padding: padding.Pkcs7
        }
    ];

    fixture.forEach(target => {

        describe(target.title, () => {

            const ciphertext = Buffer.from(target.ciphertext, 'hex');


            (target.skipEncrypt ? xit : it)
            ('should encrypt', () => {
            
                const rijndael = new algorithm.Rijndael256();
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

                const rijndael = new algorithm.Rijndael256();
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
            
            const rijndael = new algorithm.Rijndael256();
            rijndael.setKey(key);

            const cipher = new mode.ecb.Cipher(rijndael, iv);

            assert.throws(() => {
                const transform = createEncryptStream(cipher, padding.Pkcs5);
            }, Error, 'PKCS5 allows only 8 bytes block size');
            
        });
        
        it('should create decrypt stream', () => {
            
            const rijndael = new algorithm.Rijndael256();
            rijndael.setKey(key);

            const decipher = new mode.ecb.Decipher(rijndael, iv);

            assert.throws(() => {
                const transform = createDecryptStream(decipher, padding.Pkcs5);
            }, Error, 'PKCS5 allows only 8 bytes block size');
            
        });
        
    });
    

});

