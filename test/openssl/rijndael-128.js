


const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../..');

const crypto = require('crypto');
    
const assert = require('assert');

const streamBuffers = require('stream-buffers');

(typeof algorithm.Rijndael128 === 'function' ? describe : describe.skip)
('rijndael-128 with openssl aes-128 compat', () => {

    const modes = [
        { name: 'cbc', mode: mode.cbc, openssl: 'aes-128-cbc' },
        { name: 'ecb', mode: mode.ecb, openssl: 'aes-128-ecb', skipIv: true },
        { name: 'cfb', mode: mode.cfb, openssl: 'aes-128-cfb8' },
        { name: 'ncfb', mode: mode.ncfb, openssl: 'aes-128-cfb' },
        { name: 'ctr', mode: mode.ctr, openssl: 'aes-128-ctr' },
        { name: 'ofb', mode: mode.nofb, openssl: 'aes-128-ofb' }
    ];


    modes.forEach(target => {
        
        (typeof target.mode === 'object' ? describe : describe.skip)
        (target.name + ' mode pkcs7 padding', () => {
            
            it('encrypt cryptian to decrypt openssl', () => {
                
                const iv  = target.skipIv ? Buffer.alloc(0) : crypto.randomBytes(16);
                const key = crypto.randomBytes(16);
                const plaintext = crypto.randomBytes(50);
                
                const rijndael = new algorithm.Rijndael128();
                rijndael.setKey(key);
                const cipher = new target.mode.Cipher(rijndael, iv);

                const encryptTransform = createEncryptStream(cipher, padding.Pkcs7);
                const decryptTransform = encryptTransform.pipe(crypto.createDecipheriv(target.openssl, key, iv));
                const buffer           = decryptTransform.pipe(new streamBuffers.WritableStreamBuffer());
                
                buffer.on('finish', () => {
                    assert(plaintext.equals(buffer.getContents()), 'encrypted plaintext should be equal to ciphertext');
                });
                
                encryptTransform.write(plaintext.slice(0, 22));
                encryptTransform.write(plaintext.slice(22, 39));
                encryptTransform.end(plaintext.slice(39));
                
            });

            
            it('encrypt openssl to decrypt cryptian', () => {
                
                const iv  = target.skipIv ? Buffer.alloc(0) : crypto.randomBytes(16);
                const key = crypto.randomBytes(16);
                const plaintext = crypto.randomBytes(50);
                
                const rijndael = new algorithm.Rijndael128();
                rijndael.setKey(key);
                const decipher = new target.mode.Decipher(rijndael, iv);

                const encryptTransform = crypto.createCipheriv(target.openssl, key, iv);
                const decryptTransform = encryptTransform.pipe(createDecryptStream(decipher, padding.Pkcs7));
                const buffer           = decryptTransform.pipe(new streamBuffers.WritableStreamBuffer());
                
                buffer.on('finish', () => {
                    assert(plaintext.equals(buffer.getContents()), 'encrypted plaintext should be equal to ciphertext');
                });
                
                encryptTransform.write(plaintext.slice(0, 22));
                encryptTransform.write(plaintext.slice(22, 39));
                encryptTransform.end(plaintext.slice(39));
                
            });
            
        });

    });
    

});

