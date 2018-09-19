


const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../..');

const crypto = require('crypto');
    
const assert = require('assert');

const streamBuffers = require('stream-buffers');

(typeof algorithm.Des === 'function' ? describe : describe.skip)
('des with openssl des compat', () => {

    const modes = [
        { name: 'cbc', mode: mode.cbc,  openssl: 'des-cbc' },
        { name: 'ecb', mode: mode.ecb,  openssl: 'des-ecb', skipIv: true },
        { name: 'cfb', mode: mode.cfb,  openssl: 'des-cfb8' },
        { name: 'ncfb', mode: mode.ncfb,  openssl: 'des-cfb' },
        { name: 'ofb', mode: mode.nofb, openssl: 'des-ofb' }
    ];


    modes.forEach(target => {
        
        (typeof target.mode === 'object' ? describe : describe.skip)
        (target.name + ' mode pkcs7 padding', () => {
            
            it('encrypt cryptian to decrypt openssl', () => {
                
                const iv  = target.skipIv ? Buffer.alloc(0) : crypto.randomBytes(8);
                const key = crypto.randomBytes(8);
                const plaintext = crypto.randomBytes(50);
                
                const des = new algorithm.Des();
                des.setKey(key);
                const cipher = new target.mode.Cipher(des, iv);

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
                
                const iv  = target.skipIv ? Buffer.alloc(0) : crypto.randomBytes(8);
                const key = crypto.randomBytes(8);
                const plaintext = crypto.randomBytes(50);
                
                const des = new algorithm.Des();
                des.setKey(key);
                const decipher = new target.mode.Decipher(des, iv);

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

