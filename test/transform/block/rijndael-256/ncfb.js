
const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

(typeof algorithm.Rijndael256 === 'function' && typeof mode.ncfb === 'object' ? describe : describe.skip)
('rijndael-256 transform ncfb mode', () => {

    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '4a3d38b469c6bed8c354140713adac0f1d8e82542c4be738ce' +
        '65cdce11e3b2e9310fe7cc74a6c45d044d9436b98a5f99d292', 'hex');

    const iv = Buffer.from('c87422cb2a703f8f8887b2e427fcb7b9650b61d5d07e3b7f056be64b21bdf112', 'hex');


    const ciphertext = Buffer.from(
        '9d8ec1e2c1ff028a2aaa54585dbb765a4c344761b89d8ab123' +
        'b438e178636d68db7d5d28cf98ee770e79e0445844b8588df8', 'hex');

    it('should encrypt', () => {
    
        const rijndael = new algorithm.Rijndael256();
        rijndael.setKey(key);

        const cipher = new mode.ncfb.Cipher(rijndael, iv);

        const transform = createEncryptStream(cipher);
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
        
        const decipher = new mode.ncfb.Decipher(rijndael, iv);

        const transform = createDecryptStream(decipher);
        const buffer = transform.pipe(new streamBuffers.WritableStreamBuffer());

        buffer.on('finish', () => {
            assert(plaintext.equals(buffer.getContents()), 'decrypted ciphertext should be equal to plaintext');
        });

        transform.write(ciphertext.slice(0, 27));
        transform.write(ciphertext.slice(27, 42));
        transform.end(ciphertext.slice(42));
        
    });

    

});

