
const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

(typeof algorithm.Rijndael256 === 'function' && typeof mode.cfb === 'object' ? describe : describe.skip)
('rijndael-256 transform cfb mode', () => {

    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '6dc72656101a95d38451f61e009ad1abfd8fac36dad3ab9073' +
        '1bec1e2fcb9029a39084a95a600313815d600c381f702b40d4', 'hex');

    const iv = Buffer.from('6c0b05beabaa6a091ef7b2f4213d67d0cffdaf2f694e3356b8c7d3ce92301806', 'hex');


    const ciphertext = Buffer.from(
        'a26635deb880c93ea970951256d162ba72ee159ec349405e75' +
        '55d3f73f5fadda1cb57ebb09c83d75337a98a22451da194c41', 'hex');

    it('should encrypt', () => {
    
        const rijndael = new algorithm.Rijndael256();
        rijndael.setKey(key);

        const cipher = new mode.cfb.Cipher(rijndael, iv);

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
        
        const decipher = new mode.cfb.Decipher(rijndael, iv);

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

