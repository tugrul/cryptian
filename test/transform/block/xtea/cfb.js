
const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

(typeof algorithm.Xtea === 'function' && typeof mode.cfb === 'object' ? describe : describe.skip)
('xtea transform cfb mode', () => {

    const key = Buffer.alloc(16, 0);

    for (let i = 0; i < 16; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        'a252c70d1c94ed6cf3a4399547b9f086c61c3306a880e95a32' +
        '9971b504fd04a3d7354fe489f26aa672c1d42267bd03600642', 'hex');

    const iv = Buffer.from('d38680a3b76ba96d', 'hex');



    const ciphertext = Buffer.from(
        '24839a06fb0544702ab6f928517081164d584e70a7c486c8dd' +
        '1e554c725abd509cfa8a6718156a96abef9708a53a12df597e', 'hex');

    it('should encrypt', () => {
    
        const xtea = new algorithm.Xtea();
        xtea.setKey(key);

        const cipher = new mode.cfb.Cipher(xtea, iv);

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

        const xtea = new algorithm.Xtea();
        xtea.setKey(key);

        const decipher = new mode.cfb.Decipher(xtea, iv);

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

