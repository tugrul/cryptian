
const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

(typeof algorithm.Safer === 'function' && typeof mode.ctr === 'object' ? describe : describe.skip)
('safer-64 transform ctr mode', () => {

    const key = Buffer.alloc(8, 0);

    for (let i = 0; i < 8; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '1696bfa0a4736d395c9a3b0b0d20f753efd1070624ebbf4076' +
        '78100f6a57ea91bb48c932bc448a4548a297f9d34e8e84bd6e', 'hex');

    const iv = Buffer.from('222cab9dc7597739', 'hex');



    const ciphertext = Buffer.from(
        '5a14569a9f60b06798dce8ea722be54971795f730c66413f93' +
        'fb69e4ed8317d487a453bba611fad49eca5f72be6f4b263ba7', 'hex');

    it('should encrypt', () => {
    
        const safer = new algorithm.Safer();
        safer.setKey(key);

        const cipher = new mode.ctr.Cipher(safer, iv);

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

        const safer = new algorithm.Safer();
        safer.setKey(key);

        const decipher = new mode.ctr.Decipher(safer, iv);

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

