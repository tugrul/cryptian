

const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

(typeof algorithm.Loki97 === 'function' && typeof mode.cfb === 'object' ? describe : describe.skip)
('loki97 transform cfb mode', () => {


    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        'bf269071c86f7a359793d4e5c04404e22021c3be9aff527352' +
        'd02d0b698bf7f04362ab84187cfbaca0c3fae2f168bf921e98', 'hex');

    const iv = Buffer.from('ee4142a9aeaf2a6ec37e1178577e556f', 'hex');


    const ciphertext = Buffer.from(
        '94a69301e59afc5935f72aa92499027067b4cafdce8f53ad2a' +
        '68515bef09ae314eb745fdce6c9f5ac2f2a0a29cb86fa2b79b', 'hex');

    it('should encrypt', () => {
    
        const loki97 = new algorithm.Loki97();
        loki97.setKey(key);

        const cipher = new mode.cfb.Cipher(loki97, iv);

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

        const loki97 = new algorithm.Loki97();
        loki97.setKey(key);
        
        const decipher = new mode.cfb.Decipher(loki97, iv);

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

