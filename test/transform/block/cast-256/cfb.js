
const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

(typeof algorithm.Cast256 === 'function' && typeof mode.cfb === 'object' ? describe : describe.skip)
('cast-256 transform cfb mode', () => {

    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '048dd08e9ca5a25a764fb1bd0ff70ef25fb2c552c0ada08d5e' +
        '4bf58fc1b6887d4e5900f1866ca80a760c7037ae73d5de57f0', 'hex');

    const iv = Buffer.from('930cd343bb1d725d8b01494860ff8561', 'hex');



    const ciphertext = Buffer.from(
        '481ba228dff70534a049d733a213852fe303d1ec10150ae32d' +
        '45a2b9f5acf63f73f46ff0fee1f0bceb7e9893ad7dbf5b2509', 'hex');

    it('should encrypt', () => {
    
        const cast256 = new algorithm.Cast256();
        cast256.setKey(key);

        const cipher = new mode.cfb.Cipher(cast256, iv);

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

        const cast256 = new algorithm.Cast256();
        cast256.setKey(key);
        
        const decipher = new mode.cfb.Decipher(cast256, iv);

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

