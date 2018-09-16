
const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

(typeof algorithm.Rijndael128 === 'function' && typeof mode.cfb === 'object' ? describe : describe.skip)
('rijndael-128 transform cfb mode', () => {

    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '3845eac891895b9d33ad47ada34bdf4edfaaa19ccf3ed88f29' +
        '7d5f03121f2755a9bc3bf41e3facf365512b78758cd1a25ae1', 'hex');

    const iv = Buffer.from('feb52c1ffff052b6382d58aaebf2dcee', 'hex');



    const ciphertext = Buffer.from(
        '0723946109a3e9aaf9faf0db4eb56fb44fc264b7ff160e743c' +
        'd9b1349e0b1d880296a49bf1efe394085cddf3cf46a2f4a1df', 'hex');

    it('should encrypt', () => {
    
        const rijndael = new algorithm.Rijndael128();
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

        const rijndael = new algorithm.Rijndael128();
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

