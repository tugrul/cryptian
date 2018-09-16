
const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

(typeof algorithm.Rijndael128 === 'function' && typeof mode.ofb === 'object' ? describe : describe.skip)
('rijndael-128 transform ofb mode', () => {

    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '41b899183383c2851e24fe3b6ce927bb84101aeafb33e25376' +
        '5bd8b73090e9304355b64a8a231ca8ed8e7227dd2eb295b58a', 'hex');

    const iv = Buffer.from('f8228721cecc1007373816dd018076f5', 'hex');


    const ciphertext = Buffer.from(
        'acfdc45b484dd13aea5595146a1361b1c87fbf5a1ebc345bf0' +
        'a7528f8fdd9b19ac5689ee1f8ceaec73c6429ed9eb0172fc60', 'hex');

    it('should encrypt', () => {
    
        const rijndael = new algorithm.Rijndael128();
        rijndael.setKey(key);

        const cipher = new mode.ofb.Cipher(rijndael, iv);

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
        
        const decipher = new mode.ofb.Decipher(rijndael, iv);

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

