
const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

(typeof algorithm.Safer === 'function' && typeof mode.cfb === 'object' ? describe : describe.skip)
('safer-64 transform cfb mode', () => {

    const key = Buffer.alloc(8, 0);

    for (let i = 0; i < 8; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '97555675a2844810cb61dad5e7e745319933ff32de69ad85fa' +
        'baf9b36a858de24f62f5ec42a6c8296cc861169a2122ffeb0c', 'hex');

    const iv = Buffer.from('618181aa2769dbf7', 'hex');



    const ciphertext = Buffer.from(
        'b062231d0f4d492c32de2f9e3ebc1e34f9c4be55bc83d6a4c0' +
        '6c6d93ec761093c629659a8dcf1553fe409818602870fd5e08', 'hex');

    it('should encrypt', () => {
    
        const safer = new algorithm.Safer();
        safer.setKey(key);

        const cipher = new mode.cfb.Cipher(safer, iv);

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

        const decipher = new mode.cfb.Decipher(safer, iv);

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

