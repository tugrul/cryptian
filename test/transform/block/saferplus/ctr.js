
const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

(typeof algorithm.Saferplus === 'function' && typeof mode.ctr === 'object' ? describe : describe.skip)
('saferplus transform ctr mode', () => {

    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        'add25a478b3d5d47bf807026f8fb8c2b717c197b676e23b419' +
        'a5ea0a9f1d598cd44204e5aa97e9699c4bf71a331263cd3c41', 'hex');

    const iv = Buffer.from('60d81554b186db779e25198a53d65adf', 'hex');



    const ciphertext = Buffer.from(
        'af5072d144e55517708c7067d0c778045a1a3c1978f33c8e61' +
        'd79d81b9206d64f69e53684a9051c63ca91141c5bd61307550', 'hex');

    it('should encrypt', () => {
    
        const saferplus = new algorithm.Saferplus();
        saferplus.setKey(key);

        const cipher = new mode.ctr.Cipher(saferplus, iv);

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

        const saferplus = new algorithm.Saferplus();
        saferplus.setKey(key);
        
        const decipher = new mode.ctr.Decipher(saferplus, iv);

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

