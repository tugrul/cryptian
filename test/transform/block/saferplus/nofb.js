
const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

(typeof algorithm.Saferplus === 'function' && typeof mode.nofb === 'object' ? describe : describe.skip)
('saferplus transform nofb mode', () => {

    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        'e2983c58fa0bbe006e2d890d98f9fd0ecfe98eff9759dc7179' +
        '5cb66cf7d77252e589d7d7f55e512daf1b3cf29735c05feda5', 'hex');

    const iv = Buffer.from('428533eef1f2b03ee43dad828574abbc', 'hex');



    const ciphertext = Buffer.from(
        'da7477c1b1f5158b235942f44439af8ae43fdecc57332db81d' +
        '9de2ab5274493f5dfab73a2ca1eb5d3a21922f9741565f966f', 'hex');

    it('should encrypt', () => {
    
        const saferplus = new algorithm.Saferplus();
        saferplus.setKey(key);

        const cipher = new mode.nofb.Cipher(saferplus, iv);

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
        
        const decipher = new mode.nofb.Decipher(saferplus, iv);

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

