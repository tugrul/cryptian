
const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

(typeof algorithm.Saferplus === 'function' && typeof mode.ofb === 'object' ? describe : describe.skip)
('saferplus transform ofb mode', () => {

    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        'b00309e59b69dd31d9fab12740f6b6822c5332c70054e5705b' +
        '3085c5abb4543eeda5baee86d620c853e8aa45cccdba1aa733', 'hex');

    const iv = Buffer.from('d6b5a838fa9b8e54ef7b24266cce62ba', 'hex');



    const ciphertext = Buffer.from(
        '19c028826cb89f8f78cd902f8e9274e12011575ebea9de28b3' +
        '096c71d3d09b6ef5e48736ffafde65466ae8584c1f07d4639f', 'hex');

    it('should encrypt', () => {
    
        const saferplus = new algorithm.Saferplus();
        saferplus.setKey(key);

        const cipher = new mode.ofb.Cipher(saferplus, iv);

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
        
        const decipher = new mode.ofb.Decipher(saferplus, iv);

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

