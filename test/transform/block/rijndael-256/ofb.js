
const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

(typeof algorithm.Rijndael256 === 'function' && typeof mode.ofb === 'object' ? describe : describe.skip)
('rijndael-256 transform ofb mode', () => {

    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '929cd6fd3f04ce20b8b7c97a89c708826774e5ceac838c87b2' +
        'e471a1290223de9c8012c14cda7180512467d9330b36274362', 'hex');

    const iv = Buffer.from('dd3fbf22dcbe5a10bcd9981afb7bdf8b3dac203e1f1505a9fdab0ba8dc6df011', 'hex');


    const ciphertext = Buffer.from(
        'ff153a96bd8732c263294cea6aa2356499b464c338e8df876e' +
        '5c8985d4f5c759f136f085cb88fe2211591efde2034661720a', 'hex');

    it('should encrypt', () => {
    
        const rijndael = new algorithm.Rijndael256();
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

        const rijndael = new algorithm.Rijndael256();
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

