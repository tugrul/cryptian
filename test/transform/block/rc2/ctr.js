
const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

(typeof algorithm.Rc2 === 'function' && typeof mode.ctr === 'object' ? describe : describe.skip)
('RC2 transform ctr mode', () => {

    const key = Buffer.alloc(128, 0);

    for (let i = 0; i < 128; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        'e50eebe2921c25fcb25985165261208999480f52251418d072' +
        '733fee32fc6b910e9cb18282c61ce7789c98cd3d76e964f77c', 'hex');

    const iv = Buffer.from('57dd71c24dbd7836', 'hex');


    const ciphertext = Buffer.from(
        '9c8f4215ade1d6198b75c42721350a6d246e5f6cef1ad3724c' +
        'cf3744b16c3cdbd2a786700a761b8eabba5ccc9a74848ee33e', 'hex');

    it('should encrypt', () => {
    
        const rc2 = new algorithm.Rc2();
        rc2.setKey(key);

        const cipher = new mode.ctr.Cipher(rc2, iv);

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

        const rc2 = new algorithm.Rc2();
        rc2.setKey(key);
        
        const decipher = new mode.ctr.Decipher(rc2, iv);

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

