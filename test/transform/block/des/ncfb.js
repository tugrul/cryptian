
const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

describe('des transform ncfb mode', () => {

    it('should be constructor', () => {
        assert(typeof algorithm.Blowfish === 'function', 'there is no constructor');
    });

    const key = Buffer.alloc(8, 0);

    for (let i = 0; i < 8; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '8da6c3ca04562d87271710110117b81168593eebc783373f23' +
        'c51bd24a44c137400e10f20f42e6d6a132fbb6916a6f428d61', 'hex');

    const iv = Buffer.from('27be68be720b7801', 'hex');



    const ciphertext = Buffer.from(
        '64dd66eee98aef526ce86fdf95fc1368e3e1af3981b7642b57' +
        '98dc3ca6db4ffaca5fd64759bf826351b71ff9a832347ad853', 'hex');

    it('should encrypt', () => {
    
        const des = new algorithm.Des();
                des.setKey(key);

        const cipher = new mode.ncfb.Cipher(des, iv);

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

        const des = new algorithm.Des();
        des.setKey(key);

        const decipher = new mode.ncfb.Decipher(des, iv);

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

