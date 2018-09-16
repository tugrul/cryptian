
const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

(typeof algorithm.Cast256 === 'function' && typeof mode.ctr === 'object' ? describe : describe.skip)
('cast-256 transform ctr mode', () => {


    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        'a8ecb62a06caae4025e5ce38d63c54cdd030b4be63ccf640c9' +
        '691a61edbc430161c3ce116d687076d5cd9b036d33d9d13fc2', 'hex');

    const iv = Buffer.from('5cf6486adc339117950ecbee3a084db8', 'hex');



    const ciphertext = Buffer.from(
        '3b0eed6cb8f34eef86076bff91c621eaa38384def23a7d7af0' +
        'aaca98a2284c2fe91f97dbc7766d0cd6f277642f85eae2f2b0', 'hex');

    it('should encrypt', () => {
    
        const cast256 = new algorithm.Cast256();
        cast256.setKey(key);

        const cipher = new mode.ctr.Cipher(cast256, iv);

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
        
        const decipher = new mode.ctr.Decipher(cast256, iv);

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

