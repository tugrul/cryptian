
const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

(typeof algorithm.Tripledes === 'function' && typeof mode.cfb === 'object' ? describe : describe.skip)
('tripledes transform cfb mode', () => {

    const key = Buffer.alloc(24, 0);

    for (let i = 0; i < 24; i++) {
        key[i] = i % 256;
    }

    const plaintext = Buffer.from(
        '66cb22bf111ee0938d46b6644a0e0e7fd27d45d1c03fdc830d' +
        '73aabd5c998ecd277277fbc449557b56ae1ffb45da50b156e3', 'hex');

    const iv = Buffer.from('d926794463d805b4', 'hex');



    const ciphertext = Buffer.from(
        '6c2849dfaaa59c4907a33ba455af1f8e500783ef2a75eebc95' +
        'eeb39ac1903d37d164785d67fd7bd531c2bf7870ad1fa4b569', 'hex');

    it('should encrypt', () => {
    
        const tripledes = new algorithm.Tripledes();
        tripledes.setKey(key);

        const cipher = new mode.cfb.Cipher(tripledes, iv);

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

        const tripledes = new algorithm.Tripledes();
        tripledes.setKey(key);

        const decipher = new mode.cfb.Decipher(tripledes, iv);

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

