
const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

(typeof algorithm.Rijndael256 === 'function' && typeof mode.nofb === 'object' ? describe : describe.skip)
('rijndael-256 transform nofb mode', () => {

    const key = Buffer.alloc(32, 0);

    for (let i = 0; i < 32; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = Buffer.from(
        '0404bbe9986f9564e561d8738a64cb44d29e32cdb7a382de8e' +
        'd4974cc27bce505101a31d975cfc3b1d74adfe49e22851fe64', 'hex');

    const iv = Buffer.from('7821c3ae6768fe99253e1c99ecea8c451da4376cba204208e61ea8533c0327c1', 'hex');


    const ciphertext = Buffer.from(
        '9822558b7e3b8f375fc2d03889814e716dc698c3118517d1e3' +
        '81402b614e7e3e5a30d1db6c733485d3766d61964c48afa02a', 'hex');

    it('should encrypt', () => {
    
        const rijndael = new algorithm.Rijndael256();
        rijndael.setKey(key);

        const cipher = new mode.nofb.Cipher(rijndael, iv);

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
        
        const decipher = new mode.nofb.Decipher(rijndael, iv);

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

