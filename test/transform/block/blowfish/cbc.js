
const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

describe('blowfish transform cbc mode', () => {

    it('should be constructor', () => {
        assert(typeof algorithm.Blowfish === 'function', 'there is no constructor');
    });


    const key = new Buffer(56);

    for (let i = 0; i < 56; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = new Buffer(
        'd7944f4102aced25534ed06b413cc5763fc53199fd6ff2fcc2' +
        '5d7d7c476d0257aca394c1693645f85f84ce8a238fb3955372', 'hex');

    const iv = new Buffer('e3343cad08296fdc', 'hex');

    describe('standard', () => {

        describe('null padding', () => {
    
            const ciphertext = new Buffer(
                '8c0585fe8fd31056b6984bfbb0c9154b4305c38302f5e12716a9e042' +
                'd7b75f21e1f5963d0eb649dd32f29e0e1e21981bfe75f97bfb50f6a6', 'hex');

            it('should do encrypt and decrypt operations', () => {

                describe('encrypt', () => {
                    
                    const blowfish = new algorithm.Blowfish();
                    blowfish.setKey(key);

                    const cipher = new mode.cbc.Cipher(blowfish, iv);

                    const transform = createEncryptStream(cipher, padding.Null);
                    const buffer = transform.pipe(new streamBuffers.WritableStreamBuffer());

                    buffer.on('finish', () => {
                        assert(ciphertext.equals(buffer.getContents()), 'encrypted plaintext should be equal to ciphertext');
                    });

                    transform.write(plaintext.slice(0, 22));
                    transform.write(plaintext.slice(22, 39));
                    transform.end(plaintext.slice(39));
                    
                });

                describe('decrypt', () => {

                    const blowfish = new algorithm.Blowfish();
                    blowfish.setKey(key);
                    
                    const decipher = new mode.cbc.Decipher(blowfish, iv);

                    const transform = createDecryptStream(decipher, padding.Null);
                    const buffer = transform.pipe(new streamBuffers.WritableStreamBuffer());

                    buffer.on('finish', () => {
                        assert(plaintext.equals(buffer.getContents()), 'decrypted ciphertext should be equal to plaintext');
                    });

                    transform.write(ciphertext.slice(0, 27));
                    transform.write(ciphertext.slice(27, 42));
                    transform.end(ciphertext.slice(42));
                    
                });

            });
        
        });
        

    });


});

