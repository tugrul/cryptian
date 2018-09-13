

const {algorithm, mode, padding,
    createEncryptStream, 
    createDecryptStream} = require('../../../..');


const assert = require('assert');

const streamBuffers = require('stream-buffers');

describe('blowfish transform ecb mode', () => {

    it('should be constructor', () => {
        assert(typeof algorithm.Blowfish === 'function', 'there is no constructor');
    });


    const key = new Buffer(56);

    for (let i = 0; i < 56; i++) {
        key[i] = ((i * 2 + 10) % 256);
    }

    const plaintext = new Buffer(
        'efe4100ebd0f60807a6f194b46c1b179a5900eee31bd629538' +
        'b1b53c7ce2e63c27b6ffcbc15f440cc39f10df097bbfced422', 'hex');

    const iv = new Buffer('33f90a870be427b5', 'hex');

    describe('standard', () => {

        const fixture = [
            {
                title: 'null padding',
                ciphertext: '7f0c90b0291a3e73b6612fbd555335feff113aa922dafab1b137039b' + 
                            '1d9cdd500d98d57714dd0c257556db074867ef64b11d4e9ee82778a1',
                padding: padding.Null
            },
            {
                title: 'space padding',
                ciphertext: '7f0c90b0291a3e73b6612fbd555335feff113aa922dafab1b137039b' + 
                            '1d9cdd500d98d57714dd0c257556db074867ef6407c7ef92c545dee1',
                padding: padding.Space
            },
            {
                title: 'ansi-x923 padding',
                ciphertext: '7f0c90b0291a3e73b6612fbd555335feff113aa922dafab1b137039b' +
                            '1d9cdd500d98d57714dd0c257556db074867ef64bea9594e63bd1692',
                padding: padding.AnsiX923
            },
            {
                title: 'iso-10126 padding',
                ciphertext: '7f0c90b0291a3e73b6612fbd555335feff113aa922dafab1b137039b' +
                            '1d9cdd500d98d57714dd0c257556db074867ef64bea9594e63bd1692',
                padding: padding.Iso10126,
                skipEncrypt: true // because there are random bytes in padding and not match
            },
            {
                title: 'iso-7816 padding',
                ciphertext: '7f0c90b0291a3e73b6612fbd555335feff113aa922dafab1b137039b' +
                            '1d9cdd500d98d57714dd0c257556db074867ef642eafc3ed9cac7433',
                padding: padding.Iso7816
            },
            {
                title: 'PKCS5 padding',
                ciphertext: '7f0c90b0291a3e73b6612fbd555335feff113aa922dafab1b137039b' +
                            '1d9cdd500d98d57714dd0c257556db074867ef6483f1614e930d6d7c',
                padding: padding.Pkcs5
            },
            {
                title: 'PKCS7 padding',
                ciphertext: '7f0c90b0291a3e73b6612fbd555335feff113aa922dafab1b137039b' +
                            '1d9cdd500d98d57714dd0c257556db074867ef6483f1614e930d6d7c',
                padding: padding.Pkcs7
            }
        ];
    
        fixture.forEach(target => {

            describe(target.title, () => {
    
                const ciphertext = new Buffer(target.ciphertext, 'hex');

                it('should do encrypt and decrypt operations', () => {

                    describe('encrypt', () => {
                    
                        if (target.skipEncrypt) {
                            return;
                        }
                    
                        const blowfish = new algorithm.Blowfish();
                        blowfish.setKey(key);

                        const cipher = new mode.ecb.Cipher(blowfish, iv);

                        const transform = createEncryptStream(cipher, target.padding);
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
                        
                        const decipher = new mode.ecb.Decipher(blowfish, iv);

                        const transform = createDecryptStream(decipher, target.padding);
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
    
    describe('endian compat', () => {

        const fixture = [
            {
                title: 'null padding',
                ciphertext: '7ed9a84617bc54ca794f1b82af52c3b1c8dbad129c83dcf35fd36f4c' +
                            '6352a104bde2d1902cf9580e94485b53567307db76fa0289fc07f0e1',
                padding: padding.Null
            },
            {
                title: 'space padding',
                ciphertext: '7ed9a84617bc54ca794f1b82af52c3b1c8dbad129c83dcf35fd36f4c' + 
                            '6352a104bde2d1902cf9580e94485b53567307dbfcebb595dd6deeda',
                padding: padding.Space
            },
            {
                title: 'ansi-x923 padding',
                ciphertext: '7ed9a84617bc54ca794f1b82af52c3b1c8dbad129c83dcf35fd36f4c' +
                            '6352a104bde2d1902cf9580e94485b53567307db2eb48b604e7655df',
                padding: padding.AnsiX923
            },
            {
                title: 'iso-10126 padding',
                ciphertext: '7ed9a84617bc54ca794f1b82af52c3b1c8dbad129c83dcf35fd36f4c' +
                            '6352a104bde2d1902cf9580e94485b53567307db34f4a375e0d5b7bf',
                padding: padding.Iso10126,
                skipEncrypt: true // because there are random bytes in padding and not match
            },
            {
                title: 'iso-7816 padding',
                ciphertext: '7ed9a84617bc54ca794f1b82af52c3b1c8dbad129c83dcf35fd36f4c' +
                            '6352a104bde2d1902cf9580e94485b53567307dbd36c5d83802eac2f',
                padding: padding.Iso7816
            },
            {
                title: 'PKCS5 padding',
                ciphertext: '7ed9a84617bc54ca794f1b82af52c3b1c8dbad129c83dcf35fd36f4c' + 
                            '6352a104bde2d1902cf9580e94485b53567307db67a812695b3b4faa',
                padding: padding.Pkcs5
            },
            {
                title: 'PKCS7 padding',
                ciphertext: '7ed9a84617bc54ca794f1b82af52c3b1c8dbad129c83dcf35fd36f4c' +
                            '6352a104bde2d1902cf9580e94485b53567307db67a812695b3b4faa',
                padding: padding.Pkcs7
            }
        ];
    
        fixture.forEach(target => {

            describe(target.title, () => {
    
                const ciphertext = new Buffer(target.ciphertext, 'hex');

                it('should do encrypt and decrypt operations', () => {

                    describe('encrypt', () => {
                    
                        if (target.skipEncrypt) {
                            return;
                        }
                    
                        const blowfish = new algorithm.Blowfish();
                        blowfish.setEndianCompat(true);
                        blowfish.setKey(key);

                        const cipher = new mode.ecb.Cipher(blowfish, iv);

                        const transform = createEncryptStream(cipher, target.padding);
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
                        blowfish.setEndianCompat(true);
                        blowfish.setKey(key);
                        
                        const decipher = new mode.ecb.Decipher(blowfish, iv);

                        const transform = createDecryptStream(decipher, target.padding);
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


});


