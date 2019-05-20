


#include <algorithm-block.h>

namespace cryptian {

namespace algorithm {

class Cast128 : public AlgorithmBlock {
private:
    //const unsigned int CAST_MIN_KEYSIZE = 5;
    //const unsigned int CAST_MAX_KEYSIZE = 16;
    //const unsigned int CAST_BLOCKSIZE = 8;

    const unsigned int CAST_SMALL_KEY = 10;
    const unsigned int CAST_SMALL_ROUNDS = 12;
    const unsigned int CAST_FULL_ROUNDS = 16;

    const static unsigned int sbox[8][256];

    unsigned int xkey[32]; // Key, after expansion
	unsigned int rounds;   // Number of rounds to use, 12 or 16

    inline unsigned char U8a(const unsigned int x) { return x >> 24 & 255; }
    inline unsigned char U8b(const unsigned int x) { return ( x >> 16) & 255; }
    inline unsigned char U8c(const unsigned int x) { return ( x >> 8) & 255; }
    inline unsigned char U8d(const unsigned int x) { return x & 255; }

    // Circular left shift
    inline unsigned int ROL(const unsigned int x, const unsigned int n) { return ((x)<<(n)) | ((x)>>(32-(n))); }

    // CAST-128 uses three different round functions
    inline void F1(unsigned int &t, unsigned int &l, const unsigned int r, const unsigned int i) {
        t = ROL(xkey[i] + r, xkey[i+16]);
    	l ^= ((sbox[0][U8a(t)] ^ sbox[1][U8b(t)]) - sbox[2][U8c(t)]) + sbox[3][U8d(t)];
    }

    inline void F2(unsigned int &t, unsigned int &l, const unsigned int r, const unsigned int i) {
        t = ROL(xkey[i] ^ r, xkey[i+16]);
    	l ^= ((sbox[0][U8a(t)] - sbox[1][U8b(t)]) + sbox[2][U8c(t)]) ^ sbox[3][U8d(t)];
    }

    inline void F3(unsigned int &t, unsigned int &l, const unsigned int r, const unsigned int i) {
        t = ROL(xkey[i] - r, xkey[i+16]);
    	l ^= ((sbox[0][U8a(t)] + sbox[1][U8b(t)]) ^ sbox[2][U8c(t)]) - sbox[3][U8d(t)];
    }


public:
    std::string getName();
    std::size_t getVersion();
    std::size_t getBlockSize();
    std::vector<std::size_t> getKeySizes();

    std::vector<char> encrypt(const std::vector<char>);
    std::vector<char> decrypt(const std::vector<char>);

    void reset();
};

};

};

