

#include <algorithm-block.h>

namespace cryptian {

namespace algorithm {

class Twofish : public AlgorithmBlock {
private:
    static const std::size_t TWOFISH_BLOCK_LEN = 16;
    static const std::size_t TWOFISH_ROUNDS = 16;

    // Whitening takes eight subkeys and the rounds take two each.
    unsigned int _subkeys[8 + 2 * TWOFISH_ROUNDS];

    // The key dependent s-boxes folded together with the MDS matrix, so the
    // round function is four lookups and three exclusive ors.
    unsigned int _sbox[4][256];

    // Key length in 64 bit words: 2, 3 or 4.
    unsigned int _words;

    static unsigned char qPermute(const unsigned char t[4][16], unsigned char x);
    static unsigned char q0(unsigned char x);
    static unsigned char q1(unsigned char x);

    static unsigned char multiplyGf(unsigned char a, unsigned char b, unsigned int modulus);
    static unsigned int multiplyMds(const unsigned char y[4]);
    static unsigned int reedSolomon(const unsigned char key[8]);

    static unsigned char sboxByte(unsigned int position, unsigned char y, const unsigned int* l, unsigned int words);
    unsigned int h(unsigned int x, const unsigned int* l, unsigned int words);

    inline unsigned int g(unsigned int x) {
        return _sbox[0][x & 0xFF]
             ^ _sbox[1][(x >> 8) & 0xFF]
             ^ _sbox[2][(x >> 16) & 0xFF]
             ^ _sbox[3][(x >> 24) & 0xFF];
    }

    static inline unsigned int load(const char* p) {
        return (static_cast<unsigned int>(static_cast<unsigned char>(p[0])))
             | (static_cast<unsigned int>(static_cast<unsigned char>(p[1])) << 8)
             | (static_cast<unsigned int>(static_cast<unsigned char>(p[2])) << 16)
             | (static_cast<unsigned int>(static_cast<unsigned char>(p[3])) << 24);
    }

    static inline void store(char* p, unsigned int v) {
        p[0] = static_cast<char>(v & 0xFF);
        p[1] = static_cast<char>((v >> 8) & 0xFF);
        p[2] = static_cast<char>((v >> 16) & 0xFF);
        p[3] = static_cast<char>((v >> 24) & 0xFF);
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
