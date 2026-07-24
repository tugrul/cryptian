

#include <algorithm-block.h>

namespace cryptian {

namespace algorithm {

class Serpent : public AlgorithmBlock {
private:
    static const std::size_t SERPENT_BLOCK_LEN = 16;
    static const std::size_t SERPENT_ROUNDS = 32;

    // 33 subkeys of four words: one per round plus a final whitening subkey.
    unsigned int _subkeys[SERPENT_ROUNDS + 1][4];

    static void applySbox(unsigned int index, unsigned int* x);
    static void applySboxInverse(unsigned int index, unsigned int* x);

    static void linearTransform(unsigned int* x);
    static void linearTransformInverse(unsigned int* x);

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
