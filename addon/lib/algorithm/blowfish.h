

#include <algorithm-block.h>

namespace cryptian {

namespace algorithm {

class Blowfish : public AlgorithmBlock {
private:
    union block {
        unsigned int ui[2];
        char c[8];
    };

    unsigned int S[4][256];
    unsigned int P[18];

    // const unsigned short MAXKEYBYTES = 56;
    const unsigned short BF_N = 16;
    // const unsigned short KEYBYTES = 8;

    static const unsigned int ks[4][256];
    static const unsigned int pi[18];


    void enblf_noswap(unsigned int *);

    inline unsigned int F(unsigned int x) {
        return ((S[0][(x >> 24) & 0xff] + S[1][(x >> 16) & 0xff]) ^ S[2][(x >>  8) & 0xff]) + S[3][x & 0xff];
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
