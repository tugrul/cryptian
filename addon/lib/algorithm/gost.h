

#include <algorithm-block.h>

namespace cryptian {

namespace algorithm {

class Gost : public AlgorithmBlock {
private:
    union block {
        unsigned int ui[2];
        char c[8];
    };

    union key_block {
         unsigned int ui[8];
         char c[32];
    };

    key_block key;

    unsigned char gost_k87[256];
    unsigned char gost_k65[256];
    unsigned char gost_k43[256];
    unsigned char gost_k21[256];

    static const unsigned char gost_k1[16];
    static const unsigned char gost_k2[16];
    static const unsigned char gost_k3[16];
    static const unsigned char gost_k4[16];
    static const unsigned char gost_k5[16];
    static const unsigned char gost_k6[16];
    static const unsigned char gost_k7[16];
    static const unsigned char gost_k8[16];

    inline unsigned int f(unsigned int x) {
        x = gost_k87[x >> 24 & 255] << 24 | gost_k65[x >> 16 & 255] << 16 |
    	    gost_k43[x >> 8 & 255] << 8 | gost_k21[x & 255];

        return x << 11 | x >> (32 - 11);
    }

public:
    Gost();

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

