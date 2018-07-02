

#include <algorithm-block.h>

namespace cryptian {

namespace algorithm {

class Des : public AlgorithmBlock {
private:
    union block {
        unsigned int ui[2];
        char c[8];
    };

    static const char ip[64];
    static const char fp[64];
    static const char pc1[56];
    static const char pc2[48];
    static const char totrot[16];
    static const char si[8][64];
    static const char p32i[32];
    static const int bytebit[8];
    static const int nibblebit[4];

    char kn[16][8];
    char iperm[16][16][8];
    char fperm[16][16][8];
    unsigned int sp[8][64];

    void spinit(unsigned int (&)[8][64]);
    void perminit(char (&)[16][16][8], const char (&)[64]);
    void permute(const char (&)[16][16][8], block*, block*);

    unsigned int f(unsigned int, char*);

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

