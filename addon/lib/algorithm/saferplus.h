
#include <algorithm-block.h>

namespace cryptian {

namespace algorithm {

class Saferplus : public AlgorithmBlock {
private:
    union block {
        unsigned int ui[4];
        unsigned char uc[16];
        char c[16];
    };
    union key_block {
        unsigned int ui[9];
        unsigned char uc[36];
        char c[36];
    };

    unsigned char key[33 * 16];

    static const unsigned char safer_expf[256];
    static const unsigned char safer_logf[512];

    void do_fr(unsigned char[16], unsigned short);
    void do_ir(unsigned char[16], unsigned short);

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
