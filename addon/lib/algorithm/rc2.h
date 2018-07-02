
#include <algorithm-block.h>

namespace cryptian {

namespace algorithm {

class Rc2 : public AlgorithmBlock {
private:
    union block {
        unsigned char uc[8];
        unsigned short us[4];
        unsigned int ui[2];
    };

    union key_block {
        unsigned char uc[128];
        unsigned short us[64];
        unsigned int ui[32];

    };

    key_block key;
    static const unsigned char permute[256];

public:
    std::string getName();
    std::size_t getVersion();
    std::size_t getBlockSize();
    std::vector<std::size_t> getKeySizes();
    void reset();

    std::vector<char> encrypt(const std::vector<char>);
    std::vector<char> decrypt(const std::vector<char>);
};

};

};
