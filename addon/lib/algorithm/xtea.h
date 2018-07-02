

#include <algorithm-block.h>

namespace cryptian {

namespace algorithm {

class Xtea : public AlgorithmBlock {
private:
    union block {
        unsigned int ui[2];
        char c[8];
    };

    union key_block {
        unsigned int ui[4];
        char c[16];
    };

    key_block key;

    const unsigned int ROUNDS = 32;
    const unsigned int DELTA = 0x9e3779b9;

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

