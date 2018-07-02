
#include <algorithm-block.h>

namespace cryptian {

namespace algorithm {

class Dummy : public AlgorithmBlock {
public:
    std::string getName();
    std::size_t getVersion();
    std::size_t getBlockSize();
    std::vector<std::size_t> getKeySizes();

    std::vector<char> encrypt(const std::vector<char>);
    std::vector<char> decrypt(const std::vector<char>);
};

};

};
