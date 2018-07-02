
#include <algorithm-stream.h>

namespace cryptian {

namespace algorithm {


class Arcfour : public AlgorithmStream {
private:
    char state[256];
    char I;
    char J;

public:
    std::string getName();
    std::size_t getVersion();
    std::vector<std::size_t> getKeySizes();

    std::size_t getIvSize();

    std::vector<char> encrypt(const std::vector<char>);
    std::vector<char> decrypt(const std::vector<char>);

    void reset();

};

};

};
