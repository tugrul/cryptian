
#include <algorithm-block.h>

namespace cryptian {

namespace algorithm {

class Safer : public AlgorithmBlock {
private:
    const size_t TAB_LEN = 256;
    const size_t SAFER_BLOCK_LEN = 8;
    const size_t SAFER_MAX_NOF_ROUNDS = 13;

    unsigned char exp_tab[256];
    unsigned char log_tab[256];

    unsigned char local_key[217];

    inline void pht(unsigned char &x, unsigned char &y) { y += x; x += y; }
    inline void ipht(unsigned char &x, unsigned char &y) { x -= y; y -= x; }
protected:
    unsigned int nofRounds;
    unsigned int strengthened;

public:
    Safer();

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
