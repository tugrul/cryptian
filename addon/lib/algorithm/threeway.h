
#include <algorithm-block.h>

namespace cryptian {

namespace algorithm {

class Threeway : public AlgorithmBlock {
private:
    union block {
        unsigned int ui[3];
        char c[12];
    };

    const unsigned int NMBR = 11; // number of rounds is 11
    const unsigned int STRT_E = 0x0b0b; // round constant of first encryption round
    const unsigned int STRT_D = 0xb1b1; // round constant of first decryption round

    block key;

    void mu(unsigned int*);
    void gamma(unsigned int*);
    void theta(unsigned int*);
    void pi_1(unsigned int*);
    void pi_2(unsigned int*);
    void rho(unsigned int*);
    void rndcon_gen(unsigned int, unsigned int*);
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
