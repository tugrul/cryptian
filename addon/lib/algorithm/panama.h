

#include <algorithm-stream.h>

namespace cryptian {

namespace algorithm {

class Panama : public AlgorithmStream {
private:
    static const std::size_t PANAMA_STAGE_SIZE = 8;
    static const std::size_t PANAMA_STAGES = 32;
    static const std::size_t PANAMA_STATE_SIZE = 17;

    // 32 stage buffer, 256 bits wide, addressed through a moving tap.
    unsigned int _buffer[PANAMA_STAGES][PANAMA_STAGE_SIZE];
    unsigned int _state[PANAMA_STATE_SIZE];
    std::size_t _tap;

    // One pulled block of key material and how much of it has been consumed.
    unsigned int _keyMaterial[PANAMA_STAGE_SIZE];
    std::size_t _keyMaterialPosition;

    void resetState();
    void rho(unsigned int* theta);
    void push(const unsigned int* input, std::size_t blocks);
    void pull(unsigned int* output, std::size_t blocks);

    std::vector<char> crypt(const std::vector<char> input);

    static inline unsigned int load(const char* p) {
        return (static_cast<unsigned int>(static_cast<unsigned char>(p[0])))
             | (static_cast<unsigned int>(static_cast<unsigned char>(p[1])) << 8)
             | (static_cast<unsigned int>(static_cast<unsigned char>(p[2])) << 16)
             | (static_cast<unsigned int>(static_cast<unsigned char>(p[3])) << 24);
    }

public:
    std::string getName();
    std::size_t getVersion();
    std::size_t getIvSize();
    std::vector<std::size_t> getKeySizes();

    std::vector<char> encrypt(const std::vector<char>);
    std::vector<char> decrypt(const std::vector<char>);

    void reset();
};

};

};
