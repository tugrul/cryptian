
#include <algorithm-stream.h>

namespace cryptian {

namespace algorithm {


class Wake : public AlgorithmStream {
private:

    union key_block {
        unsigned int ui[5];
        unsigned char uc[40];
        char c[40];
    };

    unsigned int t[257];
	key_block key;

	int counter;
	int started;

    static const unsigned int tt[10];

    inline void M(unsigned char index1, unsigned char index2)
    {
    	register unsigned int sum = key.ui[index1] + key.ui[index2];
    	key.ui[index1] = (((sum) >> 8) & 0x00ffffff) ^ t[(sum) & 0xff];
    }


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
