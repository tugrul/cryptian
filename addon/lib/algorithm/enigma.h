
#include <algorithm-stream.h>

namespace cryptian {

namespace algorithm {


class Enigma : public AlgorithmStream {
private:
    // const unsigned int E_ECHO = 010;
    const int ROTORSZ = 256;
    const unsigned int MASK = 0377;

    char t1[256];
	char t2[256];
	char t3[256];
	char deck[256];
	char cbuf[13];
	int n1, n2, nr1, nr2;

    void shuffle();

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
