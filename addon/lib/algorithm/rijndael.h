
#ifndef CRYPTIAN_RIJNDAEL_H_
#define CRYPTIAN_RIJNDAEL_H_


#include <algorithm-block.h>

namespace cryptian {

namespace algorithm {

class Rijndael : public AlgorithmBlock {
private:

    const unsigned char InCo[4] = { 0xB, 0xD, 0x9, 0xE };

    unsigned char fbsub[256];
    unsigned char rbsub[256];
    unsigned char ptab[256];
    unsigned char ltab[256];
    unsigned int ftable[256];
    unsigned int rtable[256];
    unsigned int rco[30];

    int Nk;
    int Nr;
	unsigned char fi[24];
    unsigned char ri[24];
	unsigned int fkey[120];
	unsigned int rkey[120];

    unsigned char xtime(unsigned char);
    unsigned char byteSub(unsigned char);
    unsigned int pack(const unsigned char*);
    void unpack(unsigned int, unsigned char*);
    unsigned char bmul(unsigned char, unsigned char);
    unsigned int subByte(unsigned int);
    unsigned char product(unsigned int, unsigned int);
    unsigned int invMixCol(unsigned int);

protected:
    int Nb;

public:
    Rijndael();

    std::size_t getVersion();
    std::size_t getBlockSize();
    std::vector<std::size_t> getKeySizes();

    std::vector<char> encrypt(const std::vector<char>);
    std::vector<char> decrypt(const std::vector<char>);

    void reset();
};

};

};

#endif  // ~ CRYPTIAN_RIJNDAEL_H_

