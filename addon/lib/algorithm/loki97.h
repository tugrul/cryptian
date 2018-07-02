

#include <algorithm-block.h>

namespace cryptian {

namespace algorithm {

class Loki97 : public AlgorithmBlock {
private:
    union block {
        unsigned int ui[4];
        char c[16];
    };

    union key_block {
         unsigned int ui[8];
         char c[32];
    };

    const unsigned int S1_SIZE = 13;
    const unsigned int S1_LEN = 8192;
    const unsigned int S1_MASK = 8191;
    const unsigned int S1_HMASK = 7936;
    const unsigned int S1_POLY = 0x2911;

    const unsigned int S2_SIZE = 11;
    const unsigned int S2_LEN = 2048;
    const unsigned int S2_MASK = 2047;
    const unsigned int S2_HMASK = 1792;
    const unsigned int S2_POLY = 0x0aa7;

    const unsigned int delta[2] = { 0x7f4a7c15, 0x9e3779b9 };

    unsigned int l_key[96];

    unsigned char sb1[8192];
    unsigned char sb2[2048];
    unsigned int  prm[256][2];

    inline void add_eq(unsigned int *x, const unsigned int *y) { x[1] += y[1] + ((x[0] += y[0]) < y[0] ? 1 : 0); }
    inline void sub_eq(unsigned int *x, unsigned int *y, unsigned int &xs) { xs = x[0]; x[1] -= y[1] + ((x[0] -= y[0]) > xs ? 1 : 0); }

    inline void ir_fun(unsigned int *l, unsigned int *r, unsigned int *k, unsigned int &xs) { sub_eq(l, k + 4, xs); f_fun(r, l, k + 2); sub_eq(l, k, xs); }
    inline void  r_fun(unsigned int *l, unsigned int *r, unsigned int *k) { add_eq(l, k); f_fun(r, l, k + 2); add_eq(l, k + 4); }

    inline unsigned char getByte(unsigned int x, unsigned int n) { return (unsigned char)((x) >> (8 * n)); }

    unsigned int ff_mult(unsigned int, unsigned int, unsigned int, unsigned int);
    void f_fun(unsigned int[2], const unsigned int[2], const unsigned int[2]);

public:
    Loki97();

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

