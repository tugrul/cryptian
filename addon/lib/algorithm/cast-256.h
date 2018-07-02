


#include <algorithm-block.h>

namespace cryptian {

namespace algorithm {

class Cast256 : public AlgorithmBlock {
private:
    union block {
        unsigned int ui[4];
        char c[16];
    };

    union key_block {
        unsigned int ui[8];
        char c[32];
    };

    const static unsigned int cast256_sbox[4][256];

    unsigned int l_key[96];

    inline unsigned char getByte(unsigned int x, unsigned int n) {
        return (unsigned char)((x) >> (8 * n));
    }

    inline void f1(unsigned int &t, unsigned int &u, unsigned int &y, unsigned int x, unsigned int kr, unsigned int km) {
        t  = rotl32(km + x, kr);
        u  = cast256_sbox[0][getByte(t, 3)];
        u ^= cast256_sbox[1][getByte(t, 2)];
        u -= cast256_sbox[2][getByte(t, 1)];
        u += cast256_sbox[3][getByte(t, 0)];
        y ^= u;
    }

    inline void f2(unsigned int &t, unsigned int &u, unsigned int &y, unsigned int x, unsigned int kr, unsigned int km) {
        t  = rotl32(km ^ x, kr);
        u  = cast256_sbox[0][getByte(t, 3)];
        u -= cast256_sbox[1][getByte(t, 2)];
        u += cast256_sbox[2][getByte(t, 1)];
        u ^= cast256_sbox[3][getByte(t, 0)];
        y ^= u;
    }

    inline void f3(unsigned int &t, unsigned int &u, unsigned int &y, unsigned int x, unsigned int kr, unsigned int km) {
        t  = rotl32(km - x, kr);
        u  = cast256_sbox[0][getByte(t, 3)];
        u += cast256_sbox[1][getByte(t, 2)];
        u ^= cast256_sbox[2][getByte(t, 1)];
        u -= cast256_sbox[3][getByte(t, 0)];
        y ^= u;
    }

    inline void f_rnd(unsigned int &t, unsigned int &u, unsigned int *x, unsigned char n) {
        f1(t, u, x[2], x[3], l_key[n],    l_key[n + 4]);
        f2(t, u, x[1], x[2], l_key[n + 1], l_key[n + 5]);
        f3(t, u, x[0], x[1], l_key[n + 2], l_key[n + 6]);
        f1(t, u, x[3], x[0], l_key[n + 3], l_key[n + 7]);
    }

    inline void i_rnd(unsigned int &t, unsigned int &u, unsigned int *x, unsigned char n) {
        f1(t, u, x[3], x[0], l_key[n + 3], l_key[n + 7]);
        f3(t, u, x[0], x[1], l_key[n + 2], l_key[n + 6]);
        f2(t, u, x[1], x[2], l_key[n + 1], l_key[n + 5]);
        f1(t, u, x[2], x[3], l_key[n],    l_key[n + 4]);
    }

    inline void k_rnd(unsigned int &t, unsigned int &u, unsigned int *k, unsigned int *tr, unsigned int *tm) {
        f1(t, u, k[6], k[7], tr[0], tm[0]);
        f2(t, u, k[5], k[6], tr[1], tm[1]);
        f3(t, u, k[4], k[5], tr[2], tm[2]);
        f1(t, u, k[3], k[4], tr[3], tm[3]);
        f2(t, u, k[2], k[3], tr[4], tm[4]);
        f3(t, u, k[1], k[2], tr[5], tm[5]);
        f1(t, u, k[0], k[1], tr[6], tm[6]);
        f2(t, u, k[7], k[0], tr[7], tm[7]);
    }

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

