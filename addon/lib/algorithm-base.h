
#ifndef CRYPTIAN_ALGORITM_BASE_H_
#define CRYPTIAN_ALGORITM_BASE_H_

#include <cstddef>
#include <vector>
#include <string>
#include <algorithm>

namespace cryptian {

namespace algorithm {

class AlgorithmBase {
protected:
    std::vector<char> _key;
    bool _endianCompat;

    inline unsigned char rotl8(unsigned char x, unsigned char n)  {
        return ((x) << ((unsigned char)(n))) | ((x) >> (8 - (unsigned char)(n)));
    }

    inline unsigned short rotl16(unsigned short x, unsigned short n)  {
        return ((x) << ((unsigned short)(n))) | ((x) >> (16 - (unsigned short)(n)));
    }

    inline unsigned int rotl32(unsigned int x, unsigned int n)  {
        return ((x) << ((unsigned int)(n))) | ((x) >> (32 - (unsigned int)(n)));
    }

    inline unsigned char rotr8(unsigned char x, unsigned char n)  {
        return rotl8(x, 8 - n);
    }

    inline unsigned short rotr16(unsigned short x, unsigned short n)  {
        return rotl16(x, 16 - n);
    }

    inline unsigned int rotr32(unsigned int x, unsigned int n)  {
        return rotl32(x, 32 - n);
    }

    const char LE_VAL = 0x04;
    const char BE_VAL = 0x01;

    inline unsigned char getEndianType() {
        union {
            unsigned int ui;
            char c[4];
        } val = {0x01020304};

        return val.c[0];
    }


    inline unsigned short byteswap(unsigned short value, bool hit) {

        if (!(hit ^ _endianCompat)) {
            return value;
        }

        return ( (value >> 8)  & 0x00FF )
             | ( (value << 8)  & 0xFF00 );
    }

    inline unsigned int byteswap(unsigned int value, bool hit) {

        if (!(hit ^ _endianCompat)) {
            return value;
        }

        return ( (value >> 24) & 0x000000FF )
             | ( (value >> 8)  & 0x0000FF00 )
             | ( (value << 8)  & 0x00FF0000 )
             | ( (value << 24) & 0xFF000000 );
    }

    template <typename T>
    inline T byteswapBE(T value) {
        return byteswap(value, getEndianType() == BE_VAL);
    }

    template <typename T>
    inline T byteswapLE(T value) {
        return byteswap(value, getEndianType() == LE_VAL);
    }

public:
    AlgorithmBase() : _endianCompat(false) {}
    virtual ~AlgorithmBase() {}

    virtual std::string getName() = 0;
    virtual std::size_t getVersion() = 0;

    virtual std::vector<std::size_t> getKeySizes() = 0;

    virtual std::vector<char> encrypt(const std::vector<char>) = 0;
    virtual std::vector<char> decrypt(const std::vector<char>) = 0;

    virtual void reset() {

    }

    void setEndianCompat(const bool endianCompat) {
        _endianCompat = endianCompat;
    }

    void setKey(const std::vector<char> key) {

        if (_key.size() != key.size() || !std::equal(key.begin(), key.end(), _key.begin())) {
            _key = key;
            reset();
        }


    }
};

};

};

#endif  // ~ CRYPTIAN_ALGORITM_BASE_H_

