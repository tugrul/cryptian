
#include "gost.h"

namespace cryptian {

namespace algorithm {

Gost::Gost() {

    for (size_t i = 0; i < 256; i++) {

        gost_k87[i] = gost_k8[i >> 4] << 4 | gost_k7[i & 15];
        gost_k65[i] = gost_k6[i >> 4] << 4 | gost_k5[i & 15];
        gost_k43[i] = gost_k4[i >> 4] << 4 | gost_k3[i & 15];
        gost_k21[i] = gost_k2[i >> 4] << 4 | gost_k1[i & 15];

    }

}

std::string Gost::getName() {
    return "GOST";
}

std::size_t Gost::getVersion() {
    return 20010801;
}

std::size_t Gost::getBlockSize() {
    return 8;
}

std::vector<std::size_t> Gost::getKeySizes() {
    return {32};
}


std::vector<char> Gost::encrypt(const std::vector<char> plaintext) {

    register unsigned int n1, n2;

    block ciphertext = {};

    std::copy_n(plaintext.begin(), 8, ciphertext.c);

    n1 = byteswapLE(ciphertext.ui[0]);
    n2 = byteswapLE(ciphertext.ui[1]);

	// Instead of swapping halves, swap names each round
	n2 ^= f(n1 + key.ui[0]);
	n1 ^= f(n2 + key.ui[1]);
	n2 ^= f(n1 + key.ui[2]);
	n1 ^= f(n2 + key.ui[3]);
	n2 ^= f(n1 + key.ui[4]);
	n1 ^= f(n2 + key.ui[5]);
	n2 ^= f(n1 + key.ui[6]);
	n1 ^= f(n2 + key.ui[7]);

	n2 ^= f(n1 + key.ui[0]);
	n1 ^= f(n2 + key.ui[1]);
	n2 ^= f(n1 + key.ui[2]);
	n1 ^= f(n2 + key.ui[3]);
	n2 ^= f(n1 + key.ui[4]);
	n1 ^= f(n2 + key.ui[5]);
	n2 ^= f(n1 + key.ui[6]);
	n1 ^= f(n2 + key.ui[7]);

	n2 ^= f(n1 + key.ui[0]);
	n1 ^= f(n2 + key.ui[1]);
	n2 ^= f(n1 + key.ui[2]);
	n1 ^= f(n2 + key.ui[3]);
	n2 ^= f(n1 + key.ui[4]);
	n1 ^= f(n2 + key.ui[5]);
	n2 ^= f(n1 + key.ui[6]);
	n1 ^= f(n2 + key.ui[7]);

	n2 ^= f(n1 + key.ui[7]);
	n1 ^= f(n2 + key.ui[6]);
	n2 ^= f(n1 + key.ui[5]);
	n1 ^= f(n2 + key.ui[4]);
	n2 ^= f(n1 + key.ui[3]);
	n1 ^= f(n2 + key.ui[2]);
	n2 ^= f(n1 + key.ui[1]);
	n1 ^= f(n2 + key.ui[0]);

    ciphertext.ui[0] = byteswapLE(n2);
    ciphertext.ui[1] = byteswapLE(n1);

    return std::vector<char>(ciphertext.c, ciphertext.c + 8);
}

std::vector<char> Gost::decrypt(const std::vector<char> ciphertext) {

    register unsigned int n1, n2;

    block plaintext = {};

    std::copy_n(ciphertext.begin(), 8, plaintext.c);

    n1 = byteswapLE(plaintext.ui[0]);
    n2 = byteswapLE(plaintext.ui[1]);


    n2 ^= f(n1 + key.ui[0]);
    n1 ^= f(n2 + key.ui[1]);
    n2 ^= f(n1 + key.ui[2]);
    n1 ^= f(n2 + key.ui[3]);
    n2 ^= f(n1 + key.ui[4]);
    n1 ^= f(n2 + key.ui[5]);
    n2 ^= f(n1 + key.ui[6]);
    n1 ^= f(n2 + key.ui[7]);

    n2 ^= f(n1 + key.ui[7]);
    n1 ^= f(n2 + key.ui[6]);
    n2 ^= f(n1 + key.ui[5]);
    n1 ^= f(n2 + key.ui[4]);
    n2 ^= f(n1 + key.ui[3]);
    n1 ^= f(n2 + key.ui[2]);
    n2 ^= f(n1 + key.ui[1]);
    n1 ^= f(n2 + key.ui[0]);

    n2 ^= f(n1 + key.ui[7]);
    n1 ^= f(n2 + key.ui[6]);
    n2 ^= f(n1 + key.ui[5]);
    n1 ^= f(n2 + key.ui[4]);
    n2 ^= f(n1 + key.ui[3]);
    n1 ^= f(n2 + key.ui[2]);
    n2 ^= f(n1 + key.ui[1]);
    n1 ^= f(n2 + key.ui[0]);

    n2 ^= f(n1 + key.ui[7]);
    n1 ^= f(n2 + key.ui[6]);
    n2 ^= f(n1 + key.ui[5]);
    n1 ^= f(n2 + key.ui[4]);
    n2 ^= f(n1 + key.ui[3]);
    n1 ^= f(n2 + key.ui[2]);
    n2 ^= f(n1 + key.ui[1]);
    n1 ^= f(n2 + key.ui[0]);


    plaintext.ui[0] = byteswapLE(n2);
    plaintext.ui[1] = byteswapLE(n1);

    return std::vector<char>(plaintext.c, plaintext.c + 8);
}

void Gost::reset() {

    std::fill_n(key.ui, 8, 0);

    std::copy_n(_key.begin(), _key.size() > 32 ? 32 : _key.size(), key.c);

    for (size_t i = 0; i < 8; i++) {
        key.ui[i] = byteswapBE(key.ui[i]);
    }

}

const unsigned char Gost::gost_k1[16] = {
	1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 2
};

const unsigned char Gost::gost_k2[16] = {
	13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12
};

const unsigned char Gost::gost_k3[16] = {
	4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14
};

const unsigned char Gost::gost_k4[16] = {
	6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2
};

const unsigned char Gost::gost_k5[16] = {
	7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3
};

const unsigned char Gost::gost_k6[16] = {
	5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11
};

const unsigned char Gost::gost_k7[16] = {
	14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9
};

const unsigned char Gost::gost_k8[16] = {
	4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3
};

};

};

