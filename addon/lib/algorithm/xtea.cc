
#include "xtea.h"

namespace cryptian {

namespace algorithm {

std::string Xtea::getName() {
    return "xTEA";
}

std::size_t Xtea::getVersion() {
    return 20010801;
}

std::size_t Xtea::getBlockSize() {
    return 8;
}

std::vector<std::size_t> Xtea::getKeySizes() {
    return {16};
}

std::vector<char> Xtea::encrypt(const std::vector<char> plaintext) {

    block ciphertext = {.ui = {0, 0}};
    std::copy_n(plaintext.begin(), plaintext.size() > 8 ? 8 : plaintext.size(), ciphertext.c);


    ciphertext.ui[0] = byteswapLE(ciphertext.ui[0]);
    ciphertext.ui[1] = byteswapLE(ciphertext.ui[1]);

	unsigned int limit = DELTA * ROUNDS, sum = 0;

	while (sum != limit) {

		ciphertext.ui[0] += (((ciphertext.ui[1] << 4) ^
                             (ciphertext.ui[1] >> 5)) + ciphertext.ui[1])
                            ^ (sum + byteswapLE(key.ui[sum & 3]));

		sum += DELTA;

		ciphertext.ui[1] += (((ciphertext.ui[0] << 4) ^
                             (ciphertext.ui[0] >> 5)) + ciphertext.ui[0])
                            ^ (sum + byteswapLE(key.ui[(sum >> 11) & 3]));
	}


    ciphertext.ui[0] = byteswapLE(ciphertext.ui[0]);
    ciphertext.ui[1] = byteswapLE(ciphertext.ui[1]);


    return std::vector<char>(ciphertext.c, ciphertext.c + 8);
}

std::vector<char> Xtea::decrypt(const std::vector<char> ciphertext) {


    block plaintext = {.ui = {0, 0}};
    std::copy_n(ciphertext.begin(), ciphertext.size() > 8 ? 8 : ciphertext.size(), plaintext.c);

    plaintext.ui[0] = byteswapLE(plaintext.ui[0]);
    plaintext.ui[1] = byteswapLE(plaintext.ui[1]);

	unsigned int sum = DELTA * ROUNDS;

	while (sum) {

		plaintext.ui[1] -= (((plaintext.ui[0] << 4) ^
                             (plaintext.ui[0] >> 5)) + plaintext.ui[0])
                             ^ (sum + byteswapLE(key.ui[(sum >> 11) & 3]));

        sum -= DELTA;

		plaintext.ui[0] -= (((plaintext.ui[1] << 4) ^
                             (plaintext.ui[1] >> 5)) + plaintext.ui[1])
                             ^ (sum + byteswapLE(key.ui[sum & 3]));

	}


    plaintext.ui[0] = byteswapLE(plaintext.ui[0]);
    plaintext.ui[1] = byteswapLE(plaintext.ui[1]);


    return std::vector<char>(plaintext.c, plaintext.c + 8);

}

void Xtea::reset() {

    std::fill_n(key.ui, 4, 0);
    std::copy_n(_key.begin(), _key.size() > 16 ? 16 : _key.size(), key.c);


}


};

};
