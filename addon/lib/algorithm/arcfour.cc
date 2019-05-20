
#include "arcfour.h"

namespace cryptian {

namespace algorithm {


std::string Arcfour::getName() {
    return "RC4";
}

std::size_t Arcfour::getVersion() {
    return 20020610;
}

std::size_t Arcfour::getIvSize() {
    return 32;
}

std::vector<std::size_t> Arcfour::getKeySizes() {
    return {256};
}

std::vector<char> Arcfour::encrypt(const std::vector<char> plaintext) {

    std::vector<char> ciphertext = plaintext;

    int i = I, j = J;

    for (auto &item : ciphertext) {
        i++;
        i &= 0xFF;
        j += state[i];
        j &= 0xFF;

        std::swap(state[i], state[j]);

        item ^= state[(state[i] + state[j]) & 0xFF];
    }

    I = i;
    J = j;

    return ciphertext;
}

std::vector<char> Arcfour::decrypt(const std::vector<char> ciphertext) {

    return encrypt(ciphertext);
}

void Arcfour::reset() {

    I = 0;
    J = 0;

    for (size_t i = 0; i < 256; i++) {
        state[i] = i;
    }

    for (size_t i = 0, j = 0; i < 256; i++) {

        if (_key.size() > 0) {
            j += state[i] + _key[i % _key.size()];
        }

        if (_iv.size() > 0) {
            j += _iv[i + 1 % _iv.size()];
        }

        j &= 0xff;

        std::swap(state[i], state[j]);

    }
}


};

};