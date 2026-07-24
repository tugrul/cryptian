
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
            // Was _iv[i + 1 % _iv.size()]. The modulus binds tighter than the
            // addition, so that reduced to _iv[i + 1] and indexed up to 256
            // into a vector holding far fewer bytes, reading past the end for
            // every iteration beyond its length. Output varied between
            // identical runs because it depended on whatever followed the
            // allocation.
            //
            // libmcrypt walks the vector with an index that wraps at its
            // length and starts at zero, which is i % size. Note that
            // libmcrypt leaves this path disabled behind USE_IV, so no mcrypt
            // data was ever produced with an arcfour initialization vector.
            j += _iv[i % _iv.size()];
        }

        j &= 0xff;

        std::swap(state[i], state[j]);

    }
}


};

};