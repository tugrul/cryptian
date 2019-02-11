

#include "rc2.h"

namespace cryptian {

namespace algorithm {

std::string Rc2::getName() {
    return "RC2";
}

std::size_t Rc2::getVersion() {
    return 20010801;
}

std::size_t Rc2::getBlockSize() {
    return 8;
}

std::vector<std::size_t> Rc2::getKeySizes() {
    return {128};
}


std::vector<char> Rc2::encrypt(const std::vector<char> plaintext) {

    block ciphertext = {};

    std::copy_n(plaintext.begin(), plaintext.size() > 8 ? 8 : plaintext.size(), ciphertext.uc);

    for (size_t i = 0; i < 4; i++) {
        ciphertext.us[i] = byteswapBE(ciphertext.us[i]);
    }

    for (size_t i = 0; i < 16; i++) {

        ciphertext.us[0] += (ciphertext.us[1] & ~ciphertext.us[3])
                          + (ciphertext.us[2] & ciphertext.us[3])
                          + key.us[4 * i + 0];
        ciphertext.us[0] = rotl16(ciphertext.us[0], 1);

        ciphertext.us[1] += (ciphertext.us[2] & ~ciphertext.us[0])
                          + (ciphertext.us[3] & ciphertext.us[0])
                          + key.us[4 * i + 1];
        ciphertext.us[1] = rotl16(ciphertext.us[1], 2);

        ciphertext.us[2] += (ciphertext.us[3] & ~ciphertext.us[1])
                          + (ciphertext.us[0] & ciphertext.us[1])
                          + key.us[4 * i + 2];
        ciphertext.us[2] = rotl16(ciphertext.us[2], 3);

        ciphertext.us[3] += (ciphertext.us[0] & ~ciphertext.us[2])
                          + (ciphertext.us[1] & ciphertext.us[2])
                          + key.us[4 * i + 3];
        ciphertext.us[3] = rotl16(ciphertext.us[3], 5);

        if (i == 4 || i == 10) {
            ciphertext.us[0] += key.us[ciphertext.us[3] & 63];
            ciphertext.us[1] += key.us[ciphertext.us[0] & 63];
            ciphertext.us[2] += key.us[ciphertext.us[1] & 63];
            ciphertext.us[3] += key.us[ciphertext.us[2] & 63];
        }
    }

    for (size_t i = 0; i < 4; i++) {
        ciphertext.us[i] = byteswapBE(ciphertext.us[i]);
    }


    return std::vector<char>(ciphertext.uc, ciphertext.uc + 8);
}

std::vector<char> Rc2::decrypt(const std::vector<char> ciphertext) {

    block plaintext = {};

    std::copy_n(ciphertext.begin(), ciphertext.size() > 8 ? 8 : ciphertext.size(), plaintext.uc);

    for (size_t i = 0; i < 4; i++) {
        plaintext.us[i] = byteswapBE(plaintext.us[i]);
    }

    for (int i = 15; i >= 0; i--) {

        plaintext.us[3] = rotr16(plaintext.us[3], 5);
        plaintext.us[3] -= (plaintext.us[0] & ~plaintext.us[2])
                         + (plaintext.us[1] & plaintext.us[2])
                         + key.us[4 * i + 3];

        plaintext.us[2] = rotr16(plaintext.us[2], 3);
        plaintext.us[2] -= (plaintext.us[3] & ~plaintext.us[1])
                         + (plaintext.us[0] & plaintext.us[1])
                         + key.us[4 * i + 2];

        plaintext.us[1] = rotr16(plaintext.us[1], 2);
        plaintext.us[1] -= (plaintext.us[2] & ~plaintext.us[0])
                         + (plaintext.us[3] & plaintext.us[0])
                         + key.us[4 * i + 1];

        plaintext.us[0] = rotr16(plaintext.us[0], 1);
        plaintext.us[0] -= (plaintext.us[1] & ~plaintext.us[3])
                         + (plaintext.us[2] & plaintext.us[3])
                         + key.us[4 * i + 0];

        if (i == 5 || i == 11) {
            plaintext.us[3] -= key.us[plaintext.us[2] & 63];
            plaintext.us[2] -= key.us[plaintext.us[1] & 63];
            plaintext.us[1] -= key.us[plaintext.us[0] & 63];
            plaintext.us[0] -= key.us[plaintext.us[3] & 63];
        }
    }

    for (size_t i = 0; i < 4; i++) {
        plaintext.us[i] = byteswapBE(plaintext.us[i]);
    }

    return std::vector<char>(plaintext.uc, plaintext.uc + 8);
}

void Rc2::reset() {

    std::fill_n(key.uc, 128, 0);

    std::copy_n(_key.begin(), _key.size() > 128 ? 128 : _key.size(), key.uc);

    for (size_t i = _key.size(); i < 128; i++) {
        key.uc[i] = permute[key.uc[i - _key.size()] + key.uc[i - 1] % 256];
    }

    key.uc[0] = permute[key.uc[0]];
}

const unsigned char Rc2::permute[256] = {
    217, 120, 249, 196, 25, 221, 181, 237, 40, 233, 253, 121,
    74, 160, 216, 157,
    198, 126, 55, 131, 43, 118, 83, 142, 98, 76, 100, 136,
    68, 139, 251, 162,
    23, 154, 89, 245, 135, 179, 79, 19, 97, 69, 109, 141, 9,
    129, 125, 50,
    189, 143, 64, 235, 134, 183, 123, 11, 240, 149, 33, 34,
    92, 107, 78, 130,
    84, 214, 101, 147, 206, 96, 178, 28, 115, 86, 192, 20,
    167, 140, 241, 220,
    18, 117, 202, 31, 59, 190, 228, 209, 66, 61, 212, 48,
    163, 60, 182, 38,
    111, 191, 14, 218, 70, 105, 7, 87, 39, 242, 29, 155, 188,
    148, 67, 3,
    248, 17, 199, 246, 144, 239, 62, 231, 6, 195, 213, 47,
    200, 102, 30, 215,
    8, 232, 234, 222, 128, 82, 238, 247, 132, 170, 114, 172,
    53, 77, 106, 42,
    150, 26, 210, 113, 90, 21, 73, 116, 75, 159, 208, 94, 4,
    24, 164, 236,
    194, 224, 65, 110, 15, 81, 203, 204, 36, 145, 175, 80,
    161, 244, 112, 57,
    153, 124, 58, 133, 35, 184, 180, 122, 252, 2, 54, 91, 37,
    85, 151, 49,
    45, 93, 250, 152, 227, 138, 146, 174, 5, 223, 41, 16,
    103, 108, 186, 201,
    211, 0, 230, 207, 225, 158, 168, 44, 99, 22, 1, 63, 88,
    226, 137, 169,
    13, 56, 52, 27, 171, 51, 255, 176, 187, 72, 12, 95, 185,
    177, 205, 46,
    197, 243, 219, 71, 229, 165, 156, 119, 10, 166, 32, 104,
    254, 127, 193, 173
};

};

};

