
#include "serpent.h"

namespace cryptian {

namespace algorithm {

namespace {

// The eight four bit substitutions from the Serpent submission. They are used
// in rotation, one per round, and the key schedule uses them in reverse.
const unsigned char SBOX[8][16] = {
    { 3,  8, 15,  1, 10,  6,  5, 11, 14, 13,  4,  2,  7,  0,  9, 12},
    {15, 12,  2,  7,  9,  0,  5, 10,  1, 11, 14,  8,  6, 13,  3,  4},
    { 8,  6,  7,  9,  3, 12, 10, 15, 13,  1, 14,  4,  0, 11,  5,  2},
    { 0, 15, 11,  8, 12,  9,  6,  3, 13,  1,  2,  4, 10,  7,  5, 14},
    { 1, 15,  8,  3, 12,  0, 11,  6,  2,  5,  4, 10,  9, 14,  7, 13},
    {15,  5,  2, 11,  4, 10,  9, 12,  0,  3, 14,  8, 13,  6,  7,  1},
    { 7,  2, 12,  5,  8,  4,  6, 11, 14,  9,  1, 15, 13,  3, 10,  0},
    { 1, 13, 15,  0, 14,  8,  2, 11,  7,  4, 12, 10,  9,  3,  5,  6}
};

// The golden ratio constant used by the key schedule.
const unsigned int PHI = 0x9E3779B9;

inline unsigned int rotl(unsigned int x, unsigned int n) {
    return n == 0 ? x : ((x << n) | (x >> (32 - n)));
}

inline unsigned int rotr(unsigned int x, unsigned int n) {
    return n == 0 ? x : ((x >> n) | (x << (32 - n)));
}

}  // namespace

// The substitution is applied to all four words at once. Rather than walking
// the 32 bit positions one at a time, each of the sixteen possible inputs is
// turned into a mask selecting the positions holding that value, so every
// position is handled in parallel by ordinary word operations.
//
// The masks are the minterms of the four input words, so this is derived from
// the substitution table itself and holds for any 4 bit box, forward or
// inverse, without hand written boolean expressions per box.
namespace {

inline void substitute(const unsigned char* box, unsigned int* x) {

    unsigned int literal[4][2];

    for (unsigned int word = 0; word < 4; word++) {
        literal[word][1] = x[word];
        literal[word][0] = ~x[word];
    }

    unsigned int out[4] = {0, 0, 0, 0};

    for (unsigned int value = 0; value < 16; value++) {

        unsigned int mask = literal[0][(value) & 1]
                          & literal[1][(value >> 1) & 1]
                          & literal[2][(value >> 2) & 1]
                          & literal[3][(value >> 3) & 1];

        if (mask == 0) {
            continue;
        }

        unsigned int mapped = box[value];

        for (unsigned int word = 0; word < 4; word++) {

            if ((mapped >> word) & 1) {
                out[word] |= mask;
            }
        }
    }

    for (unsigned int word = 0; word < 4; word++) {
        x[word] = out[word];
    }
}

// The inverse boxes are derived once at load rather than rebuilt on every
// call, which the previous version did for all 32 rounds of every block.
struct InverseBoxes {

    unsigned char box[8][16];

    InverseBoxes() {

        for (unsigned int index = 0; index < 8; index++) {

            for (unsigned int i = 0; i < 16; i++) {
                box[index][SBOX[index][i]] = static_cast<unsigned char>(i);
            }
        }
    }
};

const InverseBoxes INVERSE;

}  // namespace

void Serpent::applySbox(unsigned int index, unsigned int* x) {
    substitute(SBOX[index], x);
}

void Serpent::applySboxInverse(unsigned int index, unsigned int* x) {
    substitute(INVERSE.box[index], x);
}

void Serpent::linearTransform(unsigned int* x) {

    x[0] = rotl(x[0], 13);
    x[2] = rotl(x[2], 3);
    x[1] = x[1] ^ x[0] ^ x[2];
    x[3] = x[3] ^ x[2] ^ (x[0] << 3);
    x[1] = rotl(x[1], 1);
    x[3] = rotl(x[3], 7);
    x[0] = x[0] ^ x[1] ^ x[3];
    x[2] = x[2] ^ x[3] ^ (x[1] << 7);
    x[0] = rotl(x[0], 5);
    x[2] = rotl(x[2], 22);
}

void Serpent::linearTransformInverse(unsigned int* x) {

    x[2] = rotr(x[2], 22);
    x[0] = rotr(x[0], 5);
    x[2] = x[2] ^ x[3] ^ (x[1] << 7);
    x[0] = x[0] ^ x[1] ^ x[3];
    x[3] = rotr(x[3], 7);
    x[1] = rotr(x[1], 1);
    x[3] = x[3] ^ x[2] ^ (x[0] << 3);
    x[1] = x[1] ^ x[0] ^ x[2];
    x[2] = rotr(x[2], 3);
    x[0] = rotr(x[0], 13);
}

std::string Serpent::getName() {
    return "serpent";
}

std::size_t Serpent::getVersion() {
    return 1;
}

std::size_t Serpent::getBlockSize() {
    return SERPENT_BLOCK_LEN;
}

std::vector<std::size_t> Serpent::getKeySizes() {
    return std::vector<std::size_t>{16, 24, 32};
}

void Serpent::reset() {

    unsigned char key[32];
    std::fill_n(key, 32, 0);

    std::size_t length = _key.size() > 32 ? 32 : _key.size();
    std::copy_n(_key.begin(), length, key);

    // A key shorter than 256 bits is padded with a single one bit followed by
    // zeros, which in byte terms is one 0x01 immediately after the key.
    if (length < 32) {
        key[length] = 0x01;
    }

    // w holds the eight prekey words followed by the 132 derived words, so
    // index 8 + i is the w_i of the specification.
    unsigned int w[140];

    for (unsigned int i = 0; i < 8; i++) {
        w[i] = load(reinterpret_cast<const char*>(key + 4 * i));
    }

    for (unsigned int i = 0; i < 132; i++) {
        w[8 + i] = rotl(w[i] ^ w[3 + i] ^ w[5 + i] ^ w[7 + i] ^ PHI ^ i, 11);
    }

    // Each group of four derived words becomes one subkey, substituted with a
    // box index that walks backwards from three.
    for (unsigned int group = 0; group <= SERPENT_ROUNDS; group++) {

        unsigned int block[4];

        for (unsigned int word = 0; word < 4; word++) {
            block[word] = w[8 + 4 * group + word];
        }

        applySbox((3 + 8 * SERPENT_ROUNDS - group) % 8, block);

        for (unsigned int word = 0; word < 4; word++) {
            _subkeys[group][word] = block[word];
        }
    }
}

std::vector<char> Serpent::encrypt(const std::vector<char> plaintext) {

    std::vector<char> ciphertext(plaintext.size());

    for (std::size_t offset = 0; offset + SERPENT_BLOCK_LEN <= plaintext.size(); offset += SERPENT_BLOCK_LEN) {

        const char* in = plaintext.data() + offset;

        unsigned int x[4];

        for (unsigned int word = 0; word < 4; word++) {
            x[word] = load(in + 4 * word);
        }

        for (unsigned int round = 0; round < SERPENT_ROUNDS; round++) {

            for (unsigned int word = 0; word < 4; word++) {
                x[word] ^= _subkeys[round][word];
            }

            applySbox(round % 8, x);

            // The last round uses a further subkey instead of the transform.
            if (round == SERPENT_ROUNDS - 1) {

                for (unsigned int word = 0; word < 4; word++) {
                    x[word] ^= _subkeys[SERPENT_ROUNDS][word];
                }

            } else {
                linearTransform(x);
            }
        }

        char* out = ciphertext.data() + offset;

        for (unsigned int word = 0; word < 4; word++) {
            store(out + 4 * word, x[word]);
        }
    }

    return ciphertext;
}

std::vector<char> Serpent::decrypt(const std::vector<char> ciphertext) {

    std::vector<char> plaintext(ciphertext.size());

    for (std::size_t offset = 0; offset + SERPENT_BLOCK_LEN <= ciphertext.size(); offset += SERPENT_BLOCK_LEN) {

        const char* in = ciphertext.data() + offset;

        unsigned int x[4];

        for (unsigned int word = 0; word < 4; word++) {
            x[word] = load(in + 4 * word);
        }

        for (int round = SERPENT_ROUNDS - 1; round >= 0; round--) {

            if (round == static_cast<int>(SERPENT_ROUNDS) - 1) {

                for (unsigned int word = 0; word < 4; word++) {
                    x[word] ^= _subkeys[SERPENT_ROUNDS][word];
                }

            } else {
                linearTransformInverse(x);
            }

            applySboxInverse(round % 8, x);

            for (unsigned int word = 0; word < 4; word++) {
                x[word] ^= _subkeys[round][word];
            }
        }

        char* out = plaintext.data() + offset;

        for (unsigned int word = 0; word < 4; word++) {
            store(out + 4 * word, x[word]);
        }
    }

    return plaintext;
}

};

};
