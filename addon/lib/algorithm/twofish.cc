
#include "twofish.h"

namespace cryptian {

namespace algorithm {

namespace {

// The two byte permutations are built from the four bit permutations given in
// the Twofish paper rather than written out as 512 constants, so the structure
// stays visible and a transcription slip in a long table cannot hide.
const unsigned char Q0_TABLES[4][16] = {
    {0x8, 0x1, 0x7, 0xD, 0x6, 0xF, 0x3, 0x2, 0x0, 0xB, 0x5, 0x9, 0xE, 0xC, 0xA, 0x4},
    {0xE, 0xC, 0xB, 0x8, 0x1, 0x2, 0x3, 0x5, 0xF, 0x4, 0xA, 0x6, 0x7, 0x0, 0x9, 0xD},
    {0xB, 0xA, 0x5, 0xE, 0x6, 0xD, 0x9, 0x0, 0xC, 0x8, 0xF, 0x3, 0x2, 0x4, 0x7, 0x1},
    {0xD, 0x7, 0xF, 0x4, 0x1, 0x2, 0x6, 0xE, 0x9, 0xB, 0x3, 0x0, 0x8, 0x5, 0xC, 0xA}
};

const unsigned char Q1_TABLES[4][16] = {
    {0x2, 0x8, 0xB, 0xD, 0xF, 0x7, 0x6, 0xE, 0x3, 0x1, 0x9, 0x4, 0x0, 0xA, 0xC, 0x5},
    {0x1, 0xE, 0x2, 0xB, 0x4, 0xC, 0x3, 0x7, 0x6, 0xD, 0xA, 0x5, 0xF, 0x9, 0x0, 0x8},
    {0x4, 0xC, 0x7, 0x5, 0x1, 0x6, 0x9, 0xA, 0x0, 0xE, 0xD, 0x8, 0x2, 0xB, 0x3, 0xF},
    {0xB, 0x9, 0x5, 0x1, 0xC, 0x3, 0xD, 0xE, 0x6, 0x4, 0x7, 0xF, 0x2, 0x0, 0x8, 0xA}
};

// x^8 + x^6 + x^5 + x^3 + 1, used by the MDS matrix.
const unsigned int MDS_MODULUS = 0x169;

// x^8 + x^6 + x^3 + x^2 + 1, used by the Reed Solomon matrix.
const unsigned int RS_MODULUS = 0x14D;

const unsigned char MDS_MATRIX[4][4] = {
    {0x01, 0xEF, 0x5B, 0x5B},
    {0x5B, 0xEF, 0xEF, 0x01},
    {0xEF, 0x5B, 0x01, 0xEF},
    {0xEF, 0x01, 0xEF, 0x5B}
};

const unsigned char RS_MATRIX[4][8] = {
    {0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E},
    {0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5},
    {0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19},
    {0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03}
};

inline unsigned char ror4(unsigned char x) {
    return static_cast<unsigned char>(((x >> 1) | (x << 3)) & 0x0F);
}

inline unsigned int rotl32Bits(unsigned int x, unsigned int n) {
    return n == 0 ? x : ((x << n) | (x >> (32 - n)));
}

inline unsigned int rotr32Bits(unsigned int x, unsigned int n) {
    return n == 0 ? x : ((x >> n) | (x << (32 - n)));
}

}  // namespace

unsigned char Twofish::qPermute(const unsigned char t[4][16], unsigned char x) {

    unsigned char a0 = static_cast<unsigned char>(x >> 4);
    unsigned char b0 = static_cast<unsigned char>(x & 0x0F);

    unsigned char a1 = static_cast<unsigned char>(a0 ^ b0);
    unsigned char b1 = static_cast<unsigned char>((a0 ^ ror4(b0) ^ (a0 << 3)) & 0x0F);

    unsigned char a2 = t[0][a1];
    unsigned char b2 = t[1][b1];

    unsigned char a3 = static_cast<unsigned char>(a2 ^ b2);
    unsigned char b3 = static_cast<unsigned char>((a2 ^ ror4(b2) ^ (a2 << 3)) & 0x0F);

    unsigned char a4 = t[2][a3];
    unsigned char b4 = t[3][b3];

    return static_cast<unsigned char>((b4 << 4) | a4);
}

unsigned char Twofish::q0(unsigned char x) {
    return qPermute(Q0_TABLES, x);
}

unsigned char Twofish::q1(unsigned char x) {
    return qPermute(Q1_TABLES, x);
}

unsigned char Twofish::multiplyGf(unsigned char a, unsigned char b, unsigned int modulus) {

    unsigned int result = 0;
    unsigned int value = a;

    for (unsigned int i = 0; i < 8; i++) {

        if (b & (1 << i)) {
            result ^= value << i;
        }
    }

    // Reduce by the modulus, highest bit first.
    for (int bit = 15; bit >= 8; bit--) {

        if (result & (1u << bit)) {
            result ^= modulus << (bit - 8);
        }
    }

    return static_cast<unsigned char>(result & 0xFF);
}

unsigned int Twofish::multiplyMds(const unsigned char y[4]) {

    unsigned int result = 0;

    for (unsigned int row = 0; row < 4; row++) {

        unsigned char sum = 0;

        for (unsigned int col = 0; col < 4; col++) {
            sum = static_cast<unsigned char>(sum ^ multiplyGf(y[col], MDS_MATRIX[row][col], MDS_MODULUS));
        }

        result |= static_cast<unsigned int>(sum) << (8 * row);
    }

    return result;
}

unsigned int Twofish::reedSolomon(const unsigned char key[8]) {

    unsigned int result = 0;

    for (unsigned int row = 0; row < 4; row++) {

        unsigned char sum = 0;

        for (unsigned int col = 0; col < 8; col++) {
            sum = static_cast<unsigned char>(sum ^ multiplyGf(key[col], RS_MATRIX[row][col], RS_MODULUS));
        }

        result |= static_cast<unsigned int>(sum) << (8 * row);
    }

    return result;
}

unsigned char Twofish::sboxByte(unsigned int position, unsigned char y, const unsigned int* l, unsigned int words) {

    // Each byte position runs its own sequence of q permutations, interleaved
    // with the corresponding byte of each key word. The sequences differ per
    // position, which is why this cannot be written as one loop.
    const unsigned int shift = 8 * position;

    switch (position) {

        case 0:
            if (words == 4) {
                y = static_cast<unsigned char>(q1(y) ^ ((l[3] >> shift) & 0xFF));
            }
            if (words >= 3) {
                y = static_cast<unsigned char>(q1(y) ^ ((l[2] >> shift) & 0xFF));
            }
            return q1(static_cast<unsigned char>(q0(static_cast<unsigned char>(q0(y) ^ ((l[1] >> shift) & 0xFF))) ^ ((l[0] >> shift) & 0xFF)));

        case 1:
            if (words == 4) {
                y = static_cast<unsigned char>(q0(y) ^ ((l[3] >> shift) & 0xFF));
            }
            if (words >= 3) {
                y = static_cast<unsigned char>(q1(y) ^ ((l[2] >> shift) & 0xFF));
            }
            return q0(static_cast<unsigned char>(q0(static_cast<unsigned char>(q1(y) ^ ((l[1] >> shift) & 0xFF))) ^ ((l[0] >> shift) & 0xFF)));

        case 2:
            if (words == 4) {
                y = static_cast<unsigned char>(q0(y) ^ ((l[3] >> shift) & 0xFF));
            }
            if (words >= 3) {
                y = static_cast<unsigned char>(q0(y) ^ ((l[2] >> shift) & 0xFF));
            }
            return q1(static_cast<unsigned char>(q1(static_cast<unsigned char>(q0(y) ^ ((l[1] >> shift) & 0xFF))) ^ ((l[0] >> shift) & 0xFF)));

        default:
            if (words == 4) {
                y = static_cast<unsigned char>(q1(y) ^ ((l[3] >> shift) & 0xFF));
            }
            if (words >= 3) {
                y = static_cast<unsigned char>(q0(y) ^ ((l[2] >> shift) & 0xFF));
            }
            return q0(static_cast<unsigned char>(q1(static_cast<unsigned char>(q1(y) ^ ((l[1] >> shift) & 0xFF))) ^ ((l[0] >> shift) & 0xFF)));
    }
}

unsigned int Twofish::h(unsigned int x, const unsigned int* l, unsigned int words) {

    unsigned char y[4];

    for (unsigned int i = 0; i < 4; i++) {
        y[i] = sboxByte(i, static_cast<unsigned char>((x >> (8 * i)) & 0xFF), l, words);
    }

    return multiplyMds(y);
}

std::string Twofish::getName() {
    return "twofish";
}

std::size_t Twofish::getVersion() {
    return 1;
}

std::size_t Twofish::getBlockSize() {
    return TWOFISH_BLOCK_LEN;
}

std::vector<std::size_t> Twofish::getKeySizes() {
    return std::vector<std::size_t>{16, 24, 32};
}

void Twofish::reset() {

    // Shorter keys are zero extended to the next supported length, matching the
    // way mcrypt padded a key that did not fill the cipher.
    unsigned char key[32];
    std::fill_n(key, 32, 0);

    std::size_t length = _key.size() > 32 ? 32 : _key.size();
    std::copy_n(_key.begin(), length, key);

    if (length <= 16) {
        _words = 2;
    } else if (length <= 24) {
        _words = 3;
    } else {
        _words = 4;
    }

    unsigned int even[4];
    unsigned int odd[4];
    unsigned int s[4];

    for (unsigned int i = 0; i < _words; i++) {

        const unsigned char* group = key + 8 * i;

        even[i] = load(reinterpret_cast<const char*>(group));
        odd[i] = load(reinterpret_cast<const char*>(group + 4));

        // The Reed Solomon words are used in reverse order.
        s[_words - 1 - i] = reedSolomon(group);
    }

    const unsigned int rho = 0x01010101;

    for (unsigned int i = 0; i < 8 + 2 * TWOFISH_ROUNDS; i += 2) {

        unsigned int a = h(i * rho, even, _words);
        unsigned int b = rotl32Bits(h((i + 1) * rho, odd, _words), 8);

        _subkeys[i] = a + b;
        _subkeys[i + 1] = rotl32Bits(a + 2 * b, 9);
    }

    // Fold the key dependent s-box through the MDS matrix once per byte
    // position so the round function becomes four table lookups.
    for (unsigned int position = 0; position < 4; position++) {

        for (unsigned int value = 0; value < 256; value++) {

            unsigned char permuted = sboxByte(position, static_cast<unsigned char>(value), s, _words);

            unsigned int column = 0;

            for (unsigned int row = 0; row < 4; row++) {
                column |= static_cast<unsigned int>(multiplyGf(permuted, MDS_MATRIX[row][position], MDS_MODULUS)) << (8 * row);
            }

            _sbox[position][value] = column;
        }
    }
}

std::vector<char> Twofish::encrypt(const std::vector<char> plaintext) {

    // Sized to whole blocks. Sizing to the input length left any trailing
    // partial block as zeros, which looked like a successful result.
    std::vector<char> ciphertext((plaintext.size() / TWOFISH_BLOCK_LEN) * TWOFISH_BLOCK_LEN);

    for (std::size_t offset = 0; offset + TWOFISH_BLOCK_LEN <= plaintext.size(); offset += TWOFISH_BLOCK_LEN) {

        const char* in = plaintext.data() + offset;

        unsigned int r0 = load(in) ^ _subkeys[0];
        unsigned int r1 = load(in + 4) ^ _subkeys[1];
        unsigned int r2 = load(in + 8) ^ _subkeys[2];
        unsigned int r3 = load(in + 12) ^ _subkeys[3];

        for (unsigned int round = 0; round < TWOFISH_ROUNDS; round++) {

            unsigned int t0 = g(r0);
            unsigned int t1 = g(rotl32Bits(r1, 8));

            unsigned int f0 = t0 + t1 + _subkeys[8 + 2 * round];
            unsigned int f1 = t0 + 2 * t1 + _subkeys[9 + 2 * round];

            r2 = rotr32Bits(r2 ^ f0, 1);
            r3 = rotl32Bits(r3, 1) ^ f1;

            // Swap the halves, except after the final round.
            if (round < TWOFISH_ROUNDS - 1) {
                unsigned int swap0 = r0;
                unsigned int swap1 = r1;
                r0 = r2;
                r1 = r3;
                r2 = swap0;
                r3 = swap1;
            }
        }

        char* out = ciphertext.data() + offset;

        // Skipping the swap on the final round is what undoes it, so the
        // registers are already in output order here.
        store(out, r0 ^ _subkeys[4]);
        store(out + 4, r1 ^ _subkeys[5]);
        store(out + 8, r2 ^ _subkeys[6]);
        store(out + 12, r3 ^ _subkeys[7]);
    }

    return ciphertext;
}

std::vector<char> Twofish::decrypt(const std::vector<char> ciphertext) {

    std::vector<char> plaintext((ciphertext.size() / TWOFISH_BLOCK_LEN) * TWOFISH_BLOCK_LEN);

    for (std::size_t offset = 0; offset + TWOFISH_BLOCK_LEN <= ciphertext.size(); offset += TWOFISH_BLOCK_LEN) {

        const char* in = ciphertext.data() + offset;

        unsigned int r0 = load(in) ^ _subkeys[4];
        unsigned int r1 = load(in + 4) ^ _subkeys[5];
        unsigned int r2 = load(in + 8) ^ _subkeys[6];
        unsigned int r3 = load(in + 12) ^ _subkeys[7];

        for (int round = TWOFISH_ROUNDS - 1; round >= 0; round--) {

            unsigned int t0 = g(r0);
            unsigned int t1 = g(rotl32Bits(r1, 8));

            unsigned int f0 = t0 + t1 + _subkeys[8 + 2 * round];
            unsigned int f1 = t0 + 2 * t1 + _subkeys[9 + 2 * round];

            r2 = rotl32Bits(r2, 1) ^ f0;
            r3 = rotr32Bits(r3 ^ f1, 1);

            if (round > 0) {
                unsigned int swap0 = r0;
                unsigned int swap1 = r1;
                r0 = r2;
                r1 = r3;
                r2 = swap0;
                r3 = swap1;
            }
        }

        char* out = plaintext.data() + offset;

        store(out, r0 ^ _subkeys[0]);
        store(out + 4, r1 ^ _subkeys[1]);
        store(out + 8, r2 ^ _subkeys[2]);
        store(out + 12, r3 ^ _subkeys[3]);
    }

    return plaintext;
}

};

};
