
#include "saferplus.h"

namespace cryptian {

namespace algorithm {

std::string Saferplus::getName() {
    return "Safer+";
}

std::size_t Saferplus::getVersion() {
    return 20010801;
}

std::size_t Saferplus::getBlockSize() {
    return 16;
}

std::vector<std::size_t> Saferplus::getKeySizes() {
    return {16, 24, 32};
}


std::vector<char> Saferplus::encrypt(const std::vector<char> plaintext) {

    block ciphertext = {};
    unsigned char *kp;
    size_t keySize = _key.size();

    std::copy_n(plaintext.begin(), plaintext.size() > 16 ? 16 : plaintext.size(), ciphertext.c);
    std::reverse(ciphertext.uc, ciphertext.uc + 16);

    for (size_t i = 0; i < 4; i++) {
        ciphertext.ui[i] = byteswapLE(ciphertext.ui[i]);
    }

    // i max 7  when keySize < 16
    // i max 11 when keysize > 16 and keySize < 24
    // i max 15 when keySize > 24
    for (size_t i = 0; i < ((keySize > 24) ? 16 : ((keySize > 16) ? 12 : 8)); i++) {
        do_fr(ciphertext.uc, i * 32);
    }

	kp = key + 16 * keySize;

    for (size_t i = 0; i < 8; i++) {

        size_t offset = i * 2;

        if ((i % 2) == 0) {
            ciphertext.uc[offset + 0] ^= kp[offset + 0];
        	ciphertext.uc[offset + 1] += kp[offset + 1];
        } else {
            ciphertext.uc[offset + 0] += kp[offset + 0];
        	ciphertext.uc[offset + 1] ^= kp[offset + 1];
        }

    }

    std::reverse(ciphertext.uc, ciphertext.uc + 16);

    for (size_t i = 0; i < 4; i++) {
        ciphertext.ui[i] = byteswapLE(ciphertext.ui[i]);
    }

    return std::vector<char>(ciphertext.c, ciphertext.c + 16);
}

std::vector<char> Saferplus::decrypt(const std::vector<char> ciphertext) {

    block plaintext = {};
    unsigned char *kp;
    size_t keySize = _key.size();


    std::copy_n(ciphertext.begin(), ciphertext.size() > 16 ? 16 : ciphertext.size(), plaintext.c);
    std::reverse(plaintext.uc, plaintext.uc + 16);

    for (size_t i = 0; i < 4; i++) {
        plaintext.ui[i] = byteswapLE(plaintext.ui[i]);
    }

    kp = key + 16 * keySize;

    for (size_t i = 0; i < 8; i++) {

        size_t offset = i * 2;

        if ((i % 2) == 0) {
            plaintext.uc[offset + 0] ^= kp[offset + 0];
        	plaintext.uc[offset + 1] -= kp[offset + 1];
        } else {
            plaintext.uc[offset + 0] -= kp[offset + 0];
        	plaintext.uc[offset + 1] ^= kp[offset + 1];
        }

    }

    // i max 7  when keySize < 16
    // i max 11 when keysize > 16 and keySize < 24
    // i max 15 when keySize > 24
    for (int i = ((keySize > 24) ? 15 : ((keySize > 16) ? 11 : 7)); i >= 0 ; i--) {
        do_ir(plaintext.uc, i * 32);
    }

    std::reverse(plaintext.uc, plaintext.uc + 16);

    for (size_t i = 0; i < 4; i++) {
        plaintext.ui[i] = byteswapLE(plaintext.ui[i]);
    }

    return std::vector<char>(plaintext.c, plaintext.c + 16);
}

void Saferplus::reset() {

	unsigned int k, l, m;

    key_block localKey;

    size_t keySize = _key.size() > 32 ? 32 : _key.size();

    std::fill_n(localKey.ui, 9, 0);

    for (size_t i = 0; i < keySize; i++) {
        localKey.c[i] = _key[keySize - i - 1];
    }

    for (size_t i = 0; i < 9; i++) {
        localKey.ui[i] = byteswapLE(localKey.ui[i]);
    }

    localKey.uc[keySize] = 0;

	for (size_t i = 0; i < keySize; ++i) {
		localKey.uc[keySize] ^= localKey.uc[i];
		key[i] = localKey.uc[i];
	}

	for (size_t i = 0; i < keySize; ++i) {

		for (size_t j = 0; j <= keySize; ++j) {
            localKey.uc[j] = rotl8(localKey.uc[j], 3);
		}

		k = 17 * i + 35;
		l = 16 * i + 16;
		m = i + 1;

		if (i < 16) {
			for (size_t j = 0; j < 16; ++j) {
				key[l + j] = localKey.uc[m] + safer_expf[safer_expf[(k + j) & 255]];

				m = (m == keySize ? 0 : m + 1);
			}
		} else {
			for (size_t j = 0; j < 16; ++j) {
				key[l + j] = localKey.uc[m] + safer_expf[(k + j) & 255];

				m = (m == keySize ? 0 : m + 1);
			}
		}
	}
}


void Saferplus::do_fr(unsigned char x[16], unsigned short offset)
{
	unsigned char t;
    unsigned char *kp = key + offset;

	x[0] = safer_expf[x[0] ^ kp[0]] + kp[16];
	x[1] = safer_logf[x[1] + kp[1]] ^ kp[17];
	x[2] = safer_logf[x[2] + kp[2]] ^ kp[18];
	x[3] = safer_expf[x[3] ^ kp[3]] + kp[19];

	x[4] = safer_expf[x[4] ^ kp[4]] + kp[20];
	x[5] = safer_logf[x[5] + kp[5]] ^ kp[21];
	x[6] = safer_logf[x[6] + kp[6]] ^ kp[22];
	x[7] = safer_expf[x[7] ^ kp[7]] + kp[23];

	x[8] = safer_expf[x[8] ^ kp[8]] + kp[24];
	x[9] = safer_logf[x[9] + kp[9]] ^ kp[25];
	x[10] = safer_logf[x[10] + kp[10]] ^ kp[26];
	x[11] = safer_expf[x[11] ^ kp[11]] + kp[27];

	x[12] = safer_expf[x[12] ^ kp[12]] + kp[28];
	x[13] = safer_logf[x[13] + kp[13]] ^ kp[29];
	x[14] = safer_logf[x[14] + kp[14]] ^ kp[30];
	x[15] = safer_expf[x[15] ^ kp[15]] + kp[31];

	x[1] += x[0];
	x[0] += x[1];
	x[3] += x[2];
	x[2] += x[3];
	x[5] += x[4];
	x[4] += x[5];
	x[7] += x[6];
	x[6] += x[7];
	x[9] += x[8];
	x[8] += x[9];
	x[11] += x[10];
	x[10] += x[11];
	x[13] += x[12];
	x[12] += x[13];
	x[15] += x[14];
	x[14] += x[15];

	x[7] += x[0];
	x[0] += x[7];
	x[1] += x[2];
	x[2] += x[1];
	x[3] += x[4];
	x[4] += x[3];
	x[5] += x[6];
	x[6] += x[5];
	x[11] += x[8];
	x[8] += x[11];
	x[9] += x[10];
	x[10] += x[9];
	x[15] += x[12];
	x[12] += x[15];
	x[13] += x[14];
	x[14] += x[13];

	x[3] += x[0];
	x[0] += x[3];
	x[15] += x[2];
	x[2] += x[15];
	x[7] += x[4];
	x[4] += x[7];
	x[1] += x[6];
	x[6] += x[1];
	x[5] += x[8];
	x[8] += x[5];
	x[13] += x[10];
	x[10] += x[13];
	x[11] += x[12];
	x[12] += x[11];
	x[9] += x[14];
	x[14] += x[9];

	x[13] += x[0];
	x[0] += x[13];
	x[5] += x[2];
	x[2] += x[5];
	x[9] += x[4];
	x[4] += x[9];
	x[11] += x[6];
	x[6] += x[11];
	x[15] += x[8];
	x[8] += x[15];
	x[1] += x[10];
	x[10] += x[1];
	x[3] += x[12];
	x[12] += x[3];
	x[7] += x[14];
	x[14] += x[7];

	t = x[0];
	x[0] = x[14];
	x[14] = x[12];
	x[12] = x[10];
	x[10] = x[2];
	x[2] = x[8];
	x[8] = x[4];
	x[4] = t;

	t = x[1];
	x[1] = x[7];
	x[7] = x[11];
	x[11] = x[5];
	x[5] = x[13];
	x[13] = t;

	t = x[15];
	x[15] = x[3];
	x[3] = t;
}

void Saferplus::do_ir(unsigned char x[16], unsigned short offset)
{
	unsigned char t;
    unsigned char *kp = key + offset;

	t = x[3];
	x[3] = x[15];
	x[15] = t;

	t = x[13];
	x[13] = x[5];
	x[5] = x[11];
	x[11] = x[7];
	x[7] = x[1];
	x[1] = t;

	t = x[4];
	x[4] = x[8];
	x[8] = x[2];
	x[2] = x[10];
	x[10] = x[12];
	x[12] = x[14];
	x[14] = x[0];
	x[0] = t;

	x[14] -= x[7];
	x[7] -= x[14];
	x[12] -= x[3];
	x[3] -= x[12];
	x[10] -= x[1];
	x[1] -= x[10];
	x[8] -= x[15];
	x[15] -= x[8];
	x[6] -= x[11];
	x[11] -= x[6];
	x[4] -= x[9];
	x[9] -= x[4];
	x[2] -= x[5];
	x[5] -= x[2];
	x[0] -= x[13];
	x[13] -= x[0];

	x[14] -= x[9];
	x[9] -= x[14];
	x[12] -= x[11];
	x[11] -= x[12];
	x[10] -= x[13];
	x[13] -= x[10];
	x[8] -= x[5];
	x[5] -= x[8];
	x[6] -= x[1];
	x[1] -= x[6];
	x[4] -= x[7];
	x[7] -= x[4];
	x[2] -= x[15];
	x[15] -= x[2];
	x[0] -= x[3];
	x[3] -= x[0];

	x[14] -= x[13];
	x[13] -= x[14];
	x[12] -= x[15];
	x[15] -= x[12];
	x[10] -= x[9];
	x[9] -= x[10];
	x[8] -= x[11];
	x[11] -= x[8];
	x[6] -= x[5];
	x[5] -= x[6];
	x[4] -= x[3];
	x[3] -= x[4];
	x[2] -= x[1];
	x[1] -= x[2];
	x[0] -= x[7];
	x[7] -= x[0];

	x[14] -= x[15];
	x[15] -= x[14];
	x[12] -= x[13];
	x[13] -= x[12];
	x[10] -= x[11];
	x[11] -= x[10];
	x[8] -= x[9];
	x[9] -= x[8];
	x[6] -= x[7];
	x[7] -= x[6];
	x[4] -= x[5];
	x[5] -= x[4];
	x[2] -= x[3];
	x[3] -= x[2];
	x[0] -= x[1];
	x[1] -= x[0];

	x[0] = safer_logf[x[0] - kp[16] + 256] ^ kp[0];
	x[1] = safer_expf[x[1] ^ kp[17]] - kp[1];
	x[2] = safer_expf[x[2] ^ kp[18]] - kp[2];
	x[3] = safer_logf[x[3] - kp[19] + 256] ^ kp[3];

	x[4] = safer_logf[x[4] - kp[20] + 256] ^ kp[4];
	x[5] = safer_expf[x[5] ^ kp[21]] - kp[5];
	x[6] = safer_expf[x[6] ^ kp[22]] - kp[6];
	x[7] = safer_logf[x[7] - kp[23] + 256] ^ kp[7];

	x[8] = safer_logf[x[8] - kp[24] + 256] ^ kp[8];
	x[9] = safer_expf[x[9] ^ kp[25]] - kp[9];
	x[10] = safer_expf[x[10] ^ kp[26]] - kp[10];
	x[11] = safer_logf[x[11] - kp[27] + 256] ^ kp[11];

	x[12] = safer_logf[x[12] - kp[28] + 256] ^ kp[12];
	x[13] = safer_expf[x[13] ^ kp[29]] - kp[13];
	x[14] = safer_expf[x[14] ^ kp[30]] - kp[14];
	x[15] = safer_logf[x[15] - kp[31] + 256] ^ kp[15];
}

const unsigned char Saferplus::safer_expf[256] = {
    1, 45, 226, 147, 190, 69, 21, 174, 120, 3, 135, 164, 184, 56, 207,
	63,
	8, 103, 9, 148, 235, 38, 168, 107, 189, 24, 52, 27, 187, 191, 114,
	247,
	64, 53, 72, 156, 81, 47, 59, 85, 227, 192, 159, 216, 211, 243, 141,
	177,
	255, 167, 62, 220, 134, 119, 215, 166, 17, 251, 244, 186, 146, 145,
	100, 131,
	241, 51, 239, 218, 44, 181, 178, 43, 136, 209, 153, 203, 140, 132,
	29, 20,
	129, 151, 113, 202, 95, 163, 139, 87, 60, 130, 196, 82, 92, 28,
	232, 160,
	4, 180, 133, 74, 246, 19, 84, 182, 223, 12, 26, 142, 222, 224, 57,
	252,
	32, 155, 36, 78, 169, 152, 158, 171, 242, 96, 208, 108, 234, 250,
	199, 217,
	0, 212, 31, 110, 67, 188, 236, 83, 137, 254, 122, 93, 73, 201, 50,
	194,
	249, 154, 248, 109, 22, 219, 89, 150, 68, 233, 205, 230, 70, 66,
	143, 10,
	193, 204, 185, 101, 176, 210, 198, 172, 30, 65, 98, 41, 46, 14,
	116, 80,
	2, 90, 195, 37, 123, 138, 42, 91, 240, 6, 13, 71, 111, 112, 157,
	126,
	16, 206, 18, 39, 213, 76, 79, 214, 121, 48, 104, 54, 117, 125, 228,
	237,
	128, 106, 144, 55, 162, 94, 118, 170, 197, 127, 61, 175, 165, 229,
	25, 97,
	253, 77, 124, 183, 11, 238, 173, 75, 34, 245, 231, 115, 35, 33,
	200, 5,
	225, 102, 221, 179, 88, 105, 99, 86, 15, 161, 49, 149, 23, 7, 58,
	40
};

const unsigned char Saferplus::safer_logf[512] = {
	128, 0, 176, 9, 96, 239, 185, 253, 16, 18, 159, 228, 105, 186, 173,
	248,
	192, 56, 194, 101, 79, 6, 148, 252, 25, 222, 106, 27, 93, 78, 168,
	130,
	112, 237, 232, 236, 114, 179, 21, 195, 255, 171, 182, 71, 68, 1,
	172, 37,
	201, 250, 142, 65, 26, 33, 203, 211, 13, 110, 254, 38, 88, 218, 50,
	15,
	32, 169, 157, 132, 152, 5, 156, 187, 34, 140, 99, 231, 197, 225,
	115, 198,
	175, 36, 91, 135, 102, 39, 247, 87, 244, 150, 177, 183, 92, 139,
	213, 84,
	121, 223, 170, 246, 62, 163, 241, 17, 202, 245, 209, 23, 123, 147,
	131, 188,
	189, 82, 30, 235, 174, 204, 214, 53, 8, 200, 138, 180, 226, 205,
	191, 217,
	208, 80, 89, 63, 77, 98, 52, 10, 72, 136, 181, 86, 76, 46, 107,
	158,
	210, 61, 60, 3, 19, 251, 151, 81, 117, 74, 145, 113, 35, 190, 118,
	42,
	95, 249, 212, 85, 11, 220, 55, 49, 22, 116, 215, 119, 167, 230, 7,
	219,
	164, 47, 70, 243, 97, 69, 103, 227, 12, 162, 59, 28, 133, 24, 4,
	29,
	41, 160, 143, 178, 90, 216, 166, 126, 238, 141, 83, 75, 161, 154,
	193, 14,
	122, 73, 165, 44, 129, 196, 199, 54, 43, 127, 67, 149, 51, 242,
	108, 104,
	109, 240, 2, 40, 206, 221, 155, 234, 94, 153, 124, 20, 134, 207,
	229, 66,
	184, 64, 120, 45, 58, 233, 100, 31, 146, 144, 125, 57, 111, 224,
	137, 48,

	128, 0, 176, 9, 96, 239, 185, 253, 16, 18, 159, 228, 105, 186, 173,
	248,
	192, 56, 194, 101, 79, 6, 148, 252, 25, 222, 106, 27, 93, 78, 168,
	130,
	112, 237, 232, 236, 114, 179, 21, 195, 255, 171, 182, 71, 68, 1,
	172, 37,
	201, 250, 142, 65, 26, 33, 203, 211, 13, 110, 254, 38, 88, 218, 50,
	15,
	32, 169, 157, 132, 152, 5, 156, 187, 34, 140, 99, 231, 197, 225,
	115, 198,
	175, 36, 91, 135, 102, 39, 247, 87, 244, 150, 177, 183, 92, 139,
	213, 84,
	121, 223, 170, 246, 62, 163, 241, 17, 202, 245, 209, 23, 123, 147,
	131, 188,
	189, 82, 30, 235, 174, 204, 214, 53, 8, 200, 138, 180, 226, 205,
	191, 217,
	208, 80, 89, 63, 77, 98, 52, 10, 72, 136, 181, 86, 76, 46, 107,
	158,
	210, 61, 60, 3, 19, 251, 151, 81, 117, 74, 145, 113, 35, 190, 118,
	42,
	95, 249, 212, 85, 11, 220, 55, 49, 22, 116, 215, 119, 167, 230, 7,
	219,
	164, 47, 70, 243, 97, 69, 103, 227, 12, 162, 59, 28, 133, 24, 4,
	29,
	41, 160, 143, 178, 90, 216, 166, 126, 238, 141, 83, 75, 161, 154,
	193, 14,
	122, 73, 165, 44, 129, 196, 199, 54, 43, 127, 67, 149, 51, 242,
	108, 104,
	109, 240, 2, 40, 206, 221, 155, 234, 94, 153, 124, 20, 134, 207,
	229, 66,
	184, 64, 120, 45, 58, 233, 100, 31, 146, 144, 125, 57, 111, 224,
	137, 48
};

};

};

