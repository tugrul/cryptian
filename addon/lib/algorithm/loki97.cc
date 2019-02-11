

#include "loki97.h"

namespace cryptian {

namespace algorithm {


Loki97::Loki97() {

    unsigned int i, j, v;

	/* initialise S box 1 */

	for (i = 0; i < S1_LEN; ++i) {
		j = v = i ^ S1_MASK;
		v = ff_mult(v, j, S1_SIZE, S1_POLY);
		sb1[i] = (unsigned char) ff_mult(v, j, S1_SIZE, S1_POLY);
	}
	/* initialise S box 2 */

	for (i = 0; i < S2_LEN; ++i) {
		j = v = i ^ S2_MASK;
		v = ff_mult(v, j, S2_SIZE, S2_POLY);
		sb2[i] = (unsigned char) ff_mult(v, j, S2_SIZE, S2_POLY);
	}

	/* initialise permutation table */

	for (i = 0; i < 256; ++i) {
		prm[i][0] =
		    ((i & 1) << 7) | ((i & 2) << 14) | ((i & 4) << 21) |
		    ((i & 8) << 28);
		prm[i][1] =
		    ((i & 16) << 3) | ((i & 32) << 10) | ((i & 64) << 17) |
		    ((i & 128) << 24);
	}

}

std::string Loki97::getName() {
    return "LOKI97";
}

std::size_t Loki97::getVersion() {
    return 20010801;
}

std::size_t Loki97::getBlockSize() {
    return 16;
}

std::vector<std::size_t> Loki97::getKeySizes() {
    return {16, 24, 32};
}


std::vector<char> Loki97::encrypt(const std::vector<char> plaintext) {

    block blk = {};

    std::copy_n(plaintext.begin(), plaintext.size() > 16 ? 16 : plaintext.size(), blk.c);

    std::reverse(blk.ui, blk.ui + 4);

    for (size_t i = 0 ; i < 4; i++) {
        blk.ui[i] = byteswapBE(blk.ui[i]);
    }

	r_fun(blk.ui, blk.ui + 2, l_key + 0);
	r_fun(blk.ui + 2, blk.ui, l_key + 6);
	r_fun(blk.ui, blk.ui + 2, l_key + 12);
	r_fun(blk.ui + 2, blk.ui, l_key + 18);
	r_fun(blk.ui, blk.ui + 2, l_key + 24);
	r_fun(blk.ui + 2, blk.ui, l_key + 30);
	r_fun(blk.ui, blk.ui + 2, l_key + 36);
	r_fun(blk.ui + 2, blk.ui, l_key + 42);
	r_fun(blk.ui, blk.ui + 2, l_key + 48);
	r_fun(blk.ui + 2, blk.ui, l_key + 54);
	r_fun(blk.ui, blk.ui + 2, l_key + 60);
	r_fun(blk.ui + 2, blk.ui, l_key + 66);
	r_fun(blk.ui, blk.ui + 2, l_key + 72);
	r_fun(blk.ui + 2, blk.ui, l_key + 78);
	r_fun(blk.ui, blk.ui + 2, l_key + 84);
	r_fun(blk.ui + 2, blk.ui, l_key + 90);

    block ciphertext;

    ciphertext.ui[3] = byteswapBE(blk.ui[2]);
	ciphertext.ui[2] = byteswapBE(blk.ui[3]);
	ciphertext.ui[1] = byteswapBE(blk.ui[0]);
	ciphertext.ui[0] = byteswapBE(blk.ui[1]);

    return std::vector<char>(ciphertext.c, ciphertext.c + 16);
}

std::vector<char> Loki97::decrypt(const std::vector<char> ciphertext) {

    unsigned int xs;

    block blk = {};

    std::copy_n(ciphertext.begin(), ciphertext.size() > 16 ? 16 : ciphertext.size(), blk.c);

    std::reverse(blk.ui, blk.ui + 4);

    for (size_t i = 0 ; i < 4; i++) {
        blk.ui[i] = byteswapBE(blk.ui[i]);
    }

	ir_fun(blk.ui, blk.ui + 2, l_key + 90, xs);
	ir_fun(blk.ui + 2, blk.ui, l_key + 84, xs);
	ir_fun(blk.ui, blk.ui + 2, l_key + 78, xs);
	ir_fun(blk.ui + 2, blk.ui, l_key + 72, xs);
	ir_fun(blk.ui, blk.ui + 2, l_key + 66, xs);
	ir_fun(blk.ui + 2, blk.ui, l_key + 60, xs);
	ir_fun(blk.ui, blk.ui + 2, l_key + 54, xs);
	ir_fun(blk.ui + 2, blk.ui, l_key + 48, xs);
	ir_fun(blk.ui, blk.ui + 2, l_key + 42, xs);
	ir_fun(blk.ui + 2, blk.ui, l_key + 36, xs);
	ir_fun(blk.ui, blk.ui + 2, l_key + 30, xs);
	ir_fun(blk.ui + 2, blk.ui, l_key + 24, xs);
	ir_fun(blk.ui, blk.ui + 2, l_key + 18, xs);
	ir_fun(blk.ui + 2, blk.ui, l_key + 12, xs);
	ir_fun(blk.ui, blk.ui + 2, l_key + 6, xs);
	ir_fun(blk.ui + 2, blk.ui, l_key, xs);


    block plaintext;

    plaintext.ui[3] = byteswapBE(blk.ui[2]);
    plaintext.ui[2] = byteswapBE(blk.ui[3]);
    plaintext.ui[1] = byteswapBE(blk.ui[0]);
    plaintext.ui[0] = byteswapBE(blk.ui[1]);

    return std::vector<char>(plaintext.c, plaintext.c + 16);
}

void Loki97::reset() {

    unsigned int i, k1[2], k2[2], k3[2], k4[2], del[2], tt[2], sk[2];

    key_block in_key;

    std::copy_n(_key.begin(), _key.size() > 32 ? 32 : _key.size(), in_key.c);

    k4[0] = byteswapBE(in_key.ui[1]);
    k4[1] = byteswapBE(in_key.ui[0]);
    k3[0] = byteswapBE(in_key.ui[3]);
    k3[1] = byteswapBE(in_key.ui[2]);


    k2[0] = byteswapBE(in_key.ui[5]);
    k2[1] = byteswapBE(in_key.ui[4]);
    k1[0] = byteswapBE(in_key.ui[7]);
    k1[1] = byteswapBE(in_key.ui[6]);

    del[0] = delta[0];
    del[1] = delta[1];

    for (i = 0; i < 48; ++i) {
        tt[0] = k1[0];
        tt[1] = k1[1];

        add_eq(tt, k3);
        add_eq(tt, del);
        add_eq(del, delta);

        sk[0] = k4[0];
        sk[1] = k4[1];
        k4[0] = k3[0];
        k4[1] = k3[1];
        k3[0] = k2[0];
        k3[1] = k2[1];
        k2[0] = k1[0];
        k2[1] = k1[1];
        k1[0] = sk[0];
        k1[1] = sk[1];

        f_fun(k1, tt, k3);

        l_key[i + i] = k1[0];
        l_key[i + i + 1] = k1[1];
    }

}

unsigned int Loki97::ff_mult(unsigned int a, unsigned int b, unsigned int tpow, unsigned int mpol)
{
	unsigned int s, m;

	s = 0;
	m = (1 << tpow);

	while (b) {
		if (b & 1)

			s ^= a;

		b >>= 1;
		a <<= 1;

		if (a & m)

			a ^= mpol;
	}

	return s;
}

void Loki97::f_fun(unsigned int res[2], const unsigned int in[2], const unsigned int key[2])
{
	unsigned int i, tt[2], pp[2];

    // tt[0] = in[0] & ~key[0] | in[1] & key[0];
    // tt[1] = in[1] & ~key[0] | in[0] & key[0];

	tt[0] = (in[0] & ~key[0]) | (in[1] & key[0]);
	tt[1] = (in[1] & ~key[0]) | (in[0] & key[0]);

	i = sb1[((tt[1] >> 24) | (tt[0] << 8)) & S1_MASK];
	pp[0] = prm[i][0] >> 7;
	pp[1] = prm[i][1] >> 7;
	i = sb2[(tt[1] >> 16) & S2_MASK];
	pp[0] |= prm[i][0] >> 6;
	pp[1] |= prm[i][1] >> 6;
	i = sb1[(tt[1] >> 8) & S1_MASK];
	pp[0] |= prm[i][0] >> 5;
	pp[1] |= prm[i][1] >> 5;
	i = sb2[tt[1] & S2_MASK];
	pp[0] |= prm[i][0] >> 4;
	pp[1] |= prm[i][1] >> 4;
	i = sb2[((tt[0] >> 24) | (tt[1] << 8)) & S2_MASK];
	pp[0] |= prm[i][0] >> 3;
	pp[1] |= prm[i][1] >> 3;
	i = sb1[(tt[0] >> 16) & S1_MASK];
	pp[0] |= prm[i][0] >> 2;
	pp[1] |= prm[i][1] >> 2;
	i = sb2[(tt[0] >> 8) & S2_MASK];
	pp[0] |= prm[i][0] >> 1;
	pp[1] |= prm[i][1] >> 1;
	i = sb1[tt[0] & S1_MASK];
	pp[0] |= prm[i][0];
	pp[1] |= prm[i][1];


    // res[0] ^=  sb1[getByte(pp[0], 0) | (key[1] <<  8) & S1_HMASK]
    //         | (sb1[getByte(pp[0], 1) | (key[1] <<  3) & S1_HMASK] << 8)
    //         | (sb2[getByte(pp[0], 2) | (key[1] >>  2) & S2_HMASK] << 16)
    //         | (sb2[getByte(pp[0], 3) | (key[1] >>  5) & S2_HMASK] << 24);
    // res[1] ^=  sb1[getByte(pp[1], 0) | (key[1] >>  8) & S1_HMASK]
    //         | (sb1[getByte(pp[1], 1) | (key[1] >> 13) & S1_HMASK] << 8)
    //         | (sb2[getByte(pp[1], 2) | (key[1] >> 18) & S2_HMASK] << 16)
    //         | (sb2[getByte(pp[1], 3) | (key[1] >> 21) & S2_HMASK] << 24);

	res[0] ^= sb1[getByte(pp[0], 0) | ((key[1] << 8) & S1_HMASK)]
	    | ((sb1[getByte(pp[0], 1) | ((key[1] << 3) & S1_HMASK)] << 8))
	    | ((sb2[getByte(pp[0], 2) | ((key[1] >> 2) & S2_HMASK)] << 16))
	    | ((sb2[getByte(pp[0], 3) | ((key[1] >> 5) & S2_HMASK)] << 24));
	res[1] ^= sb1[getByte(pp[1], 0) | ((key[1] >> 8) & S1_HMASK)]
	    | ((sb1[getByte(pp[1], 1) | ((key[1] >> 13) & S1_HMASK)] << 8))
	    | ((sb2[getByte(pp[1], 2) | ((key[1] >> 18) & S2_HMASK)] << 16))
	    | ((sb2[getByte(pp[1], 3) | ((key[1] >> 21) & S2_HMASK)] << 24));

}


};

};

