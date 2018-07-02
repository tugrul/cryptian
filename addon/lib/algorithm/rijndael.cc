
#include "rijndael.h"

namespace cryptian {

namespace algorithm {

Rijndael::Rijndael() {

	unsigned char y;
    unsigned char b[4];

	// use 3 as primitive root to generate power and log tables

	ltab[0] = 0;
	ptab[0] = 1;
	ltab[1] = 0;
	ptab[1] = 3;
	ltab[3] = 1;

	for (size_t i = 2; i < 256; i++) {
		ptab[i] = ptab[i - 1] ^ xtime(ptab[i - 1]);
		ltab[ptab[i]] = i;
	}

	// affine transformation:- each bit is xored with itself shifted one bit

	fbsub[0] = 0x63;
	rbsub[0x63] = 0;
	for (size_t i = 1; i < 256; i++) {
		y = byteSub((unsigned char) i);
		fbsub[i] = y;
		rbsub[y] = i;
	}

	for (size_t i = 0, y = 1; i < 30; i++) {
		rco[i] = y;
		y = xtime(y);
	}

	// calculate forward and reverse tables

	for (size_t i = 0; i < 256; i++) {
		y = fbsub[i];
		b[3] = y ^ xtime(y);
		b[2] = y;
		b[1] = y;
		b[0] = xtime(y);
		ftable[i] = pack(b);

		y = rbsub[i];
		b[3] = bmul(InCo[0], y);
		b[2] = bmul(InCo[1], y);
		b[1] = bmul(InCo[2], y);
		b[0] = bmul(InCo[3], y);
		rtable[i] = pack(b);
	}

}


std::size_t Rijndael::getVersion() {
    return 20010801;
}

std::size_t Rijndael::getBlockSize() {
    return Nb * 4;
}

std::vector<std::size_t> Rijndael::getKeySizes() {
    return {16, 24, 32};
}


std::vector<char> Rijndael::encrypt(const std::vector<char> plaintext) {

    size_t blockSize = getBlockSize();

    unsigned char ciphertext[32];

    std::copy_n(plaintext.begin(), plaintext.size() > blockSize ? blockSize : plaintext.size(), ciphertext);

    int i, j, k, m;
	unsigned int a[8], b[8], *x, *y, *t;

	for (i = j = 0; i < Nb; i++, j += 4) {
		a[i] = pack(ciphertext + j);
		a[i] ^= fkey[i];
	}

	k = Nb;
	x = a;
	y = b;

    // State alternates between a and b
	for (i = 1; i < Nr; i++) {	// Nr is number of rounds. May be odd.

    // if Nb is fixed - unroll this next
    // loop and hard-code in the values of fi[]

		for (m = j = 0; j < Nb; j++, m += 3) {	// deal with each 32-bit element of the State

			// This is the time-critical bit

			y[j] = fkey[k++] ^ ftable[(unsigned char) x[j]] ^
			    rotl32(ftable[(unsigned char) (x[fi[m]] >> 8)], 8) ^
                rotl32(ftable[(unsigned char) (x[fi[m + 1]] >> 16)], 16) ^
                rotl32(ftable[x[fi[m + 2]] >> 24], 24);
		}
		t = x;
		x = y;
		y = t;		// swap pointers
	}

    // Last Round - unroll if possible

	for (m = j = 0; j < Nb; j++, m += 3) {
		y[j] = fkey[k++] ^ (unsigned int) fbsub[(unsigned char) x[j]] ^ rotl32((unsigned int) fbsub[(unsigned char) (x[fi[m]] >> 8)], 8) ^
		    rotl32((unsigned int) fbsub[(unsigned char) (x[fi[m + 1]] >> 16)], 16) ^ rotl32((unsigned int) fbsub[x[fi[m + 2]] >> 24], 24);
	}

	for (i = j = 0; i < Nb; i++, j += 4) {
		unpack(y[i], ciphertext + j);
		x[i] = y[i] = 0;	// clean up stack
	}

    return std::vector<char>(ciphertext, ciphertext + blockSize);

}

std::vector<char> Rijndael::decrypt(const std::vector<char> ciphertext) {

    size_t blockSize = getBlockSize();

    unsigned char plaintext[32];

    std::copy_n(ciphertext.begin(), ciphertext.size() > blockSize ? blockSize : ciphertext.size(), plaintext);

    int i, j, k, m;
    unsigned int a[8], b[8], *x, *y, *t;

    for (i = j = 0; i < Nb; i++, j += 4) {
        a[i] = pack(plaintext + j);
        a[i] ^= rkey[i];
    }
    k = Nb;
    x = a;
    y = b;

    // State alternates between a and b
    for (i = 1; i < Nr; i++) {	/* Nr is number of rounds. May be odd. */

    // if Nb is fixed - unroll this next
    // loop and hard-code in the values of ri[]

        for (m = j = 0; j < Nb; j++, m += 3) {
            // This is the time-critical bit

            y[j] = rkey[k++] ^ rtable[(unsigned char) x[j]] ^ rotl32(rtable[(unsigned char) (x[ri[m]] >> 8)], 8) ^ rotl32(rtable[(unsigned char) (x[ri[m + 1]] >> 16)], 16) ^
                rotl32(rtable[x[ri[m + 2]] >> 24], 24);
        }

        t = x;
        x = y;
        y = t;		// swap pointers
    }

    // Last Round - unroll if possible

    for (m = j = 0; j < Nb; j++, m += 3) {
        y[j] = rkey[k++] ^ (unsigned int) rbsub[(unsigned char) x[j]] ^
            rotl32((unsigned int) rbsub[(unsigned char) (x[ri[m]] >> 8)], 8) ^
            rotl32((unsigned int) rbsub[(unsigned char) (x[ri[m + 1]] >> 16)], 16) ^
            rotl32((unsigned int) rbsub[x[ri[m + 2]] >> 24], 24);
    }
    for (i = j = 0; i < Nb; i++, j += 4) {
        unpack(y[i], plaintext + j);
        x[i] = y[i] = 0;	// clean up stack
    }


    return std::vector<char>(plaintext, plaintext + blockSize);
}

unsigned char Rijndael::xtime(unsigned char a) {
	unsigned char b;
	if (a & 0x80)
		b = 0x1B;
	else
		b = 0;
	a <<= 1;
	a ^= b;
	return a;
}

unsigned char Rijndael::byteSub(unsigned char x) {
	unsigned char y = ptab[255 - ltab[x]];	// multiplicative inverse
	x = y;
	x = rotl8(x, 1);
	y ^= x;
	x = rotl8(x, 1);
	y ^= x;
	x = rotl8(x, 1);
	y ^= x;
	x = rotl8(x, 1);
	y ^= x;
	y ^= 0x63;

	return y;
}

unsigned int Rijndael::pack(const unsigned char * b) {
    // pack bytes into a 32-bit Word

	return ((unsigned int) b[3] << 24) |
           ((unsigned int) b[2] << 16) |
           ((unsigned int) b[1] << 8)  |
           (unsigned int) b[0];
}

void Rijndael::unpack(unsigned int a, unsigned char * b) {
    // unpack bytes from a word

	b[0] = (unsigned char) a;
	b[1] = (unsigned char) (a >> 8);
	b[2] = (unsigned char) (a >> 16);
	b[3] = (unsigned char) (a >> 24);
}

unsigned char Rijndael::bmul(unsigned char x, unsigned char y) {
    // x.y= AntiLog(Log(x) + Log(y))

	if (x && y) {
        return ptab[(ltab[x] + ltab[y]) % 255];
    }

	return 0;
}

unsigned int Rijndael::subByte(unsigned int a) {
	unsigned char b[4];

	unpack(a, b);

	b[0] = fbsub[b[0]];
	b[1] = fbsub[b[1]];
	b[2] = fbsub[b[2]];
	b[3] = fbsub[b[3]];

	return pack(b);
}

unsigned char Rijndael::product(unsigned int x, unsigned int y) {

    // dot product of two 4-byte arrays

	unsigned char xb[4];
    unsigned char yb[4];

	unpack(x, xb);
	unpack(y, yb);

	return bmul(xb[0], yb[0]) ^
           bmul(xb[1], yb[1]) ^
           bmul(xb[2], yb[2]) ^
           bmul(xb[3], yb[3]);
}

unsigned int Rijndael::invMixCol(unsigned int x) {

    // matrix Multiplication

	unsigned int y, m;
	unsigned char b[4];

	m = pack(InCo);
	b[3] = product(m, x);
	m = rotl32(m, 24);
	b[2] = product(m, x);
	m = rotl32(m, 24);
	b[1] = product(m, x);
	m = rotl32(m, 24);
	b[0] = product(m, x);
	y = pack(b);
	return y;
}

void Rijndael::reset() {

    int i, j, k, m, N;
	int C1, C2, C3;
	unsigned int cipherKey[8];

	unsigned char key[32];

	std::fill_n(key, 32, 0);
	std::copy_n(_key.begin(), _key.size() > 32 ? 32 : _key.size(), key);

    Nk = _key.size();

    Nk /= 4;

	if (Nb == 4 && Nk < 4) {
		Nk = 4;
	}

    if (Nb >= Nk) {
        Nr = 6 + Nb;
    } else {
        Nr = 6 + Nk;
    }

    C1 = 1;
	if (Nb < 8) {
		C2 = 2;
		C3 = 3;
	} else {
		C2 = 3;
		C3 = 4;
	}


    // pre-calculate forward and reverse increments

	for (m = j = 0; j < Nb; j++, m += 3) {
		fi[m] = (j + C1) % Nb;
		fi[m + 1] = (j + C2) % Nb;
		fi[m + 2] = (j + C3) % Nb;
		ri[m] = (Nb + j - C1) % Nb;
		ri[m + 1] = (Nb + j - C2) % Nb;
		ri[m + 2] = (Nb + j - C3) % Nb;
	}

	N = Nb * (Nr + 1);

	for (i = j = 0; i < Nk; i++, j += 4) {
		cipherKey[i] = pack(key + j);
	}

	for (i = 0; i < Nk; i++) {
        fkey[i] = cipherKey[i];
    }

	for (j = Nk, k = 0; j < N; j += Nk, k++) {

		fkey[j] = fkey[j - Nk] ^ subByte(rotl32(fkey[j - 1], 24)) ^ rco[k];

		if (Nk <= 6) {

			for (i = 1; i < Nk && (i + j) < N; i++) {
                fkey[i + j] = fkey[i + j - Nk] ^ fkey[i + j - 1];
            }

		} else {

			for (i = 1; i < 4 && (i + j) < N; i++) {
                fkey[i + j] = fkey[i + j - Nk] ^ fkey[i + j - 1];
            }

			if ((j + 4) < N) {
                fkey[j + 4] = fkey[j + 4 - Nk] ^ subByte(fkey[j + 3]);
            }

			for (i = 5; i < Nk && (i + j) < N; i++) {
                fkey[i + j] = fkey[i + j - Nk] ^  fkey[i + j - 1];
            }

		}

	}

	// now for the expanded decrypt key in reverse order

	for (j = 0; j < Nb; j++) {
        rkey[j + N - Nb] = fkey[j];
    }


	for (i = Nb; i < N - Nb; i += Nb) {
		k = N - Nb - i;

		for (j = 0; j < Nb; j++) {
            rkey[k + j] = invMixCol(fkey[i + j]);
        }

	}

	for (j = N - Nb; j < N; j++) {
        rkey[j - N + Nb] = fkey[j];
    }

}

};

};

