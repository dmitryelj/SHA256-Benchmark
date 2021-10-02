/*
* SHA-256 Single-Core Benchmark. Calculation is emulating Bitcoin double hash. 
* Source: https://github.com/dmitryelj/SHA256-Benchmark, based on https://github.com/jb55/sha256.c
*
* Compile:
* Windows (Open Watcom): owcc.exe SHA256.cpp -Ot
* MS-DOS (Open Watcom): owcc.exe SHA256.cpp -bdos -mcmodel=l -Ot
* Linux: gcc SHA256.cpp -o SHA256 -O3
*/

// #define BORLANDC  // Uncomment for 16-bit MS-DOS only

#ifndef BORLANDC
#include <stdint.h>
#else
typedef unsigned long uint32_t;
#endif
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <time.h>

// Year profit from 1Mh speed (2021)
#define YEAR_PROFIT_PER_1M 0.0001129

#define HEADER_SIZE 80
#define SHA256_DIGEST_SIZE 32

typedef struct sha256_t
{
    uint32_t state[8];
    uint32_t count;
    unsigned char buffer[64];
} sha256_t;

#define S0(x) (ROTR32(x, 2) ^ ROTR32(x,13) ^ ROTR32(x, 22))
#define S1(x) (ROTR32(x, 6) ^ ROTR32(x,11) ^ ROTR32(x, 25))
#define s0(x) (ROTR32(x, 7) ^ ROTR32(x,18) ^ (x >> 3))
#define s1(x) (ROTR32(x,17) ^ ROTR32(x,19) ^ (x >> 10))

#define blk0(i) (W[i] = data[i])
#define blk2(i) (W[i&15] += s1(W[(i-2)&15]) + W[(i-7)&15] + s0(W[(i-15)&15]))

#define Ch(x,y,z) (z^(x&(y^z)))
#define Maj(x,y,z) ((x&y)|(z&(x|y)))

#define a(i) T[(0-(i))&7]
#define b(i) T[(1-(i))&7]
#define c(i) T[(2-(i))&7]
#define d(i) T[(3-(i))&7]
#define e(i) T[(4-(i))&7]
#define f(i) T[(5-(i))&7]
#define g(i) T[(6-(i))&7]
#define h(i) T[(7-(i))&7]

#define ROTL32(v, n) rotl32((v), (n))
#define ROTR32(v, n) rotr32((v), (n))

#define R(i) h(i) += S1(e(i)) + Ch(e(i),f(i),g(i)) + K[i+j] + (j?blk2(i):blk0(i)); d(i) += h(i); h(i) += S0(a(i)) + Maj(a(i), b(i), c(i))

static const uint32_t K[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

inline uint32_t rotl32(uint32_t n, unsigned int c) {
    const unsigned int mask = (CHAR_BIT * sizeof(n) - 1);  // assumes width is a power of 2.
    c &= mask;
    return (n << c) | (n >> ((-(int)c) & mask));
}

inline uint32_t rotr32(uint32_t n, unsigned int c) {
    const unsigned int mask = (CHAR_BIT * sizeof(n) - 1);
    c &= mask;
    return (n >> c) | (n << ((-(int)c) & mask));
}

void sha256_init(sha256_t* p) {
    p->state[0] = 0x6a09e667;
    p->state[1] = 0xbb67ae85;
    p->state[2] = 0x3c6ef372;
    p->state[3] = 0xa54ff53a;
    p->state[4] = 0x510e527f;
    p->state[5] = 0x9b05688c;
    p->state[6] = 0x1f83d9ab;
    p->state[7] = 0x5be0cd19;
    p->count = 0;
}

inline void sha256_transform(uint32_t* state, const uint32_t* data) {
    uint32_t W[16], T[8];
    int i, j;
    for (j = 0; j < 8; j++)
	T[j] = state[j];

    for (j = 0; j < 64; j += 16) {
	for (i = 0; i < 16; i++) { R(i); }
    }

    for (j = 0; j < 8; j++)
	state[j] += T[j];
}

inline void sha256_write_byte_block(sha256_t* p) {
    uint32_t data32[16];
    for (int i = 0; i < 16; i++)
	data32[i] = ((uint32_t)(p->buffer[i * 4]) << 24) +
	((uint32_t)(p->buffer[i * 4 + 1]) << 16) +
	((uint32_t)(p->buffer[i * 4 + 2]) << 8) +
	((uint32_t)(p->buffer[i * 4 + 3]));
    sha256_transform(p->state, data32);
}


inline void sha256_update(sha256_t* p, const unsigned char* data, size_t size) {
    uint32_t curBufferPos = (uint32_t)p->count & 0x3F;
    while (size > 0) {
	p->buffer[curBufferPos++] = *data++;
	p->count++;
	size--;
	if (curBufferPos == 64)
	{
	    curBufferPos = 0;
	    sha256_write_byte_block(p);
	}
    }
}

inline void sha256_final(sha256_t* p, unsigned char* digest) {
    uint32_t lenInBits = (p->count << 3);  // uint64_t
    uint32_t curBufferPos = (uint32_t)p->count & 0x3F;
    p->buffer[curBufferPos++] = 0x80;
    while (curBufferPos != (64 - 8)) {
	curBufferPos &= 0x3F;
	if (curBufferPos == 0)
	    sha256_write_byte_block(p);
	p->buffer[curBufferPos++] = 0;
    }
    // 16-bit Borland C++ does not support 64bit data types, used hardcoded values for length 80 and 32 (only used for bitcoin)
    // for (int i = 0; i < 8; i++) {
    //    p->buffer[curBufferPos++] = (unsigned char)(lenInBits >> 56);
    //    lenInBits <<= 8;
    //}
    if (p->count == 32) {
	p->buffer[curBufferPos++] = 0;
	p->buffer[curBufferPos++] = 0;
	p->buffer[curBufferPos++] = 0;
	p->buffer[curBufferPos++] = 0;
	p->buffer[curBufferPos++] = 0;
	p->buffer[curBufferPos++] = 0;
	p->buffer[curBufferPos++] = 1;
	p->buffer[curBufferPos++] = 0;
    }
    else if (p->count == 80) {
	p->buffer[curBufferPos++] = 0;
	p->buffer[curBufferPos++] = 0;
	p->buffer[curBufferPos++] = 0;
	p->buffer[curBufferPos++] = 0;
	p->buffer[curBufferPos++] = 0;
	p->buffer[curBufferPos++] = 0;
	p->buffer[curBufferPos++] = 2;
	p->buffer[curBufferPos++] = 128;
    }
    sha256_write_byte_block(p);

    for (int i = 0; i < 8; i++) {
	*digest++ = (unsigned char)(p->state[i] >> 24);
	*digest++ = (unsigned char)(p->state[i] >> 16);
	*digest++ = (unsigned char)(p->state[i] >> 8);
	*digest++ = (unsigned char)(p->state[i]);
    }
    sha256_init(p);
}

inline void sha256_hash(unsigned char* buf, const unsigned char* data, size_t size) {
    sha256_t hash;
    sha256_init(&hash);
    sha256_update(&hash, data, size);
    sha256_final(&hash, buf);
}

int main(void) {
    unsigned char block[HEADER_SIZE+1] = "\x02\x00\x00\x00\x49\x22\x63\xa1\x71\x1b\x7d\x5f\xf0\x65\xd7\xae\x3d\xa8\xb5\xf3\xfa\x39\xad\x7b\xfe\xa6\x7b\x7e\x02\x00\x00\x00\x00\x00\x00\x00\x9d\xe2\x55\x11\xea\x94\x1d\x5e\xb2\x3a\x3f\x08\xea\x8a\x54\x09\x6e\x0a\x3c\xf5\x78\x23\xb9\xeb\x2d\xab\xe0\x30\x40\x9f\x04\x5e\xce\x05\xbe\x52\x0c\xa3\x03\x19\x59\xf5\x42\xfb";
    unsigned char buf1[SHA256_DIGEST_SIZE] = { 0 }, buf2[SHA256_DIGEST_SIZE] = { 0 }, i;
    uint32_t nonce = 4215469401, N = 9, attempts[] = { 1, 10, 100, 1000, 10000, 100000, 500000, 1000000, 2000000 };
    clock_t begin;
    double time_spent, calc_speed;

    // Show info
    printf("SHA-256 Single-core Benchmark for DOS/Windows/Linux\n");
    printf("v1.0 02.10.2021 https://github.com/dmitryelj/SHA256-Benchmark\n");
    printf("Simulating of Bitcoin mining calculations\n\n");
    printf("Bitcoin block:\n");
    for (i = 0; i < 80; i++) printf("%02x", block[i]);
    printf("\nNonce: %u\n", nonce);
    sha256_hash(buf1, block, 80);
    sha256_hash(buf2, buf1, 32);
    printf("SHA256-1: ");
    for (i = 0; i < 32; i++) printf("%02x", buf1[31 - i]);
    printf("\n");
    printf("SHA256-2: ");
    for (i = 0; i < 32; i++) printf("%02x", buf2[31 - i]);
    printf("\n");
    printf("Block info:\nhttps://www.blockchain.com/btc/block/0000000000000002a7bbd25a417c0374cc55261021e8a9ca74442b01284f0569\n\n");

    // Start benchmark
    printf("Starting the benchmark\n");
    for (i = 0; i < N; i++) {
        printf("Trying %d calculations...", attempts[i]);
        begin = clock();
        for (nonce = 0; nonce < attempts[i]; nonce++) {
            block[76] = nonce & 0xFF;  // Trying to simulate different values
            sha256_hash(buf1, block, 80);
            sha256_hash(buf2, buf1, 32);
        }
        time_spent = (double)(clock() - begin) / CLOCKS_PER_SEC;
        printf("done in %fs", time_spent);
        if (time_spent > 0.2) {
            // Example calculation: 
            // 0.026s => 1000 hashes, 1 hash = 0.026/1000 = 0,000026 
            // 1000000 hash speed => $0.0001129 per year (2021), x_per_year = 0.0001129*calc_speed/1000000
            calc_speed = attempts[i] / time_spent;
            printf(", speed estimate: %f hash/s\nWith this speed you can earn 1$ in %f years\n", calc_speed, 1000000/(YEAR_PROFIT_PER_1M*calc_speed));
            break;
        }
        printf("\n");
    }
    return 0;
}