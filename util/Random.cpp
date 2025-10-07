/*
 * SMHasher3
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see
 * <https://www.gnu.org/licenses/>.
 */
#include "Platform.h"
#include "Timing.h"
#include "Random.h"
#include "TestGlobals.h" // For Stats.h
#include "Stats.h"       // For distribution testing

#include <algorithm>

// Default to zero
uint64_t Rand::GLOBAL_SEED = 0;

//-----------------------------------------------------------------------------
// Fill a buffer with 4 * PARALLEL random uint64_t values, updating the
// counter to reflect the number of values generated.
//
// This is the Threefry-4x64-16 CBRNG as documented in:
//   "Parallel random numbers: as easy as 1, 2, 3", by John K. Salmon,
//     Mark A. Moraes, Ron O. Dror, and David E. Shaw
//     https://www.thesalmons.org/john/random123/papers/random123sc11.pdf
static void threefry( void * buf, uint64_t & counter, const uint64_t * keyvals ) {
    uint64_t tmpbuf[Rand::BUFLEN];

    static_assert(Rand::RANDS_PER_ROUND == 4, "Threefry outputs 4 u64s per call");
    static_assert(Rand::BUFLEN == (PARALLEL * Rand::RANDS_PER_ROUND), "Rand buffer can hold current PARALLEL setting");

    // This strange construction involving many for() loops from [0,
    // PARALLEL) is exactly equivalent to a single for() loop containing
    // all the STATE() statements inside of it. Having the extra loops
    // allows some compilers to more easily auto-vectorize this sequence of
    // operations when the platform supports that. It also helps GCC do a
    // better job of insn scheduling. That said, LLVM seems to intensely
    // dislike this construction, and so we give it a single giant loop.
#if defined(__llvm__)
  #define SINGLE_GIANT_LOOP 1
#else
  #define SINGLE_GIANT_LOOP 0
#endif

#define STATE(j) tmpbuf[i + PARALLEL * j]

    // The input to the truncated Threefry cipher is a vector of 4 64-bit
    // values, which is { 0, counter, counter, 0 }. The choice of which
    // input value(s) to use as counter(s) is arbitrary; this particular
    // choice was motivated purely by performance testing.
    for (uint64_t i = 0; i < PARALLEL; i++) {
        STATE(0) = keyvals[0];
        STATE(1) = keyvals[1] + counter + i;
        STATE(2) = keyvals[2] + counter + i;
        STATE(3) = keyvals[3];
#if !SINGLE_GIANT_LOOP
    }
    for (uint64_t i = 0; i < PARALLEL; i++) {
#endif
        STATE(0) += STATE(1); STATE(1) = ROTL64(STATE(1), 14); STATE(1) ^= STATE(0);
        STATE(2) += STATE(3); STATE(3) = ROTL64(STATE(3), 16); STATE(3) ^= STATE(2);
        STATE(0) += STATE(3); STATE(3) = ROTL64(STATE(3), 52); STATE(3) ^= STATE(0);
        STATE(2) += STATE(1); STATE(1) = ROTL64(STATE(1), 57); STATE(1) ^= STATE(2);
        STATE(0) += STATE(1); STATE(1) = ROTL64(STATE(1), 23); STATE(1) ^= STATE(0);
        STATE(2) += STATE(3); STATE(3) = ROTL64(STATE(3), 40); STATE(3) ^= STATE(2);
        STATE(0) += STATE(3); STATE(3) = ROTL64(STATE(3),  5); STATE(3) ^= STATE(0);
        STATE(2) += STATE(1); STATE(1) = ROTL64(STATE(1), 37); STATE(1) ^= STATE(2);
#if !SINGLE_GIANT_LOOP
    }
    for (uint64_t i = 0; i < PARALLEL; i++) {
#endif
        STATE(0) += keyvals[1];
        STATE(1) += keyvals[2];
        STATE(2) += keyvals[3];
        STATE(3) += keyvals[4];
#if !SINGLE_GIANT_LOOP
    }
    for (uint64_t i = 0; i < PARALLEL; i++) {
#endif
        STATE(3) += 1;
#if !SINGLE_GIANT_LOOP
    }
    for (uint64_t i = 0; i < PARALLEL; i++) {
#endif
        STATE(0) += STATE(1); STATE(1) = ROTL64(STATE(1), 25); STATE(1) ^= STATE(0);
        STATE(2) += STATE(3); STATE(3) = ROTL64(STATE(3), 33); STATE(3) ^= STATE(2);
        STATE(0) += STATE(3); STATE(3) = ROTL64(STATE(3), 46); STATE(3) ^= STATE(0);
        STATE(2) += STATE(1); STATE(1) = ROTL64(STATE(1), 12); STATE(1) ^= STATE(2);
        STATE(0) += STATE(1); STATE(1) = ROTL64(STATE(1), 58); STATE(1) ^= STATE(0);
        STATE(2) += STATE(3); STATE(3) = ROTL64(STATE(3), 22); STATE(3) ^= STATE(2);
        STATE(0) += STATE(3); STATE(3) = ROTL64(STATE(3), 32); STATE(3) ^= STATE(0);
        STATE(2) += STATE(1); STATE(1) = ROTL64(STATE(1), 32); STATE(1) ^= STATE(2);
#if !SINGLE_GIANT_LOOP
    }
    for (uint64_t i = 0; i < PARALLEL; i++) {
#endif
        STATE(0) += keyvals[2];
        STATE(1) += keyvals[3];
        STATE(2) += keyvals[4];
        STATE(3) += keyvals[0];
#if !SINGLE_GIANT_LOOP
    }
    for (uint64_t i = 0; i < PARALLEL; i++) {
#endif
        STATE(3) += 2;
#if !SINGLE_GIANT_LOOP
    }
    for (uint64_t i = 0; i < PARALLEL; i++) {
#endif
        STATE(0) += STATE(1); STATE(1) = ROTL64(STATE(1), 14); STATE(1) ^= STATE(0);
        STATE(2) += STATE(3); STATE(3) = ROTL64(STATE(3), 16); STATE(3) ^= STATE(2);
        STATE(0) += STATE(3); STATE(3) = ROTL64(STATE(3), 52); STATE(3) ^= STATE(0);
        STATE(2) += STATE(1); STATE(1) = ROTL64(STATE(1), 57); STATE(1) ^= STATE(2);
        STATE(0) += STATE(1); STATE(1) = ROTL64(STATE(1), 23); STATE(1) ^= STATE(0);
        STATE(2) += STATE(3); STATE(3) = ROTL64(STATE(3), 40); STATE(3) ^= STATE(2);
        STATE(0) += STATE(3); STATE(3) = ROTL64(STATE(3),  5); STATE(3) ^= STATE(0);
        STATE(2) += STATE(1); STATE(1) = ROTL64(STATE(1), 37); STATE(1) ^= STATE(2);
#if !SINGLE_GIANT_LOOP
    }
    for (uint64_t i = 0; i < PARALLEL; i++) {
#endif
        STATE(0) += keyvals[3];
        STATE(1) += keyvals[4];
        STATE(2) += keyvals[0];
        STATE(3) += keyvals[1];
#if !SINGLE_GIANT_LOOP
    }
    for (uint64_t i = 0; i < PARALLEL; i++) {
#endif
        STATE(3) += 3;
#if !SINGLE_GIANT_LOOP
    }
    for (uint64_t i = 0; i < PARALLEL; i++) {
#endif
        STATE(0) += STATE(1); STATE(1) = ROTL64(STATE(1), 25); STATE(1) ^= STATE(0);
        STATE(2) += STATE(3); STATE(3) = ROTL64(STATE(3), 33); STATE(3) ^= STATE(2);
        STATE(0) += STATE(3); STATE(3) = ROTL64(STATE(3), 46); STATE(3) ^= STATE(0);
        STATE(2) += STATE(1); STATE(1) = ROTL64(STATE(1), 12); STATE(1) ^= STATE(2);
        STATE(0) += STATE(1); STATE(1) = ROTL64(STATE(1), 58); STATE(1) ^= STATE(0);
        STATE(2) += STATE(3); STATE(3) = ROTL64(STATE(3), 22); STATE(3) ^= STATE(2);
        STATE(0) += STATE(3); STATE(3) = ROTL64(STATE(3), 32); STATE(3) ^= STATE(0);
        STATE(2) += STATE(1); STATE(1) = ROTL64(STATE(1), 32); STATE(1) ^= STATE(2);
    }

    // Update the counter to reflect that we've generated PARALLEL values.
    counter += PARALLEL;

    // Since we want buffered byte-order to be little-endian always (see
    // Random.h for why), byte-swapping is done on big-endian ints. Doing
    // this outside the loop below seems to produce better code.
    if (isBE()) {
        for (uint64_t i = 0; i < PARALLEL; i++) {
            for (uint64_t j = 0; j < 4; j++) {
                STATE(j) = BSWAP(STATE(j));
            }
        }
    }

    // This reorders the state values so that the output bytes don't depend
    // on the value of PARALLEL. This usually gets vectorized also.
    uint8_t * rngbuf = static_cast<uint8_t *>(buf);
    for (uint64_t i = 0; i < PARALLEL; i++) {
        for (uint64_t j = 0; j < 4; j++) {
            memcpy(&rngbuf[i * 32 + j * 8], &(STATE(j)), sizeof(uint64_t));
        }
    }
#undef STATE
#undef SINGLE_GIANT_LOOP
}

//-----------------------------------------------------------------------------

void Rand::refill_buf( void * buf ) {
    threefry(buf, counter, xseed);
}

// Fill the user's buffer from our cache of random data as much as
// possible, and then generate the next random values directly into the
// user's buffer until it is almost full. Finally, refill our cache if
// needed, and then copy any remaining needed values from our cache.
//
// This keeps the Rand object invariant that the internal cache is never
// filled until some random data is needed.
void Rand::rand_n( void * buf, size_t bytes ) {
    if (bytes == 0) {
        return;
    }
    // If the user seek()ed to a point where refill_buf() needs to skip
    // some output bytes, and so can't write to buf directly, then rngbuf[]
    // needs to be filled first.
    if (bufidx > BUFLEN) {
        refill_buf(rngbuf);
        bufidx -= BUFLEN;
    }

    uint8_t * out         = static_cast<uint8_t *>(buf);
    size_t    curbufbytes = sizeof(rngbuf[0]) * (BUFLEN - bufidx);

    if (likely(bytes > curbufbytes)) {
        memcpy(out, &rngbuf[bufidx], curbufbytes);
        out   += curbufbytes;
        bytes -= curbufbytes;
        while (bytes > sizeof(rngbuf)) {
            refill_buf(out);
            out   += sizeof(rngbuf);
            bytes -= sizeof(rngbuf);
        }
        refill_buf(rngbuf);
        bufidx = 0;
    }

    memcpy(out, &rngbuf[bufidx], bytes);
    bufidx += (bytes + sizeof(rngbuf[0]) - 1) / sizeof(rngbuf[0]);

    assert(bufidx <= BUFLEN);
}

//-----------------------------------------------------------------------------
// It turns out that Feistel networks need many rounds in order to work
// with very small block sizes. This is due to the limited number of ways
// each round can permute the state when there aren't enough bits in both
// lanes; the quality of the F function doesn't matter.
//
// While 2 bits per lane is usually enough, it can lead to a sufficiently
// non-uniform selection of permutations for the purposes of cycle walking
// (for more on that, see comments below, above fill_seq()) for small
// values of elem_max, so the cutoff is set above 7. Empirically, szelem of
// 8 (so, elem_cnt of 9) also fails without fill_perm(). 10 was chosen as
// the cutoff to give a little safety margin.
//
// So for those cases, we instead use the random key to explicitly create a
// permutation, and the return the elements that were requested.

#define FEISTEL_CUTOFF 10

static void fill_perm( uint8_t * buf, const uint64_t key, const uint64_t elem_lo,
        const uint64_t elem_hi, const uint64_t elem_cnt ) {
    assert(elem_cnt <= FEISTEL_CUTOFF);

    uint64_t elems[FEISTEL_CUTOFF];
    uint64_t index = key;

    // Decode the key into a Lehmer code
    for (uint64_t i = 1; i <= elem_cnt; i++) {
        elems[elem_cnt - i] = index % i;
        index               = index / i;
    }

    // Decode the Lehmer code into a permutation
    for (int64_t i = elem_cnt - 2; i >= 0; i--) {
        for (uint64_t j = i + 1; j < elem_cnt; j++) {
            if (elems[j] >= elems[i]) {
                elems[j]++;
            }
        }
    }

    memcpy(buf, &elems[elem_lo], (elem_hi - elem_lo) * sizeof(uint64_t));
}

//-----------------------------------------------------------------------------
// An arbitrary simple mixing routine, for use as the F() function in a
// Feistel network below.
//
// Currently, despite the input and output types, no more than 32 input
// bits are ever set, and no more than 32 output bits are used.
static inline uint64_t feistelF( uint64_t value, const uint32_t * subkeys, uint32_t round ) {
    const uint64_t k = UINT64_C(0x9E3779B97F4A7C15); // phi

    value += subkeys[round]; value *= k; value ^= value >> 32;
    value += round;          value *= k; value ^= value >> 32;

    return value;
}

//-----------------------------------------------------------------------------
// This encrypts the value in n (which is of the specified width in bits)
// using a Feistel network and the key data in k[]. It is guaranteed that
// this is a bijection for values in [0, 2**nbits), even if feistelF()&mask
// is not a bijection.
//
// Two uint64_t variables (l and r) are initialized with a counter value in
// n. While these are technically 64-bit wide variables, they are treated
// instead as two smaller-width variables, each approximately half of nbits
// wide. This is why l and r are masked off each time they are assigned to,
// and why the counter value (which can go up to 2**nbits - 1) must be
// split across them.
//
// Each round uses 1 64-bit key, 32 bits in the r->l half-round, and 32
// bits in the l->r half-round.
static inline uint64_t feistel( const uint32_t k[RandSeq::FEISTEL_MAXROUNDS * 2],
        const uint64_t n, const uint64_t bits ) {
    const uint64_t lbits  = bits / 2;
    const uint64_t rbits  = bits - lbits;
    const uint64_t lmask  = (UINT64_C(1) << lbits) - UINT64_C(1);
    const uint64_t rmask  = (UINT64_C(1) << rbits) - UINT64_C(1);
    const uint64_t rounds = RandSeq::FEISTEL_MAXROUNDS -
            ((bits < 6) ? 0 : ((bits < 8) ? 1 : 2));

    uint64_t l = n            & lmask;
    uint64_t r = (n >> lbits) & rmask;

    for (uint64_t i = 0; i < rounds; i++) {
        l ^= feistelF(r, k, 2 * i + 0) & lmask;
        r ^= feistelF(l, k, 2 * i + 1) & rmask;
    }
    r = (r << lbits) + l;
    return r;
}

//-----------------------------------------------------------------------------
// This is a table of data for constructing sets of numbers that have a
// minimum of 3 bits difference. It comes from BCH error correcting codes
// (https://en.wikipedia.org/wiki/BCH_code).
//
// The two columns represent the polynomial used to generate the BCH code
// for a given bit width. These can be any irreducible primitive polynomial
// of the correct size. A polynomial of degree d can be used for a code of
// [2**(d-1), 2**(d)-1] bits. So for a 16-bit or a 24-bit code, a
// polynomial of degree 5 is used, since 16 and 24 are both in the range
// [2**(5-1), 2**(5)-1] == [16, 31]. The polynomial of degree 5 that was
// chosen here is x**5 + x**3 + 1, so the two values in the rows for both
// 16- and 24-bit codes are 3 and 5. Since valid polynomials always have "+
// 1" as a term, that is left out of the table. A complete list of
// primitive irreducible polynomials can be found online in many places; I
// used the list at https://www.jjj.de/mathdata/all-irredpoly.txt.
//
// The other important information for BCH codes is how many codewords
// exist for a given bit with. For example, a 24 bit-wide code (3 bytes)
// consists of 2**19 different codewords. This number is equal to n - d,
// where n is the code length and d is the degree of the generator
// polynomial. So for the row for the 16-bit code, d is 5, and so there are
// 2**(16-5) == 2**11 == 2048 2-byte codewords. This means that order is
// important for this table, and the highest value goes in the last column.
//
// The row for 0-byte codes isn't used, it only exists as "padding" to make
// array indexing more convenient.
static const uint8_t polytable[9][2] = {
    { 0, 0 }, // 0-bytes
    { 3, 4 }, // 1-byte
    { 3, 5 }, // 2-bytes
    { 3, 5 }, // 3-bytes
    { 5, 6 }, // 4-bytes
    { 5, 6 }, // 5-bytes
    { 5, 6 }, // 6-bytes
    { 5, 6 }, // 7-bytes
    { 6, 7 }, // 8-bytes
};

//-----------------------------------------------------------------------------
// These routines fill buf[] with a random sequence of unique elements,
// each of which is szelem bytes. The implementation uses a
// possibly-unbalanced Feistel network with limited-domain values to
// implement Format-Preserving Encryption (FPE). This could be done in a
// simpler way, but this method is still sufficiently fast and it minimizes
// the chance that some subtle pattern or correlation in the random values
// might interact with hash function in some way.
//
// To describe how this works in detail, the case of min_dist==1 will be
// covered first.
//
// Assume that each element is 8 bytes or less (szelem <= 8). In this case,
// every value from [0, 2**szelem) is valid as long as each value only
// appears in the output once at most. The implementation could generate a
// list of all of these values, shuffle them, and then only output the
// number of elements requested. However, this could take quite a lot of
// excess time and memory, especially for larger elements. So instead, the
// value of a counter is encrypted using a Feistel network which is exactly
// 2**szelem bits wide. Because encryption is always bijective, this
// computes a random 1:1 mapping across the full range of integers in the
// given range.
//
// In the case where szelem is greater than 8 we can't easily do this same
// scheme because we can't guarantee availability of integers larger than 8
// bytes. The current suggested workaround for this is described in Random.h.
//
// If min_dist==2, then the only change is that instead of using a counter
// and encryption of szelem*8 bits, it is 1 bit smaller. That one leftover
// bit is then used for a 1-bit error-detection code on the result,
// computed by multiplying the encrypted counter value by the polynomial x
// + 1. In code, this is: r ^= (r << 1).
//
// If min_dist==3, then a similar change is done with a different, wider
// polynomial and a larger number of "withheld" bits. This is the same as
// encoding the permuted counter value with a BCH error-correction code,
// using a non-systematic encoding.
//
// In both cases where min_dist!=1, a random constant (randmask) is XORed
// over each output value. This is done to make it so that every prefix has
// a chance to be emitted. Without this, only a "canonical" set of
// codewords would be emitted. To see this, here is an example of what a
// hypothetical sequence of 6-bit elements with min_dist==3 might look
// like (note that there are a maximum of 8 elements in this case):
//
// Counter    :      0      1      2      3      4      5      6      7
// Encrypted  :      7      4      0      3      6      5      2      1
// BCH Coded  :     23     34     00     17     2e     39     1a     0d
// In binary  : 100011 110100 000000 010111 101110 111001 011010 001101
//
// As you can see, each output differs by at least 3 bits from every
// other. But some outputs cannot be emitted at all. Since 0x00 can be
// output, any value with only 1 or 2 bits set cannot ever be output. By
// XORing a random 6-bit constant over every output value, this bias is
// eliminated while maintaining the minimum distance between elements:
//
// Randmask  0:     23     34     00     17     2e     39     1a     0d
// Randmask  1:     22     35     01     16     2f     38     1b     0c
// Randmask  2:     21     36     02     15     2c     3b     18     0f
// Randmask  3:     20     37     03     14     2d     3a     19     0e
// Randmask  4:     27     30     04     13     2a     3d     1e     09
// Randmask  5:     26     31     05     12     2b     3c     1f     08
// Randmask  6:     25     32     06     11     28     3f     1c     0b
// Randmask  7:     24     33     07     10     29     3e     1d     0a
// .....etc.
//
// min_dist == 0 is used as a kind of special case where a specific
// bit-count difference is not required, and a sequence of random values is
// wanted instead. It uses FPE in a cycle walking mode to generate the
// sequence of values. In this mode, elem_sz is the highest numeric value
// that will be generated.
//
// The templating here is probably overkill, but it was fun to do and keeps
// the code for and the relationship between the four different kinds of
// elements in one place, which is nice. Separating the two write()
// variants and forcing inlining of fill_elem() also allows for things like
// inlining of the memcpy() and vectorization when szelem is large enough
// for that to be profitable.
template <unsigned min_dist>
static inline void fill_seq( uint8_t * buf, const uint32_t k[RandSeq::FEISTEL_MAXROUNDS * 2], const uint64_t randmask,
        const uint64_t elem_lo, const uint64_t elem_hi, const uint64_t elem_sz,
        const uint64_t elem_bytes, const uint64_t stride ) {
    static_assert((min_dist >= 0) && (min_dist <= 3), "min_dist must be 0, 1, 2, or 3");
    assert((min_dist == 0) || ((elem_sz >= 1) && (elem_sz <= 8)));

    const uint64_t nbits =
        (min_dist == 0) ? 64 - clz8(elem_sz)   :
        (min_dist == 1) ? elem_sz * 8          :
        (min_dist == 2) ? elem_sz * 8 - 1      :
        (min_dist == 3) ? elem_sz * 8 - polytable[elem_sz][1] : 0;

    for (uint64_t n = elem_lo; n != elem_hi; n++) {
        uint64_t r = feistel(k, n, nbits);
        if (min_dist == 0) {
            while (r > elem_sz) {
                r = feistel(k, r, nbits);
            }
        } else {
            if (min_dist == 2) {
                r ^= randmask ^ (r << 1);
            } else if (min_dist == 3) {
                r ^= randmask ^ (r << polytable[elem_sz][0]) ^ (r << polytable[elem_sz][1]);
            }
            r = COND_BSWAP(r, isBE());
        }
        memcpy(buf, &r, elem_bytes);
        buf += stride;
    }
}

// To keep fill_seq() simple, feistel() returns a uint64_t. This means that
// it can only generate sequences of 8-byte elements at most. It could be
// changed to return the l and r variables separately, but that only gets
// to 16-byte elements. Doing a good Feistel network for truly arbitrary
// sizes is something I've punted firmly into the "maybe someday" category
// for me.
//
// So, to make RandSeq be able to handle arbitrary-sized elements, what it
// does is use basically an internal, cut-down Rand object, which only has
// the 5 Threefish keys. In this way, a RandSeq object can use threefry()
// to generate a stream of random data completely independently from the
// Rand object that spawned it. When larger-than-8-byte elements are
// requested, all bytes past the 8th are simply random data, which is also
// generated in a seekable manner. The first 8 bytes always fulfill the
// requested minimum distance, so if any future bytes collide it doesn't
// matter, so they can just be random.
//
// But instead of repeatedly generating some chunks of data of length
// elem_sz - 8 and skipping over the holes where the 8-byte sequence data
// are set to go, this just fills the entire buffer with random data, and
// lets fill_seq() overwrite it with 8-byte elements in the right places.
static void fill_rand( uint8_t * out, const size_t elem_sz, const uint64_t elem_lo,
        const uint64_t elem_hi, const uint64_t * xseed ) {
    const size_t bytes_per_fill = Rand::BUFLEN * sizeof(uint64_t);
    uint8_t      tmp[Rand::BUFLEN * sizeof(uint64_t)];

    size_t nbytes        = (elem_hi - elem_lo) * elem_sz;
    size_t offset_rounds = (elem_lo * elem_sz) / (sizeof(uint64_t) * Rand::RANDS_PER_ROUND);
    size_t offset_bytes  = (elem_lo * elem_sz) % (sizeof(uint64_t) * Rand::RANDS_PER_ROUND);
    size_t offset_size   = std::min(sizeof(tmp) - offset_bytes, nbytes) % bytes_per_fill;

    if (offset_size > 0) {
        threefry(tmp, offset_rounds, xseed);
        memcpy(out, &tmp[offset_bytes], offset_size);
        out    += offset_size;
        nbytes -= offset_size;
    }

    while (nbytes >= bytes_per_fill) {
        threefry(out, offset_rounds, xseed);
        nbytes -= bytes_per_fill;
        out    += bytes_per_fill;
    }

    if (nbytes > 0) {
        threefry(tmp, offset_rounds, xseed);
        memcpy(out, tmp, nbytes);
    }
}

template <unsigned mindist>
FORCE_INLINE
void RandSeq::fill_elem( uint8_t * out, const uint64_t elem_lo, const uint64_t elem_hi, const uint64_t elem_stride ) {
    switch (szelem) {
    case  1: fill_seq<mindist>(out, fkeys, rkeys[1], elem_lo, elem_hi, 1, 1, elem_stride); break;
    case  2: fill_seq<mindist>(out, fkeys, rkeys[1], elem_lo, elem_hi, 2, 2, elem_stride); break;
    case  3: fill_seq<mindist>(out, fkeys, rkeys[1], elem_lo, elem_hi, 3, 3, elem_stride); break;
    case  4: fill_seq<mindist>(out, fkeys, rkeys[1], elem_lo, elem_hi, 4, 4, elem_stride); break;
    case  5: fill_seq<mindist>(out, fkeys, rkeys[1], elem_lo, elem_hi, 5, 5, elem_stride); break;
    case  6: fill_seq<mindist>(out, fkeys, rkeys[1], elem_lo, elem_hi, 6, 6, elem_stride); break;
    case  7: fill_seq<mindist>(out, fkeys, rkeys[1], elem_lo, elem_hi, 7, 7, elem_stride); break;
    default: fill_rand(out, szelem, elem_lo, elem_hi, rkeys); // FALLTHROUGH
    case  8: fill_seq<mindist>(out, fkeys, rkeys[1], elem_lo, elem_hi, 8, 8, elem_stride); break;
    }
}

//-----------------------------------------------------------------------------

bool RandSeq::write( void * buf, const uint64_t elem_lo, const uint64_t elem_n ) {
    const uint64_t elem_hi = elem_lo + elem_n;
    uint8_t *      out8    = reinterpret_cast<uint8_t *>(buf);

    if (elem_lo > elem_hi) {
        return false;
    }
    if (elem_hi > Rand::seq_maxelem(type, szelem)) {
        return false;
    }

    switch (type) {
    default        : return false;
    case SEQ_DIST_1: fill_elem<1>(out8, elem_lo, elem_hi, szelem); break;
    case SEQ_DIST_2: fill_elem<2>(out8, elem_lo, elem_hi, szelem); break;
    case SEQ_DIST_3: fill_elem<3>(out8, elem_lo, elem_hi, szelem); break;
    case SEQ_NUM   :
                     if (szelem < FEISTEL_CUTOFF) {
                         fill_perm(out8, rkeys[1], elem_lo, elem_hi, szelem + 1);
                     } else {
                         fill_seq<0>(out8, fkeys, 0, elem_lo, elem_hi, szelem, sizeof(uint64_t), sizeof(uint64_t));
                     }
                     break;
    }

    return true;
}

//-----------------------------------------------------------------------------

uint64_t Rand::seq_maxelem( enum RandSeqType seqtype, const uint32_t szelem ) {
    if (szelem == 0) {
        return 0;
    }
    if ((seqtype != SEQ_NUM) && (szelem > 8)) {
        return UINT64_C(-1);
    }

    switch (seqtype) {
    case SEQ_DIST_1: return szelem == 8 ? UINT64_C(-1) : UINT64_C(1) << (8 * szelem);
    case SEQ_DIST_2: return UINT64_C(1) << (8 * szelem - 1);
    case SEQ_DIST_3: return UINT64_C(1) << (8 * szelem - polytable[szelem][1]);
    case SEQ_NUM   : return (uint64_t)szelem + 1;
    }

    return 0;
}

RandSeq Rand::get_seq( enum RandSeqType seqtype, const uint32_t szelem ) {
    RandSeq rs;

    enable_ortho();

    // Initialize the Feistel network keys to random 32-bit numbers
    for (uint64_t n = 0; n < RandSeq::FEISTEL_MAXROUNDS; n++) {
        uint64_t r = rand_u64();
        rs.fkeys[2 * n + 0] = r & 0xffffffff;
        rs.fkeys[2 * n + 1] = r >> 32;
    }
    // Initialize the Threefry counter to 0. Initialize the equivalent of
    // xseed[1] through xseed[3] with basically random numbers. Initialize
    // the last key from the Threefish specification.
    //
    // The low bit is set in xseed[2] and cleared in xseed[3], in order to
    // guarantee that this can never overlap with a normal Rand object.
    rs.rkeys[0] = 0;
    rs.rkeys[1] = rand_u64();
    rs.rkeys[2] = rand_u64() |  UINT64_C(1);
    rs.rkeys[3] = rand_u64() & ~UINT64_C(1);
    const uint64_t K1 = UINT64_C(0x1BD11BDAA9FC1A22);
    rs.rkeys[4] = K1 ^ rs.rkeys[1] ^ rs.rkeys[2] ^ rs.rkeys[3];
    // Save the sequence type and element size
    rs.type     = seqtype;
    rs.szelem   = szelem;

    // Consume 1 real random number from the user's POV
    disable_ortho(1);

    return rs;
}

//-----------------------------------------------------------------------------
// Unit tests and benchmarks

#if !defined(BARE_RNG)

  #define WEAKRAND(i) (UINT64_C(0xBB67AE8584CAA73D) * (i + 1))
  #define VERIFY(r, t) { if (!(r)) { printf("%s:%d: Test for %s failed!\n", __FILE__, __LINE__, t); exit(1); } }
#define VERIFYEQUAL(x, y, n) {                                         \
        VERIFY(x.rand_u64() == y.rand_u64(), "Rand() equality");       \
        VERIFY(x.rand_range(n) == y.rand_range(n), "Rand() equality"); \
        VERIFY(x == y, "Rand() equality");                             \
    }

static void progress( const char * s ) {
    double tim = (double)monotonic_clock() / NSEC_PER_SEC;

    printf("%11.2f: %s\n", tim, s);
}

void RandTest( const unsigned runs ) {
    std::vector<Rand> testRands1;
    std::vector<Rand> testRands2;
    volatile uint64_t ignored;

    // This comprises ~54,000 tests, so ~50% chance of hitting Logp of 17,
    // and ~5% chance of hitting 20, assuming real randomness.
    constexpr int    LogpFail     = 20;
    constexpr int    LogpPrint    = 17;
    constexpr size_t Testcount_sm = 1024;
    constexpr size_t Testcount_lg = 1024 * 256;

    constexpr size_t Maxrange     = 256;
    constexpr size_t Buf64len     = 128;
    constexpr size_t Buf8len      = 2048;
    uint64_t         buf64_A[Maxrange][Buf64len], buf64_B[Maxrange][Buf64len];
    uint64_t         nbuf[Maxrange];
    uint32_t         cnt32[Maxrange][Maxrange];
    uint8_t          buf8_A[Buf8len], buf8_B[Buf8len];

    for (unsigned i = 0; i < runs; i++) {
        progress("Basic sanity");

        // Ensure two Rand() objects seeded identically produce identical results
        testRands1.emplace_back(Rand(i));
        testRands2.emplace_back(Rand(i));

        testRands1.emplace_back(Rand(WEAKRAND(i)));
        testRands2.emplace_back(Rand(WEAKRAND(i)));

        testRands1.emplace_back(Rand(i, 123));
        testRands2.emplace_back(Rand(i, 123));

        testRands1.emplace_back(Rand(123, i));
        testRands2.emplace_back(Rand(123, i));

        testRands1.emplace_back(Rand(i, i));
        testRands2.emplace_back(Rand(i, i));

        testRands1.emplace_back(Rand(WEAKRAND(i), i));
        testRands2.emplace_back(Rand(WEAKRAND(i), i));

        testRands1.emplace_back(Rand(i, WEAKRAND(i)));
        testRands2.emplace_back(Rand(i, WEAKRAND(i)));

        testRands1.emplace_back(Rand(WEAKRAND(2 * i), WEAKRAND(2 * i + 1)));
        testRands2.emplace_back(Rand(WEAKRAND(2 * i), WEAKRAND(2 * i + 1)));

        size_t Randcount = std::min(testRands1.size(), Maxrange);

        for (size_t j = 0; j < Randcount; j++) {
            VERIFY(testRands1[j] == testRands2[j], "Rand() equality");
        }
        for (size_t j = 0; j < Randcount; j++) {
            for (size_t k = 0; k < Testcount_sm; k++) {
                VERIFYEQUAL(testRands1[j], testRands2[j], j + 2);
            }
        }

        // Ensure Rand() and reseed() work the same
        Rand A1( WEAKRAND(5 * i) );
        Rand A2( 0 );
        ignored = A2.rand_u64(); unused(ignored);
        A2.reseed((uint64_t)(WEAKRAND(5 * i)));
        VERIFYEQUAL(A1, A2, 999);

        Rand B1( WEAKRAND(7 * i), WEAKRAND(9 * i) );
        Rand B2( 123, 456 );
        ignored = B2.rand_u64(); unused(ignored);
        B2.reseed((WEAKRAND(7 * i)), (WEAKRAND(9 * i)));
        VERIFYEQUAL(B1, B2, 999);

        Rand C1( WEAKRAND(11 * i), WEAKRAND(13 * i) );
        Rand C2( WEAKRAND(11 * i) );
        ignored = C2.rand_u64(); unused(ignored);
        C2.reseed(WEAKRAND(11 * i), WEAKRAND(13 * i));
        VERIFYEQUAL(C1, C2, 999);

        Rand D1( 0, WEAKRAND(15 * i) );
        Rand D2( 0, WEAKRAND(17 * i) );
        ignored = D2.rand_u64(); unused(ignored);
        D2.reseed(0, WEAKRAND(15 * i));
        VERIFYEQUAL(D1, D2, 999);

        // Ensure multiple seeds work sanely
        // Seed(x) != Seed(x,0) != Seed(x,1) != Seed(x+1,0) != Seed(x,0,0)
        // RNG of each is different
        for (const uint64_t seedval: { UINT64_C(0), UINT64_C(1), WEAKRAND(19 * i) }) {
            Rand E1( seedval );
            Rand E2( seedval, 0 );
            Rand E3( seedval, 1 );
            Rand E4( seedval + 1, 0 );
            Rand E5( seedval, 0, 0 );
            VERIFY(!(E1 == E2), "Rand() seeding inequality");
            VERIFY(!(E1 == E3), "Rand() seeding inequality");
            VERIFY(!(E1 == E4), "Rand() seeding inequality");
            VERIFY(!(E1 == E5), "Rand() seeding inequality");
            VERIFY(!(E2 == E3), "Rand() seeding inequality");
            VERIFY(!(E2 == E4), "Rand() seeding inequality");
            VERIFY(!(E2 == E5), "Rand() seeding inequality");
            VERIFY(!(E3 == E4), "Rand() seeding inequality");
            VERIFY(!(E3 == E5), "Rand() seeding inequality");
            VERIFY(!(E4 == E5), "Rand() seeding inequality");
            E1.rand_n(&buf64_A[0][0], Buf64len * sizeof(uint64_t));
            E2.rand_n(&buf64_A[1][0], Buf64len * sizeof(uint64_t));
            E3.rand_n(&buf64_A[2][0], Buf64len * sizeof(uint64_t));
            E4.rand_n(&buf64_A[3][0], Buf64len * sizeof(uint64_t));
            E5.rand_n(&buf64_A[4][0], Buf64len * sizeof(uint64_t));
            for (unsigned w = 0; w < 4; w++) {
                for (unsigned x = w + 1; x < 5; x++) {
                    for (unsigned y = 0; y < Buf64len; y++) {
                        for (unsigned z = 0; z < Buf64len; z++) {
                            VERIFY(buf64_A[w][y] != buf64_A[x][z], "Rand() seeding duplicate");
                        }
                    }
                }
            }
        }

        progress("Seeking");

        // Ensure seek() works the same as stepping forward
        for (size_t j = 0; j < Testcount_sm; j++) {
            const size_t forward = j + 3;
            for (size_t l = 0; l < Randcount; l++) {
                for (size_t k = 0; k < forward; k++) {
                    ignored = testRands1[l].rand_u64(); unused(ignored);
                }
            }
            for (size_t l = 0; l < Randcount; l++) {
                testRands2[l].seek(testRands2[l].getoffset() + forward);
            }
            for (size_t l = 0; l < Randcount; l++) {
                VERIFYEQUAL(testRands1[l], testRands2[l], j + 2);
            }
        }

        progress("Orthogonal generation");

        for (size_t j = 0; j < Testcount_sm; j++) {
            const size_t bytecnt = Buf64len * sizeof(uint64_t);
            const size_t forward = j + 1;
            for (size_t l = 0; l < Randcount; l++) {
                testRands2[l].enable_ortho();
                testRands2[l].disable_ortho();
            }
            for (size_t l = 0; l < Randcount; l++) {
                VERIFYEQUAL(testRands1[l], testRands2[l], j + 2);
            }
            for (size_t l = 0; l < Randcount; l++) {
                for (size_t k = 0; k < forward; k++) {
                    ignored = testRands1[l].rand_u64(); unused(ignored);
                }
                testRands1[l].enable_ortho();
                testRands1[l].disable_ortho();
            }
            for (size_t l = 0; l < Randcount; l++) {
                testRands2[l].seek(testRands2[l].getoffset() + forward);
            }
            for (size_t l = 0; l < Randcount; l++) {
                VERIFYEQUAL(testRands1[l], testRands2[l], j + 2);
            }
            for (size_t l = 0; l < Randcount; l++) {
                testRands2[l].enable_ortho();
                testRands2[l].disable_ortho();
            }
            for (size_t l = 0; l < Randcount; l++) {
                VERIFYEQUAL(testRands1[l], testRands2[l], j + 2);
            }
            for (size_t l = 0; l < Randcount; l++) {
                testRands1[l].enable_ortho();
                testRands1[l].rand_n(&buf64_A[l][0], bytecnt);
                testRands1[l].disable_ortho();

                testRands1[l].enable_ortho();
                testRands1[l].rand_n(&buf64_B[l][0], bytecnt);
                testRands1[l].disable_ortho();
            }
            for (size_t l = 0; l < Randcount; l++) {
                VERIFYEQUAL(testRands1[l], testRands2[l], j + 2);
            }
            for (size_t l = 0; l < Randcount; l++) {
                VERIFY(memcmp(&buf64_A[l][0], &buf64_B[l][0], bytecnt) == 0, "Orthogonal outputs match");
            }
            for (size_t l = 0; l < Randcount; l++) {
                testRands1[l].enable_ortho();
                testRands1[l].rand_n(&buf64_A[l][0], bytecnt);
                testRands1[l].disable_ortho();
            }
            for (size_t l = 0; l < Randcount; l++) {
                testRands2[l].rand_n(&buf64_B[l][0], bytecnt);
            }
            for (size_t l = 0; l < Randcount; l++) {
                for (unsigned y = 0; y < Buf64len; y++) {
                    for (unsigned z = 0; z < Buf64len; z++) {
                        VERIFY(buf64_A[l][y] != buf64_B[l][z], "Rand() orthogonal duplicate");
                    }
                }
            }
            for (size_t l = 0; l < Randcount; l++) {
                testRands1[l].rand_n(&buf64_B[l][0], bytecnt);
            }
            for (size_t l = 0; l < Randcount; l++) {
                VERIFYEQUAL(testRands1[l], testRands2[l], j + 2);
            }
        }

        progress("u64 vs. bytes");

        // Ensure rand_u64() x N and rand_n(N) match
        for (size_t j = 0; j < Randcount; j++) {
            for (size_t k = 0; k < Buf64len; k++) {
                buf64_A[j][k] = COND_BSWAP(testRands1[j].rand_u64(), isBE());
            }
        }
        for (size_t j = 0; j < Randcount; j++) {
            testRands2[j].rand_n(&buf64_B[j][0], Buf64len * sizeof(uint64_t));
        }
        for (size_t j = 0; j < Randcount; j++) {
            VERIFY(memcmp(&buf64_A[j][0], &buf64_B[j][0], Buf64len * sizeof(uint64_t)) == 0,
                    "rand_u64() x N and rand_n(N) outputs match");
        }
        // Also verify that seek() works
        for (size_t j = 0; j < Randcount; j++) {
            testRands1[j].seek(testRands1[j].getoffset() - Buf64len);
        }
        for (size_t j = 0; j < Randcount; j++) {
            testRands1[j].rand_n(&buf64_B[j][0], Buf64len * sizeof(uint64_t));
        }
        for (size_t j = 0; j < Randcount; j++) {
            VERIFY(memcmp(&buf64_A[j][0], &buf64_B[j][0], Buf64len * sizeof(uint64_t)) == 0,
                    "seek()+rand_(n) and rand_n(N) outputs match");
            VERIFYEQUAL(testRands1[j], testRands2[j], j + 2);
        }

        progress("byte generation");

        // Verify that all paths through rand_n() work and give the same results
        for (size_t j = 0; j < Randcount; j++) {
            uint64_t init = testRands1[j].getoffset();
            testRands1[j].rand_n(&buf64_A[j][0], Buf64len * sizeof(uint64_t));
            for (size_t k = 0; k < Buf64len; k++) {
                testRands1[j].seek(init + k);
                testRands1[j].rand_n(&buf64_B[j][k]    , 1                * sizeof(uint64_t));
                testRands1[j].rand_n(&buf64_B[j][k + 1], (Buf64len - 1 - k) * sizeof(uint64_t));
                VERIFY(memcmp(&buf64_A[j][0], &buf64_B[j][0], Buf64len * sizeof(uint64_t)) == 0,
                        "seek()+rand_(n) and rand_n(N) outputs match");
            }
        }

        progress("rng_range");

        // Ensure rng_range() doesn't give invalid values for edge cases
        for (size_t j = 0; j < Testcount_sm; j++) {
            for (size_t k = 0; k < Randcount; k++) {
                VERIFY(testRands1[k].rand_range(0) == 0, "Rand().rand_range(0) == 0");
                VERIFY(testRands1[k].rand_range(1) == 0, "Rand().rand_range(1) == 0");
            }
        }

        // Ensure rng_range() works acceptably
        for (size_t j = 2; j <= Maxrange; j += 3) {
            memset(&cnt32[0][0], 0, sizeof(cnt32));
            for (size_t k = 0; k < Randcount; k++) {
                for (size_t l = 0; l < Testcount_lg; l++) {
                    uint32_t r = testRands1[k].rand_range(j);
                    VERIFY(r < j, "Rand.rand_range(N) < N");
                    cnt32[k][r]++;
                }
                uint64_t sumsq      = sumSquaresBasic(&cnt32[k][0], j);
                double   score      = calcScore(sumsq, j, Testcount_lg);
                double   p_value    = GetStdNormalPValue(score);
                int      logp_value = GetLog2PValue(p_value);
                if (logp_value > LogpPrint) {
                    printf("%zd %zd: %e %e %d\n", j, k, score, p_value, logp_value);
                }
                VERIFY(logp_value <= LogpFail, "Rand.rand_range(N) is equally distributed");
            }
        }

        progress("Numeric sequence basics");

        // Test SEQ_NUM
        for (uint64_t j = 1; j < (UINT64_C(1) << 32); j = j * 2 + 1) {
            for (size_t k = 0; k < Randcount; k++) {
                const uint64_t numgen = std::min((uint64_t)Buf64len, Rand::seq_maxelem(SEQ_NUM, j));

                RandSeq rs1 = testRands1[k].get_seq(SEQ_NUM, j);
                rs1.write(&buf64_A[k][0], 0, numgen);

                testRands1[k].seek(testRands1[k].getoffset() - 1);

                RandSeq rs2 = testRands1[k].get_seq(SEQ_NUM, j);
                rs2.write(&buf64_B[k][0], 0, numgen);

                VERIFY(memcmp(&buf64_A[k][0], &buf64_B[k][0], numgen * sizeof(uint64_t)) == 0,
                        "RandSeq and seek + RandSeq outputs match");

                for (uint64_t off = 1; off < numgen; off++) {
                    rs2.write(&buf64_B[k][off], off, numgen - off);

                    VERIFY(memcmp(&buf64_A[k][0], &buf64_B[k][0], numgen * sizeof(uint64_t)) == 0,
                            "RandSeq write() outputs match");
                }

                for (uint64_t l = 0; l < numgen; l++) {
                    VERIFY(buf64_A[k][l] <= j, "RandSeq SEQ_NUM output range <= N");
                    for (uint64_t m = l + 1; m < numgen; m++) {
                        VERIFY(buf64_A[k][l] != buf64_A[k][m], "RandSeq SEQ_NUM outputs are unique");
                    }
                    rs1.write(&buf64_B[k][l], l, 1);
                    VERIFY(buf64_A[k][l] == buf64_B[k][l], "RandSeq write(N) and write(1) agree");
                }
            }
        }

        progress("Numeric sequence bias");

        // Ensure SEQ_NUM() works acceptably
        //
        // This increment was tuned to produce a "nice" range of varying
        // sizes that ends exactly at 256. The sizes it tests are:
        //   2-12, 18, 27, 40, 58, 84, 122, 177, 256
        for (size_t j = 2; j <= Maxrange;
                j = 1 + ((j < 12) ? j : (j * 1445 / 1000))) {
            for (size_t l = 0; l < Randcount; l++) {
                memset(&cnt32[0][0], 0, sizeof(cnt32));
                for (size_t k = 0; k < Testcount_lg; k++) {
                    RandSeq rs = testRands1[l].get_seq(SEQ_NUM, j - 1);
                    rs.write(nbuf, 0, j);
                    for (size_t m = 0; m < j; m++) {
                        VERIFY(nbuf[m] < j, "RandSeq.SEQ_NUM(N) < N");
                        cnt32[m][nbuf[m]]++;
                    }
                }
                for (size_t m = 0; m < j; m++) {
                    uint64_t sumsq      = sumSquaresBasic(&cnt32[m][0], j);
                    double   score      = calcScore(sumsq, j, Testcount_lg);
                    double   p_value    = GetStdNormalPValue(score);
                    int      logp_value = GetLog2PValue(p_value);
                    if (logp_value > LogpPrint) {
                        printf("%zd %zd: %e %e %d\n", j, l, score, p_value, logp_value);
                    }
                    VERIFY(logp_value <= LogpFail, "RandSeq SEQ_NUM(N) is equally distributed");
                }
            }
        }

        progress("Distance 1 sequence basics");

        // Test SEQ_DIST_1
        for (size_t j = 1; j <= 12; j++) {
            for (size_t k = 0; k < Randcount; k++) {
                const uint64_t numgen = std::min((uint64_t)Buf8len / j, Rand::seq_maxelem(SEQ_DIST_1, j));

                RandSeq rs1 = testRands1[k].get_seq(SEQ_DIST_1, j);
                rs1.write(buf8_A, 0, numgen);

                testRands1[k].seek(testRands1[k].getoffset() - 1);

                RandSeq rs2 = testRands1[k].get_seq(SEQ_DIST_1, j);
                rs2.write(buf8_B, 0, numgen);

                VERIFY(memcmp(buf8_A, buf8_B, numgen * j) == 0, "RandSeq and seek + RandSeq outputs match");

                for (size_t off = 1; off < numgen - 1; off++) {
                    rs2.write(&buf8_B[off * j], off, numgen - off);

                    VERIFY(memcmp(buf8_A, buf8_B, numgen * j) == 0, "RandSeq write() outputs match");
                }

                for (size_t l = 0; l < numgen; l++) {
                    uint64_t s = 0;
                    memcpy(&s, &buf8_A[l * j], std::min(j, sizeof(s)));
                    for (size_t m = l + 1; m < numgen; m++) {
                        uint64_t t = 0;
                        memcpy(&t, &buf8_A[m * j], std::min(j, sizeof(s)));
                        VERIFY(s != t, "RandSeq SEQ_DIST_1 outputs are unique");
                    }
                    rs1.write(buf8_B, l, 1);
                    int u = memcmp(buf8_B, &buf8_A[l * j], j);
                    VERIFY(u == 0, "RandSeq write(N) and write(1) agree");
                }
            }
        }

        progress("Distance 1 sequence bias");

        // Ensure SEQ_DIST_1() works acceptably
        unsigned sdcnt;
        sdcnt = Rand::seq_maxelem(SEQ_DIST_1, 1);
        static_assert(Maxrange >= 256, "Maxrange must handle all 1-byte values");
        for (size_t l = 0; l < Randcount; l++) {
            memset(&cnt32[0][0], 0, sizeof(cnt32));
            for (size_t k = 0; k < Testcount_lg; k++) {
                RandSeq rs = testRands1[l].get_seq(SEQ_DIST_1, 1);
                rs.write(buf8_A, 0, sdcnt);
                for (size_t m = 0; m < sdcnt; m++) {
                    cnt32[m][buf8_A[m]]++;
                }
            }
            for (size_t m = 0; m < sdcnt; m++) {
                uint64_t sumsq      = sumSquaresBasic(&cnt32[m][0], 256);
                double   score      = calcScore(sumsq, 256, Testcount_lg);
                double   p_value    = GetStdNormalPValue(score);
                int      logp_value = GetLog2PValue(p_value);
                if (logp_value > LogpPrint) {
                    printf("%d %zd: %e %e %d\n", 256, l, score, p_value, logp_value);
                }
                VERIFY(logp_value <= LogpFail, "RandSeq SEQ_DIST_1(N) is equally distributed");
            }
        }

        progress("Distance 2 sequence basics");

        // Test SEQ_DIST_2
        for (size_t j = 1; j <= 12; j++) {
            for (size_t k = 0; k < Randcount; k++) {
                const uint64_t numgen = std::min((uint64_t)Buf8len / j, Rand::seq_maxelem(SEQ_DIST_2, j));

                RandSeq rs1 = testRands1[k].get_seq(SEQ_DIST_2, j);
                rs1.write(buf8_A, 0, numgen);

                testRands1[k].seek(testRands1[k].getoffset() - 1);

                RandSeq rs2 = testRands1[k].get_seq(SEQ_DIST_2, j);
                rs2.write(buf8_B, 0, numgen);

                VERIFY(memcmp(buf8_A, buf8_B, numgen * j) == 0, "RandSeq and seek + RandSeq outputs match");

                for (size_t off = 1; off < numgen - 1; off++) {
                    rs2.write(&buf8_B[off * j], off, numgen - off);

                    VERIFY(memcmp(buf8_A, buf8_B, numgen * j) == 0, "RandSeq write() outputs match");
                }

                for (size_t l = 0; l < numgen; l++) {
                    uint64_t s = 0;
                    memcpy(&s, &buf8_A[l * j], std::min(j, sizeof(s)));
                    for (size_t m = l + 1; m < numgen; m++) {
                        uint64_t t = 0;
                        memcpy(&t, &buf8_A[m * j], std::min(j, sizeof(s)));
                        VERIFY(s != t, "RandSeq SEQ_DIST_2 outputs are unique");
                        VERIFY(popcount8(s ^ t) >= 2, "RandSeq SEQ_DIST_2 outputs are at least 2 bits apart");
                    }
                    rs1.write(buf8_B, l, 1);
                    int u = memcmp(buf8_B, &buf8_A[l * j], j);
                    VERIFY(u == 0, "RandSeq write(N) and write(1) agree");
                }
            }
        }

        progress("Distance 2 sequence bias");

        // Ensure SEQ_DIST_2() works acceptably
        sdcnt = Rand::seq_maxelem(SEQ_DIST_2, 1);
        static_assert(Maxrange >= 256, "Maxrange must handle all 1-byte values");
        for (size_t l = 0; l < Randcount; l++) {
            memset(&cnt32[0][0], 0, sizeof(cnt32));
            for (size_t k = 0; k < Testcount_lg; k++) {
                RandSeq rs = testRands1[l].get_seq(SEQ_DIST_2, 1);
                rs.write(buf8_A, 0, sdcnt);
                for (size_t m = 0; m < sdcnt; m++) {
                    cnt32[m][buf8_A[m]]++;
                }
            }
            for (size_t m = 0; m < sdcnt; m++) {
                uint64_t sumsq      = sumSquaresBasic(&cnt32[m][0], 256);
                double   score      = calcScore(sumsq, 256, Testcount_lg);
                double   p_value    = GetStdNormalPValue(score);
                int      logp_value = GetLog2PValue(p_value);
                if (logp_value > LogpPrint) {
                    printf("%d %zd: %e %e %d\n", 256, l, score, p_value, logp_value);
                }
                VERIFY(logp_value <= LogpFail, "RandSeq SEQ_DIST_2(N) is equally distributed");
            }
        }

        progress("Distance 3 sequence basics");

        // Test SEQ_DIST_3
        for (size_t j = 1; j <= 12; j++) {
            for (size_t k = 0; k < Randcount; k++) {
                const uint64_t numgen = std::min((uint64_t)Buf8len / j, Rand::seq_maxelem(SEQ_DIST_3, j));

                RandSeq rs1 = testRands1[k].get_seq(SEQ_DIST_3, j);
                rs1.write(buf8_A, 0, numgen);

                testRands1[k].seek(testRands1[k].getoffset() - 1);

                RandSeq rs2 = testRands1[k].get_seq(SEQ_DIST_3, j);
                rs2.write(buf8_B, 0, numgen);

                VERIFY(memcmp(buf8_A, buf8_B, numgen * j) == 0, "RandSeq and seek + RandSeq outputs match");

                for (size_t off = 1; off < numgen - 1; off++) {
                    rs2.write(&buf8_B[off * j], off, numgen - off);

                    VERIFY(memcmp(buf8_A, buf8_B, numgen * j) == 0, "RandSeq write() outputs match");
                }

                for (size_t l = 0; l < numgen; l++) {
                    uint64_t s = 0;
                    memcpy(&s, &buf8_A[l * j], std::min(j, sizeof(s)));
                    for (size_t m = l + 1; m < numgen; m++) {
                        uint64_t t = 0;
                        memcpy(&t, &buf8_A[m * j], std::min(j, sizeof(s)));
                        VERIFY(s != t, "RandSeq SEQ_DIST_3 outputs are unique");
                        VERIFY(popcount8(s ^ t) >= 3, "RandSeq SEQ_DIST_3 outputs are at least 3 bits apart");
                    }
                    rs1.write(buf8_B, l, 1);
                    int u = memcmp(buf8_B, &buf8_A[l * j], j);
                    VERIFY(u == 0, "RandSeq write(N) and write(1) agree");
                }
            }
        }

        progress("Distance 3 sequence bias");

        // Ensure SEQ_DIST_3() works acceptably
        sdcnt = Rand::seq_maxelem(SEQ_DIST_3, 1);
        static_assert(Maxrange >= 256, "Maxrange must handle all 1-byte values");
        for (size_t l = 0; l < Randcount; l++) {
            memset(&cnt32[0][0], 0, sizeof(cnt32));
            for (size_t k = 0; k < Testcount_lg; k++) {
                RandSeq rs = testRands1[l].get_seq(SEQ_DIST_3, 1);
                rs.write(buf8_A, 0, sdcnt);
                for (size_t m = 0; m < sdcnt; m++) {
                    cnt32[m][buf8_A[m]]++;
                }
            }
            for (size_t m = 0; m < sdcnt; m++) {
                uint64_t sumsq      = sumSquaresBasic(&cnt32[m][0], 256);
                double   score      = calcScore(sumsq, 256, Testcount_lg);
                double   p_value    = GetStdNormalPValue(score);
                int      logp_value = GetLog2PValue(p_value);
                if (logp_value > LogpPrint) {
                    printf("%d %zd: %e %e %d\n", 256, l, score, p_value, logp_value);
                }
                VERIFY(logp_value <= LogpFail, "RandSeq SEQ_DIST_3(N) is equally distributed");
            }
        }

        testRands1.clear();
        testRands2.clear();
    }
}

void RandBenchmark( void ) {
    constexpr size_t TEST_ITER = 1000;
    constexpr size_t TEST_SIZE = 1 * 1024 * 1024;

    alignas(uint64_t) uint8_t buf[TEST_SIZE];

    volatile uint64_t val;
    Rand randbuf[TEST_ITER];

    uint64_t numgen = 0;
    double   deltat;

    printf("Raw RNG.........................");
    deltat = UINT64_C(1) << 53;
    for (size_t i = 0; i < TEST_ITER; i++) {
        uint64_t keys[5] = { 1, 2, 3, 4, 5 };
        uint64_t begin   = cycle_timer_start();
        for (size_t j = 0; j < TEST_SIZE / Rand::BUFLEN; j++) {
            threefry(&buf[j * Rand::BUFLEN], numgen, keys);
        }
        uint64_t end     = cycle_timer_start();
        deltat = std::min(deltat, (double)(end - begin));
    }
    printf("%8.2f\n", deltat / (TEST_SIZE / Rand::BUFLEN));

    printf("Object init.....................");
    deltat = UINT64_C(1) << 53;
    for (size_t i = 0; i < TEST_ITER; i++) {
        uint64_t begin = cycle_timer_start();
        randbuf[i] = Rand(i);
        uint64_t end   = cycle_timer_start();
        deltat = std::min(deltat, (double)(end - begin));
    }
    printf("%8.2f\n", deltat);

    printf("Reseeding.......................");
    deltat = UINT64_C(1) << 53;
    for (size_t i = 0; i < TEST_ITER; i++) {
        Rand r1;
        uint64_t begin = cycle_timer_start();
        r1.reseed(i, i);
        uint64_t end   = cycle_timer_start();
        deltat = std::min(deltat, (double)(end - begin));
    }
    printf("%8.2f\n", deltat);

    printf("Reseed + rand_u64().............");
    deltat = UINT64_C(1) << 53;
    for (size_t i = 0; i < TEST_ITER; i++) {
        Rand r2b;
        uint64_t begin = cycle_timer_start();
        r2b.reseed(i, i);
        val = r2b.rand_u64(); (void)val;
        uint64_t end =   cycle_timer_start();
        deltat = std::min(deltat, (double)(end - begin));
    }
    printf("%8.2f\n", deltat);

    printf("rand_u64()......................");
    deltat = UINT64_C(1) << 53;
    for (size_t i = 0; i < TEST_ITER; i++) {
        Rand r3;
        uint64_t begin = cycle_timer_start();
        for (size_t j = 0; j < 4096; j++) {
            val = r3.rand_u64(); (void)val;
        }
        uint64_t end =   cycle_timer_start();
        deltat = std::min(deltat, (double)(end - begin));
    }
    printf("%8.2f\n", deltat / 4096.0);

    printf("rand_range()....................");
    deltat = UINT64_C(1) << 53;
    for (size_t i = 0; i < TEST_ITER; i++) {
        Rand r4;
        uint64_t begin = cycle_timer_start();
        for (size_t j = 0; j < 4096; j++) {
            val = r4.rand_range(j); (void)val;
        }
        uint64_t end =   cycle_timer_start();
        deltat = std::min(deltat, (double)(end - begin));
    }
    printf("%8.2f\n", deltat / 4096.0);

    printf("rand_n()........................");
    deltat = UINT64_C(1) << 53;
    for (size_t i = 0; i < TEST_ITER; i++) {
        Rand r5;
        uint64_t begin = cycle_timer_start();
        r5.rand_n(buf, sizeof(buf));
        uint64_t end   = cycle_timer_start();
        deltat = std::min(deltat, (double)(end - begin));
    }
    printf("%8.2f\n", deltat / (sizeof(buf) / sizeof(uint64_t)));

    printf("\n................................ batch  \tordered \t random \n");

    for (uint64_t szelem = 1; szelem <= 16; szelem++) {
        printf("RandSeq(SEQ_DIST_1, %2d).........", (int)szelem);
        deltat = UINT64_C(1) << 53;
        Rand r6( 6, szelem );
        numgen = std::min((uint64_t)sizeof(buf) / 16, Rand::seq_maxelem(SEQ_DIST_1, szelem));
        // Batched
        for (size_t i = 0; i < TEST_ITER; i++) {
            RandSeq  rs1   = r6.get_seq(SEQ_DIST_1, szelem);
            uint64_t begin = cycle_timer_start();
            rs1.write(buf, 0, numgen);
            uint64_t end   = cycle_timer_start();
            deltat = std::min(deltat, (double)(end - begin));
        }
        printf("%8.2f\t", deltat / numgen);
        // One-at-a-time, in order
        deltat = UINT64_C(1) << 53;
        for (size_t i = 0; i < TEST_ITER; i++) {
            RandSeq  rs1   = r6.get_seq(SEQ_DIST_1, szelem);
            uint64_t begin = cycle_timer_start();
            for (uint64_t j = 0; j < numgen; j++) {
                rs1.write(buf, j, 1);
            }
            uint64_t end =   cycle_timer_start();
            deltat = std::min(deltat, (double)(end - begin));
        }
        printf("%8.2f\t", deltat / numgen);
        // One-at-a-time, in random order
        deltat = UINT64_C(1) << 53;
        for (size_t i = 0; i < TEST_ITER; i++) {
            RandSeq rs2 = r6.get_seq(SEQ_NUM, numgen - 1);
            rs2.write(buf, 0, numgen);

            RandSeq  rs1   = r6.get_seq(SEQ_DIST_1, szelem);
            uint64_t begin = cycle_timer_start();
            for (uint64_t j = 0; j < numgen; j++) {
                uint64_t k = GET_U64<false>(buf, j * 8);
                rs1.write(buf, k, 1);
            }
            uint64_t end = cycle_timer_start();
            deltat = std::min(deltat, (double)(end - begin));
        }
        printf("%8.2f\n", deltat / numgen);
    }

    for (uint64_t szelem = 1; szelem <= 16; szelem++) {
        printf("RandSeq(SEQ_DIST_2, %2d).........", (int)szelem);
        deltat = UINT64_C(1) << 53;
        Rand r7( 7, szelem );
        numgen = std::min((uint64_t)sizeof(buf) / 16, Rand::seq_maxelem(SEQ_DIST_2, szelem));
        // Batched
        for (size_t i = 0; i < TEST_ITER; i++) {
            RandSeq  rs2   = r7.get_seq(SEQ_DIST_2, szelem);
            uint64_t begin = cycle_timer_start();
            rs2.write(buf, 0, numgen);
            uint64_t end   = cycle_timer_start();
            deltat = std::min(deltat, (double)(end - begin));
        }
        printf("%8.2f\t", deltat / numgen);
        // One-at-a-time, in order
        deltat = UINT64_C(1) << 53;
        for (size_t i = 0; i < TEST_ITER; i++) {
            RandSeq  rs2   = r7.get_seq(SEQ_DIST_2, szelem);
            uint64_t begin = cycle_timer_start();
            for (uint64_t j = 0; j < numgen; j++) {
                rs2.write(buf, j, 1);
            }
            uint64_t end =   cycle_timer_start();
            deltat = std::min(deltat, (double)(end - begin));
        }
        printf("%8.2f\t", deltat / numgen);
        // One-at-a-time, in random order
        deltat = UINT64_C(1) << 53;
        for (size_t i = 0; i < TEST_ITER; i++) {
            RandSeq rs3 = r7.get_seq(SEQ_NUM, numgen - 1);
            rs3.write(buf, 0, numgen);

            RandSeq  rs2   = r7.get_seq(SEQ_DIST_2, szelem);
            uint64_t begin = cycle_timer_start();
            for (uint64_t j = 0; j < numgen; j++) {
                uint64_t k = GET_U64<false>(buf, j * 8);
                rs2.write(buf, k, 1);
            }
            uint64_t end = cycle_timer_start();
            deltat = std::min(deltat, (double)(end - begin));
        }
        printf("%8.2f\n", deltat / numgen);
    }

    for (uint64_t szelem = 1; szelem <= 16; szelem++) {
        printf("RandSeq(SEQ_DIST_3, %2d).........", (int)szelem);
        deltat = UINT64_C(1) << 53;
        Rand r8( 8, szelem );
        numgen = std::min((uint64_t)sizeof(buf) / 16, Rand::seq_maxelem(SEQ_DIST_3, szelem));
        // Batched
        for (size_t i = 0; i < TEST_ITER; i++) {
            RandSeq  rs3   = r8.get_seq(SEQ_DIST_3, szelem);
            uint64_t begin = cycle_timer_start();
            rs3.write(buf, 0, numgen);
            uint64_t end   = cycle_timer_start();
            deltat = std::min(deltat, (double)(end - begin));
        }
        printf("%8.2f\t", deltat / numgen);
        // One-at-a-time, in order
        deltat = UINT64_C(1) << 53;
        for (size_t i = 0; i < TEST_ITER; i++) {
            RandSeq  rs3   = r8.get_seq(SEQ_DIST_3, szelem);
            uint64_t begin = cycle_timer_start();
            for (uint64_t j = 0; j < numgen; j++) {
                rs3.write(buf, j, 1);
            }
            uint64_t end =   cycle_timer_start();
            deltat = std::min(deltat, (double)(end - begin));
        }
        printf("%8.2f\t", deltat / numgen);
        // One-at-a-time, in random order
        deltat = UINT64_C(1) << 53;
        for (size_t i = 0; i < TEST_ITER; i++) {
            RandSeq rs4 = r8.get_seq(SEQ_NUM, numgen - 1);
            rs4.write(buf, 0, numgen);

            RandSeq  rs3   = r8.get_seq(SEQ_DIST_3, szelem);
            uint64_t begin = cycle_timer_start();
            for (uint64_t j = 0; j < numgen; j++) {
                uint64_t k = GET_U64<false>(buf, j * 8);
                rs3.write(buf, k, 1);
            }
            uint64_t end = cycle_timer_start();
            deltat = std::min(deltat, (double)(end - begin));
        }
        printf("%8.2f\n", deltat / numgen);
    }

    for (uint64_t maxelemP = 4; maxelemP <= 31; maxelemP += 3) {
        printf("RandSeq(SEQ_NUM, (1<<%2d)-1).....", (int)maxelemP);
        const uint64_t maxelem = UINT64_C(1) << maxelemP;
        deltat = UINT64_C(1) << 53;
        Rand r9( 9, maxelemP );
        numgen = std::min(maxelem, (uint64_t)(sizeof(buf) / sizeof(uint64_t)));
        // Batched
        for (size_t i = 0; i < TEST_ITER; i++) {
            RandSeq  rs4   = r9.get_seq(SEQ_NUM, maxelem - 1);
            uint64_t begin = cycle_timer_start();
            rs4.write(buf, 0, numgen);
            uint64_t end   = cycle_timer_start();
            deltat = std::min(deltat, (double)(end - begin));
        }
        printf("%8.2f\t", deltat / numgen);
        // One-at-a-time, in order
        deltat = UINT64_C(1) << 53;
        for (size_t i = 0; i < TEST_ITER; i++) {
            RandSeq  rs4   = r9.get_seq(SEQ_NUM, maxelem - 1);
            uint64_t begin = cycle_timer_start();
            for (uint64_t j = 0; j < numgen; j++) {
                rs4.write(buf, j, 1);
            }
            uint64_t end =   cycle_timer_start();
            deltat = std::min(deltat, (double)(end - begin));
        }
        printf("%8.2f\t", deltat / numgen);
        // One-at-a-time, in random order
        deltat = UINT64_C(1) << 53;
        for (size_t i = 0; i < TEST_ITER; i++) {
            RandSeq rs5 = r9.get_seq(SEQ_NUM, numgen - 1);
            rs5.write(buf, 0, numgen);

            RandSeq  rs4   = r9.get_seq(SEQ_NUM, maxelem - 1);
            uint64_t begin = cycle_timer_start();
            for (uint64_t j = 0; j < numgen; j++) {
                uint64_t k = GET_U64<false>(buf, j * 8);
                rs4.write(buf, k, 1);
            }
            uint64_t end = cycle_timer_start();
            deltat = std::min(deltat, (double)(end - begin));
        }
        printf("%8.2f\n", deltat / numgen);
    }

    for (uint64_t maxelemP = 4; maxelemP <= 31; maxelemP += 3) {
        printf("RandSeq(SEQ_NUM, (1<<%2d)).......", (int)maxelemP);
        const uint64_t maxelem = UINT64_C(1) << maxelemP;
        deltat = UINT64_C(1) << 53;
        Rand rA( 10, maxelemP );
        numgen = std::min(maxelem, (uint64_t)(sizeof(buf) / sizeof(uint64_t)));
        // Batched
        for (size_t i = 0; i < TEST_ITER; i++) {
            RandSeq  rs5   = rA.get_seq(SEQ_NUM, maxelem);
            uint64_t begin = cycle_timer_start();
            rs5.write(buf, 0, numgen);
            uint64_t end   = cycle_timer_start();
            deltat = std::min(deltat, (double)(end - begin));
        }
        printf("%8.2f\t", deltat / numgen);
        // One-at-a-time, in order
        deltat = UINT64_C(1) << 53;
        for (size_t i = 0; i < TEST_ITER; i++) {
            RandSeq  rs5   = rA.get_seq(SEQ_NUM, maxelem);
            uint64_t begin = cycle_timer_start();
            for (uint64_t j = 0; j < numgen; j++) {
                rs5.write(buf, j, 1);
            }
            uint64_t end =   cycle_timer_start();
            deltat = std::min(deltat, (double)(end - begin));
        }
        printf("%8.2f\t", deltat / numgen);
        // One-at-a-time, in random order
        deltat = UINT64_C(1) << 53;
        for (size_t i = 0; i < TEST_ITER; i++) {
            RandSeq rs6 = rA.get_seq(SEQ_NUM, numgen - 1);
            rs6.write(buf, 0, numgen);

            RandSeq  rs5   = rA.get_seq(SEQ_NUM, maxelem);
            uint64_t begin = cycle_timer_start();
            for (uint64_t j = 0; j < numgen; j++) {
                uint64_t k = GET_U64<false>(buf, j * 8);
                rs5.write(buf, k, 1);
            }
            uint64_t end = cycle_timer_start();
            deltat = std::min(deltat, (double)(end - begin));
        }
        printf("%8.2f\n", deltat / numgen);
    }
}

#endif // BARE_RNG
