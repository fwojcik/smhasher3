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
#include "Random.h"

#include <algorithm>
#include <cassert>

//-----------------------------------------------------------------------------
// Fill a buffer with 4 * PARALLEL random uint64_t values, updating the
// counter in keyvals[0] to reflect the number of values generated.
//
// This is the Threefry-4x64-14 CBRNG as documented in:
//   "Parallel random numbers: as easy as 1, 2, 3", by John K. Salmon,
//     Mark A. Moraes, Ron O. Dror, and David E. Shaw
//     https://www.thesalmons.org/john/random123/papers/random123sc11.pdf
static void threefry( void * buf, uint64_t * keyvals ) {
    uint64_t tmpbuf[Rand::BUFLEN];

    static_assert(Rand::RANDS_PER_ROUND == 4, "Threefry outputs 4 u64s per call");
    static_assert(Rand::BUFLEN == (PARALLEL * Rand::RANDS_PER_ROUND),
            "Rand buffer can hold current PARALLEL setting");

    // This strange construction involving many for() loops from [0,
    // PARALLEL) allows most compilers to vectorize this sequence of
    // operations when the platform supports that. It is exactly
    // equivalent to a single for() loop containing all the STATE()
    // statements inside of it.
#define STATE(j) tmpbuf[i + PARALLEL * j]
    for (uint64_t i = 0; i < PARALLEL; i++) {
        STATE(0) = keyvals[0] + i;
        STATE(1) = keyvals[1];
        STATE(2) = keyvals[2];
        STATE(3) = keyvals[3];
    }
    for (uint64_t i = 0; i < PARALLEL; i++) {
        STATE(0) += STATE(1); STATE(1) = ROTL64(STATE(1), 14); STATE(1) ^= STATE(0);
        STATE(2) += STATE(3); STATE(3) = ROTL64(STATE(3), 16); STATE(3) ^= STATE(2);
        STATE(0) += STATE(3); STATE(3) = ROTL64(STATE(3), 52); STATE(3) ^= STATE(0);
        STATE(2) += STATE(1); STATE(1) = ROTL64(STATE(1), 57); STATE(1) ^= STATE(2);
        STATE(0) += STATE(1); STATE(1) = ROTL64(STATE(1), 23); STATE(1) ^= STATE(0);
        STATE(2) += STATE(3); STATE(3) = ROTL64(STATE(3), 40); STATE(3) ^= STATE(2);
        STATE(0) += STATE(3); STATE(3) = ROTL64(STATE(3),  5); STATE(3) ^= STATE(0);
        STATE(2) += STATE(1); STATE(1) = ROTL64(STATE(1), 37); STATE(1) ^= STATE(2);
    }
    for (uint64_t i = 0; i < PARALLEL; i++) {
        STATE(0) += keyvals[1];
        STATE(1) += keyvals[2];
        STATE(2) += keyvals[3];
        STATE(3) += keyvals[4] ^ (keyvals[0] + i);
    }
    for (uint64_t i = 0; i < PARALLEL; i++) {
        STATE(3) += 1;
    }
    for (uint64_t i = 0; i < PARALLEL; i++) {
        STATE(0) += STATE(1); STATE(1) = ROTL64(STATE(1), 25); STATE(1) ^= STATE(0);
        STATE(2) += STATE(3); STATE(3) = ROTL64(STATE(3), 33); STATE(3) ^= STATE(2);
        STATE(0) += STATE(3); STATE(3) = ROTL64(STATE(3), 46); STATE(3) ^= STATE(0);
        STATE(2) += STATE(1); STATE(1) = ROTL64(STATE(1), 12); STATE(1) ^= STATE(2);
        STATE(0) += STATE(1); STATE(1) = ROTL64(STATE(1), 58); STATE(1) ^= STATE(0);
        STATE(2) += STATE(3); STATE(3) = ROTL64(STATE(3), 22); STATE(3) ^= STATE(2);
        STATE(0) += STATE(3); STATE(3) = ROTL64(STATE(3), 32); STATE(3) ^= STATE(0);
        STATE(2) += STATE(1); STATE(1) = ROTL64(STATE(1), 32); STATE(1) ^= STATE(2);
    }
    for (uint64_t i = 0; i < PARALLEL; i++) {
        STATE(0) += keyvals[2];
        STATE(1) += keyvals[3];
        STATE(2) += keyvals[4] ^ (keyvals[0] + i);
        STATE(3) += keyvals[0] + i;
    }
    for (uint64_t i = 0; i < PARALLEL; i++) {
        STATE(3) += 2;
    }
    for (uint64_t i = 0; i < PARALLEL; i++) {
        STATE(0) += STATE(1); STATE(1) = ROTL64(STATE(1), 14); STATE(1) ^= STATE(0);
        STATE(2) += STATE(3); STATE(3) = ROTL64(STATE(3), 16); STATE(3) ^= STATE(2);
        STATE(0) += STATE(3); STATE(3) = ROTL64(STATE(3), 52); STATE(3) ^= STATE(0);
        STATE(2) += STATE(1); STATE(1) = ROTL64(STATE(1), 57); STATE(1) ^= STATE(2);
        STATE(0) += STATE(1); STATE(1) = ROTL64(STATE(1), 23); STATE(1) ^= STATE(0);
        STATE(2) += STATE(3); STATE(3) = ROTL64(STATE(3), 40); STATE(3) ^= STATE(2);
        STATE(0) += STATE(3); STATE(3) = ROTL64(STATE(3),  5); STATE(3) ^= STATE(0);
        STATE(2) += STATE(1); STATE(1) = ROTL64(STATE(1), 37); STATE(1) ^= STATE(2);
    }
    for (uint64_t i = 0; i < PARALLEL; i++) {
        STATE(0) += keyvals[3];
        STATE(1) += keyvals[4] ^ (keyvals[0] + i);
        STATE(2) += keyvals[0] + i;
        STATE(3) += keyvals[1];
    }
    for (uint64_t i = 0; i < PARALLEL; i++) {
        STATE(3) += 3;
    }
    for (uint64_t i = 0; i < PARALLEL; i++) {
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
    keyvals[0] += PARALLEL;

    // This reorders the state values so that the output bytes don't depend
    // on the value of PARALLEL. This usually gets vectorized also.
    uint8_t * rngbuf = static_cast<uint8_t *>(buf);
    for (uint64_t i = 0; i < PARALLEL; i++) {
        for (uint64_t j = 0; j < 4; j++) {
            uint64_t tmp = COND_BSWAP(STATE(j), isBE());
            memcpy(&rngbuf[j * 8 + i * 32], &tmp, sizeof(uint64_t));
        }
    }
#undef STATE
}

//-----------------------------------------------------------------------------

void Rand::refill_buf( void * buf ) {
    threefry(buf, xseed);
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
static inline uint64_t feistelF( uint64_t x, uint32_t y ) {
    const uint64_t k = UINT64_C(0xBB67AE8584CAA73D);

    x ^= y; x *= k; x ^= x >> 58; x *= k; x ^= x >> 47;

    return x;
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
        l ^= feistelF(r, k[2 * i + 0]) & lmask;
        r ^= feistelF(l, k[2 * i + 1]) & rmask;
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
        const uint64_t elem_hi, uint64_t * xseed ) {
    const size_t bytes_per_fill = Rand::BUFLEN * sizeof(uint64_t);
    uint8_t      tmp[Rand::BUFLEN * sizeof(uint64_t)];

    size_t nbytes        = (elem_hi - elem_lo) * elem_sz;
    size_t offset_rounds = (elem_lo * elem_sz) / (sizeof(uint64_t) * Rand::RANDS_PER_ROUND);
    size_t offset_bytes  = (elem_lo * elem_sz) % (sizeof(uint64_t) * Rand::RANDS_PER_ROUND);
    size_t offset_size   = std::min(sizeof(tmp) - offset_bytes, nbytes) % bytes_per_fill;

    xseed[0] = offset_rounds;

    if (offset_size > 0) {
        threefry(tmp, xseed);
        memcpy(out, &tmp[offset_bytes], offset_size);
        out    += offset_size;
        nbytes -= offset_size;
    }

    while (nbytes >= bytes_per_fill) {
        threefry(out, xseed);
        nbytes -= bytes_per_fill;
        out    += bytes_per_fill;
    }

    if (nbytes > 0) {
        threefry(tmp, xseed);
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

    // Initialize the Feistel network keys to random 32-bit numbers
    for (uint64_t n = 0; n < RandSeq::FEISTEL_MAXROUNDS; n++) {
        uint64_t r = rand_u64();
        rs.fkeys[2 * n + 0] = r & 0xffffffff;
        rs.fkeys[2 * n + 1] = r >> 32;
    }
    // Initialize the Threefry counter to 0. Initialize the equivalent of
    // xseed[1] through xseed[3] with random numbers. Initialize the last
    // key from the Threefish specification.
    rs.rkeys[0] = 0;
    rs.rkeys[1] = rand_u64();
    rs.rkeys[2] = rand_u64();
    rs.rkeys[3] = rand_u64();
    const uint64_t K1 = UINT64_C(0x1BD11BDAA9FC1A22);
    rs.rkeys[4] = K1 ^ rs.rkeys[1] ^ rs.rkeys[2] ^ rs.rkeys[3];
    // Save the sequence type and element size.
    rs.type     = seqtype;
    rs.szelem   = szelem;

    return rs;
}
