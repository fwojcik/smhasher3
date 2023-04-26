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
/*
 * Random number generation via CBRNG.
 *
 * This uses the Threefry algorithm as the base RNG. This configures it
 * such that a single 64-bit seed value gives 2^64 independent substreams
 * of 2^64 random numbers. It passes TestU01/BigCrush for both forward and
 * bit-reversed outputs.
 *
 * The important feature of Threefry is that it is fully seekable. This is
 * because it is fundamentally counter-based: instead of storing the output
 * of some sort of state-evolution function to prepare for computing the
 * next random output, it simply increments a counter every iteration. By
 * resetting this counter, random outputs can be arbitrarily replayed at
 * later times, without needing to compute intermediate values.
 *
 * Threefry outputs 4 64-bit random numbers each iteration. The implementation
 * in Random.cpp computes an arbitrary number of these iterations in
 * parallel, to take advantage of vectorization instructions in some CPUs.
 *
 * These outputs are buffered in rngbuf[] until they are needed. Further,
 * the buffer is never refilled until necessary. Data is kept in the buffer
 * in little-endian format. This is to keep output data (both bytes and
 * numbers) the same on differently-endian platforms, and to prioritize the
 * speed of rand_n() over, say, rand_u64(). It lets rand_n() fill large
 * amounts of space quickly, and doesn't penalize numeric generation overly
 * much, as most platforms can byte-swap during the copy into an integer.
 *
 * Public generation APIs:
 *
 *   rand_u64() returns the next random 64-bit integer in native endianness.
 *
 *   rand_range(max) returns a random value in the range [0, max). It is
 *   not completely bias-free, because that would require more than a
 *   single random u64, and it is important that it does to retain the
 *   seekability advantage of this RNG setup. The current bias is negligible.
 *
 *   rand_n(buf, len) fills buf[] with len random bytes. It strictly
 *   follows the sequence of random u64s that are generated, so that it is
 *   possible to seek the RNG "across" a call to rand_n(). It always uses
 *   some multiple of 8 bytes of data. This implies that two consecutive
 *   calls to rand_n() are equivalent to one larger call if the first call
 *   has a length evenly divisible by 8.
 *
 * Public seeking/seeding APIs:
 *
 *   Rand takes a 64-bit seed, and an optional 64-bit substream number. The
 *   substream number is intended to allow for multiple independent streams
 *   of random numbers from the same seed value. A seed must be supplied at
 *   construction, and can be changed later via the reseed() method. A
 *   substream number can be supplied at construction time (default value
 *   is 0), or changed later via the substream() method.
 *
 *   For a given (seed, substream) tuple, the seek(N) method can update the
 *   state of the Rand object to be the same as it would be after N random
 *   numbers have been generated from the initial state. This is much
 *   faster than starting with the initial state and generating and
 *   discarding N numbers.
 */

/*
 * The only somewhat user-serviceable part here. This defines how many
 * copies of the RNG are run in parallel during bulk generation. A good
 * value here is the highest number of 64-bit integers that can fit in the
 * largest vector size your machine supports. For example, AVX2 supports
 * vectors with 4 64-bit integers, so 4 is a good value on AVX2 machines.
 *
 * This value ONLY affects performance. It does not alter any random values
 * that are returned from these objects.
 */
#define PARALLEL 4

//-----------------------------------------------------------------------------

class Rand {
  public:
    // These constants are all defined by the fact that this uses Threefry
    constexpr static unsigned  RANDS_PER_ROUND = 4;
    constexpr static unsigned  RNG_KEYS        = 5;
    constexpr static unsigned  BUFLEN = PARALLEL * RANDS_PER_ROUND;

  private:
    uint64_t  rngbuf[BUFLEN];  // Always in LE byte order
    uint64_t  xseed[RNG_KEYS]; // Threefry keys (xseed[0] is the counter)
    uint64_t  bufidx;          // The next rngbuf[] index to be given out
    uint64_t  rseed, rstream;  // The user-supplied seed and stream numbers
    void refill_buf( void * buf );

    //-----------------------------------------------------------------------------

    inline void update_xseed( void ) {
        // Init keys 1-3 from seed and stream values. This derivation of 3
        // random-ish 64-bit keys from 2 64-bit inputs is completely
        // arbitrary, but is also aesthetically pleasing.
        //
        // Key 0 is the counter, which is left untouched here.
        const uint64_t M1 = UINT64_C(0x9E3779B97F4A7C15);
        const uint64_t M2 = UINT64_C(0x6A09E667F3BCC909);

        xseed[1] = ((ROTR64(rseed, 21) | 1) * M1) + ((ROTR64(rstream, 21) | 1) * M2);
        xseed[2] = ((rseed             | 1) * M1) + ((ROTR64(rstream, 42) | 1) * M2);
        xseed[3] = ((ROTR64(rseed, 42) | 1) * M1) + ((rstream             | 1) * M2);
        // Init key 4 from the Threefish specification.
        const uint64_t K1 = UINT64_C(0x1BD11BDAA9FC1A22);
        xseed[4] = K1 ^ xseed[1] ^ xseed[2] ^ xseed[3];
    }

    //-----------------------------------------------------------------------------

  public:
    Rand( uint64_t seed = 0, uint64_t stream = 0 ) {
        reseed(seed, stream);
    }

    inline void reseed( uint64_t seed, uint64_t stream = 0 ) {
        rseed = seed;
        substream(stream);
    }

    inline void substream( uint64_t stream ) {
        rstream = stream;
        seek(0);
        update_xseed();
    }

    inline void seek( uint64_t offset ) {
        xseed[0] = offset / RANDS_PER_ROUND;
        bufidx   = BUFLEN + (offset % RANDS_PER_ROUND);
    }

    inline uint64_t getoffset( void ) const {
        return (xseed[0] * RANDS_PER_ROUND) + bufidx - BUFLEN;
    }

    //-----------------------------------------------------------------------------

    inline uint64_t rand_u64( void ) {
        if (expectp(bufidx >= BUFLEN, 1.0 / BUFLEN)) {
            refill_buf(rngbuf);
            bufidx -= BUFLEN;
        }
        return COND_BSWAP(rngbuf[bufidx++], isBE());
    }

    inline uint32_t rand_range( uint32_t max ) {
        uint32_t lzbits = clz4(max | 1);
        uint64_t r      = rand_u64() >> (64 - lzbits);

        return (r * max) >> lzbits;
    }

    void rand_n( void * buf, size_t bytes );
}; // class Rand

//-----------------------------------------------------------------------------
