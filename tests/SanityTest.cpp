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
 *
 * This file incorporates work covered by the following copyright and
 * permission notice:
 *
 *     Copyright (c) 2010-2012 Austin Appleby
 *     Copyright (c) 2014-2021 Reini Urban
 *     Copyright (c) 2019      Yann Collet
 *     Copyright (c) 2020      Thomas Dybdahl Ahle
 *
 *     Permission is hereby granted, free of charge, to any person
 *     obtaining a copy of this software and associated documentation
 *     files (the "Software"), to deal in the Software without
 *     restriction, including without limitation the rights to use,
 *     copy, modify, merge, publish, distribute, sublicense, and/or
 *     sell copies of the Software, and to permit persons to whom the
 *     Software is furnished to do so, subject to the following
 *     conditions:
 *
 *     The above copyright notice and this permission notice shall be
 *     included in all copies or substantial portions of the Software.
 *
 *     THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *     EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 *     OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *     NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 *     HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 *     WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 *     FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 *     OTHER DEALINGS IN THE SOFTWARE.
 */
#include "Platform.h"
#include "Types.h"
#include "Stats.h"
#include "Random.h"
#include "VCode.h"

#include "SanityTest.h"

// These sentinel bytes MUST be different values
static const uint8_t sentinel1 = 0x5c;
static const uint8_t sentinel2 = 0x36;
static_assert(sentinel1 != sentinel2,
        "valid sentinel bytes in SanityTest");

//----------------------------------------------------------------------------
// Basic sanity checks -
//
// A hash function should not be reading outside the bounds of the
// key.
//
// Flipping a bit of a key should, with overwhelmingly high
// probability, result in a different hash.
//
// Hashing the same key twice should always produce the same result.
//
// The memory alignment of the key should not affect the hash result.

static bool verify_sentinel(const uint8_t * buf, size_t len, const uint8_t sentinel) {
    for (size_t i = 0; i < len; i++) {
        if (buf[i] != sentinel) {
            printf(" %d: 0x%02X != 0x%02X: ", i, buf[i], sentinel);
            return false;
        }
    }
    return true;
}

template < bool checksentinels >
static bool verify_hashmatch(const uint8_t * buf1, const uint8_t * buf2, size_t len) {
    if (likely(memcmp(buf1, buf2, len) == 0)) {
        return true;
    }
    for (size_t i = 0; i < len; i++) {
        if (buf1[i] == buf2[i]) { continue; }
        if (checksentinels &&
                (buf1[i] == sentinel1) && (buf2[i] == sentinel2)) {
            printf(" output byte %d not altered:", i);
        } else {
            printf(" output byte %d inconsistent (0x%02X != 0x%02X):",
                    i, buf1[i], buf2[i]);
        }
        break;
    }
    return false;
}

//----------
// Test that the hash written is equal to the length promised, and
// that hashing the same thing gives the same result.
//
// This test can halt early, so don't add input bytes to the VCode.
bool SanityTest1(const HashInfo * hinfo, const seed_t seed) {
    Rand r(883743);
    bool result = true;
    bool danger = false;

    const HashFn hash = hinfo->hashFn(g_hashEndian);
    const int hashbytes = hinfo->bits / 8;
    const int reps = 10;
    const int keymax = 256;
    const int pad = 16*3;
    const int buflen = keymax + pad;

    uint8_t * buffer1 = new uint8_t[buflen];
    uint8_t * buffer2 = new uint8_t[buflen];
    uint8_t * hash1 = new uint8_t[buflen];
    uint8_t * hash2 = new uint8_t[buflen];

    printf("Running sanity check 1       ");

    memset(hash1, sentinel1, buflen);
    memset(hash2, sentinel2, buflen);

    for(int irep = 0; irep < reps; irep++) {
        if(irep % (reps/10) == 0) printf(".");

        for(int len = 0; len <= keymax; len++) {
            // Make 2 copies of some random input data, and hash one
            // of them.
            r.rand_p(buffer1, buflen);
            memcpy(buffer2, buffer1, buflen);
            hash(buffer1, len, seed, hash1);
            addVCodeOutput(hash1, hashbytes);

            // See if the hash somehow changed the input data
            if (memcmp(buffer1, buffer2, buflen) != 0) {
                printf(" hash altered input buffer:");
                result = false;
                danger = true;
                goto end_sanity;
            }

            // See if the hash overflowed its output buffer
            if (!verify_sentinel(hash1 + hashbytes, buflen - hashbytes, sentinel1)) {
                printf(" hash overflowed output buffer (pass 1):");
                result = false;
                danger = true;
                goto end_sanity;
            }

            // Hash the same data again
            hash(buffer1, len, seed, hash2);

            // See if the hash overflowed output buffer this time
            if (!verify_sentinel(hash2 + hashbytes, buflen - hashbytes, sentinel2)) {
                printf(" hash overflowed output buffer (pass 2):");
                result = false;
                danger = true;
                goto end_sanity;
            }

            // See if the hashes match, and if not then characterize the failure
            if (!verify_hashmatch<true>(hash1, hash2, hashbytes)) {
                result = false;
                goto end_sanity;
            }
        }
    }

 end_sanity:
    if(result == false) {
        printf(" FAIL  !!!!!\n");
    } else {
        printf(" PASS\n");
    }

    if (danger) {
        printf("ERROR: Dangerous hash behavior detected!\n");
        printf("       Cannot continue, since hash may corrupt memory.\n");
        exit(13);
    }

    recordTestResult(result, "Sanity", "Basic 1");

    addVCodeResult(result);

    delete [] buffer1;
    delete [] buffer2;
    delete [] hash1;
    delete [] hash2;

    return result;
}

//----------
// Test that changing any input bit changes at least one output bit,
// that changing bits outside the input does not change the output,
// and that hashing the same thing gives the same result, even if
// it's at a different alignment.
//
// This test can halt early, so don't add input bytes to the VCode.
bool SanityTest2(const HashInfo * hinfo, const seed_t seed) {
    Rand r(883744);
    bool result = true;

    const HashFn hash = hinfo->hashFn(g_hashEndian);
    const int hashbytes = hinfo->bits / 8;
    const int reps = 10;
    const int keymax = 256;
    const int pad = 16; // Max alignment offset tested
    const int buflen = keymax + pad*3;

    // XXX Check alignment!?!
    uint8_t * buffer1 = new uint8_t[buflen];
    uint8_t * buffer2 = new uint8_t[buflen];
    uint8_t * hash1 = new uint8_t[hashbytes];
    uint8_t * hash2 = new uint8_t[hashbytes];

    printf("Running sanity check 2       ");

    for (int irep = 0; irep < reps; irep++) {
        if(irep % (reps/10) == 0) printf(".");

        for(int len = 4; len <= keymax; len++) {
            for(int offset = pad; offset < pad*2; offset++) {
                // Fill the two buffers with different random data
                r.rand_p(buffer1, buflen);
                r.rand_p(buffer2, buflen);

                // Make 2 key pointers to the same data with different
                // alignments. The rest of buffer2 is still random
                // data that differs from buffer1, including data
                // before the key pointers.
                uint8_t * key1 = &buffer1[pad];
                uint8_t * key2 = &buffer2[pad + offset];
                memcpy(key2, key1, len);

                hash(key1, len, seed, hash1);
                addVCodeOutput(hash1, hashbytes);

                for(int bit = 0; bit < (len * 8); bit++) {
                    // Flip a bit, hash the key -> we should get a different result.
                    flipbit(key2, len, bit);
                    hash(key2, len, seed, hash2);
                    addVCodeOutput(hash2, hashbytes);

                    if (unlikely(memcmp(hash1, hash2, hashbytes) == 0)) {
                        printf(" flipped bit %d, got identical output:", bit);
                        result = false;
                        goto end_sanity;
                    }

                    // Flip it back
                    flipbit(key2, len, bit);
                    // hash again -> we should get the original result.
                    //
                    // This is actually expensive enough that doing
                    // this for more than one complete set of (len,
                    // offset) values isn't worth it.
                    if (irep == 0) {
                        hash(key2, len, seed, hash2);

                        if (!verify_hashmatch<false>(hash1, hash2, hashbytes)) {
                            result = false;
                            goto end_sanity;
                        }
                    }
                }

                // Try altering every byte in buffer2 that isn't a key
                // byte, and make sure the hash doesn't change, to try
                // catching hashes that depend on out-of-bounds key
                // bytes.
                //
                // I don't know how to catch hashes that merely read
                // out-of-bounds key bytes, but doing that isn't
                // necessarily an error or even unsafe; see:
                // https://stackoverflow.com/questions/37800739/is-it-safe-to-read-past-the-end-of-a-buffer-within-the-same-page-on-x86-and-x64
                for(uint8_t * ptr = &buffer2[0]; ptr < &buffer2[buflen]; ptr++) {
                    if ((ptr >= &key2[0]) && (ptr < &key2[len])) { continue; }
                    *ptr ^= 0xFF;
                    hash(key2, len, seed, hash2);
                    if (memcmp(hash1, hash2, hashbytes) != 0) {
                        printf(" changing non-key byte altered hash: ");
                        result = false;
                        goto end_sanity;
                    }
                }
            }
        }
    }

 end_sanity:
    if(result == false) {
        printf(" FAIL  !!!!!\n");
    } else {
        printf(" PASS\n");
    }

    recordTestResult(result, "Sanity", "Basic 2");

    addVCodeResult(result);

    delete [] buffer1;
    delete [] buffer2;

    delete [] hash1;
    delete [] hash2;

    return result;
}

//----------------------------------------------------------------------------
// Appending zero bytes to a key should always cause it to produce a different
// hash value
bool AppendedZeroesTest (const HashInfo * hinfo, const seed_t seed) {
  Rand r(173994);

  const HashFn hash = hinfo->hashFn(g_hashEndian);
  const int hashbytes = hinfo->bits / 8;
  bool result = true;

  printf("Running append zeroes test   ");

  for(int rep = 0; rep < 100; rep++)
  {
    if(rep % 10 == 0) printf(".");

    unsigned char key[256];
    memset(key,0,sizeof(key));

    r.rand_p(key,32);
    // This test can halt early, so don't add input bytes to the VCode.

    std::vector<std::vector<uint8_t>> hashes;

    for(int i = 0; i < 32; i++) {
      std::vector<uint8_t> h(hashbytes);
      hash(key,32+i,seed,&h[0]);
      hashes.push_back(h);
      addVCodeOutput(&h[0], hashbytes);
    }

    // Sort in little-endian order, for human friendliness
    std::sort(hashes.begin(), hashes.end(),
            [](const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
                for (int i = a.size() - 1; i >= 0; i--) {
                    if (a[i] != b[i]) {
                        return a[i] < b[i];
                    }
                }
                return false;
            } );

    for(int i = 1; i < 32; i++) {
        if (memcmp(&hashes[i][0], &hashes[i-1][0], hashbytes) == 0) {
            result = false;
            goto done;
        }
    }
  }

 done:
  if (result) {
    printf(" PASS\n");
  } else {
    printf(" FAIL !!!!!\n");
  }

  recordTestResult(result, "Sanity", "Append zeroes");

  addVCodeResult(result);

  return result;
}

//----------------------------------------------------------------------------
// Prepending zero bytes to a key should also always cause it to
// produce a different hash value
bool PrependedZeroesTest (const HashInfo * hinfo, const seed_t seed) {
  Rand r(534281);

  const HashFn hash = hinfo->hashFn(g_hashEndian);
  const int hashbytes = hinfo->bits / 8;
  bool result = true;

  printf("Running prepend zeroes test  ");

  for(int rep = 0; rep < 100; rep++)
  {
    if(rep % 10 == 0) printf(".");

    unsigned char key[256];
    memset(key,0,sizeof(key));

    r.rand_p(key+32,32);
    // This test can halt early, so don't add input bytes to the VCode.

    std::vector<std::vector<uint8_t>> hashes;

    for(int i = 0; i < 32; i++) {
      std::vector<uint8_t> h(hashbytes);
      hash(key+32-i,32+i,seed,&h[0]);
      hashes.push_back(h);
      addVCodeOutput(&h[0], hashbytes);
    }

    // Sort in little-endian order, for human friendliness
    std::sort(hashes.begin(), hashes.end(),
            [](const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
                for (int i = a.size() - 1; i >= 0; i--) {
                    if (a[i] != b[i]) {
                        return a[i] < b[i];
                    }
                }
                return false;
            } );

    for(int i = 1; i < 32; i++) {
        if (memcmp(&hashes[i][0], &hashes[i-1][0], hashbytes) == 0) {
	    result = false;
	    goto done;
        }
    }
  }

 done:
  if (result) {
    printf(" PASS\n");
  } else {
    printf(" FAIL !!!!!\n");
  }

  recordTestResult(result, "Sanity", "Prepend zeroes");

  addVCodeResult(result);

  return result;
}

bool SanityTest(const HashInfo * hinfo) {
    bool result = true;

    // Sanity tests are all done with seed of 0
    const seed_t seed = hinfo->Seed(0, true);

    result &= SanityTest1(hinfo, seed);
    result &= SanityTest2(hinfo, seed);
    result &= AppendedZeroesTest(hinfo, seed);
    result &= PrependedZeroesTest(hinfo, seed);

    return result;
}
