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
#include "Hashinfo.h"
#include "TestGlobals.h"
#include "Random.h"
#include "VCode.h"

#include "SanityTest.h"

// These sentinel bytes MUST be different values
static const uint8_t sentinel1 = 0x5c;
static const uint8_t sentinel2 = 0x36;
static_assert(sentinel1 != sentinel2, "valid sentinel bytes in SanityTest");

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

#define maybeprintf(...) if (REPORT(VERBOSE, flags)) { printf(__VA_ARGS__); }

static bool verify_sentinel( const uint8_t * buf, size_t len, const uint8_t sentinel, flags_t flags ) {
    for (size_t i = 0; i < len; i++) {
        if (buf[i] != sentinel) {
            maybeprintf(" %" PRIu64 ": 0x%02X != 0x%02X: ", i, buf[i], sentinel);
            return false;
        }
    }
    return true;
}

template <bool checksentinels>
static bool verify_hashmatch( const uint8_t * buf1, const uint8_t * buf2, size_t len, flags_t flags ) {
    if (likely(memcmp(buf1, buf2, len) == 0)) {
        return true;
    }
    for (size_t i = 0; i < len; i++) {
        if (buf1[i] == buf2[i]) { continue; }
        if (checksentinels &&
                (buf1[i] == sentinel1) && (buf2[i] == sentinel2)) {
            maybeprintf(" output byte %" PRIu64 " not altered:", i);
        } else {
            maybeprintf(" output byte %" PRIu64 " inconsistent (0x%02X != 0x%02X):", i, buf1[i], buf2[i]);
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
bool SanityTest1( const HashInfo * hinfo, flags_t flags ) {
    Rand r( 763849 );
    bool result            = true;
    bool danger            = false;

    const HashFn hash      = hinfo->hashFn(g_hashEndian);
    const int    hashbytes = hinfo->bits / 8;
    const seed_t seed      = hinfo->Seed(0, HashInfo::SEED_FORCED);

    const int reps         = 10;
    const int keymax       = 256;
    const int pad          = 16 * 3;
    const int buflen       = keymax + pad;

    uint8_t * buffer1      = new uint8_t[buflen];
    uint8_t * buffer2      = new uint8_t[buflen];
    uint8_t * hash1        = new uint8_t[buflen];
    uint8_t * hash2        = new uint8_t[buflen];

    maybeprintf("Running sanity check 1       ");

    memset(hash1, sentinel1, buflen);
    memset(hash2, sentinel2, buflen);

    for (int irep = 0; irep < reps; irep++) {
        if (REPORT(PROGRESS, flags)) {
            progressdots(irep, 0, reps - 1, 10);
        }

        for (int len = 0; len <= keymax; len++) {
            // Make 2 copies of some random input data, and hash one
            // of them.
            r.rand_n(buffer1, buflen);
            memcpy(buffer2, buffer1, buflen);
            hash(buffer1, len, seed, hash1);
            addVCodeOutput(hash1, hashbytes);

            // See if the hash somehow changed the input data
            if (memcmp(buffer1, buffer2, buflen) != 0) {
                maybeprintf(" hash altered input buffer:");
                result = false;
                danger = true;
                goto end_sanity;
            }

            // See if the hash overflowed its output buffer
            if (!verify_sentinel(hash1 + hashbytes, buflen - hashbytes, sentinel1, flags)) {
                maybeprintf(" hash overflowed output buffer (pass 1):");
                result = false;
                danger = true;
                goto end_sanity;
            }

            // Hash the same data again
            hash(buffer1, len, seed, hash2);

            // See if the hash overflowed output buffer this time
            if (!verify_sentinel(hash2 + hashbytes, buflen - hashbytes, sentinel2, flags)) {
                maybeprintf(" hash overflowed output buffer (pass 2):");
                result = false;
                danger = true;
                goto end_sanity;
            }

            // See if the hashes match, and if not then characterize the failure
            if (!verify_hashmatch<true>(hash1, hash2, hashbytes, flags)) {
                result = false;
                goto end_sanity;
            }
        }
    }

  end_sanity:
    if (result == false) {
        printf("%s", REPORT(VERBOSE, flags) ? " FAIL  !!!!!\n" : " FAIL");
    } else {
        printf("%s", REPORT(VERBOSE, flags) ? " PASS\n"        : " pass");
    }

    if (danger) {
        // This is always fatal in any context
        printf("\nERROR: Dangerous hash behavior detected!\n");
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
// This test is expensive, so only run 1 rep.
//
// This test can halt early, so don't add input bytes to the VCode.
bool SanityTest2( const HashInfo * hinfo, flags_t flags ) {
    Rand r( 104125 );
    bool result            = true;

    const HashFn hash      = hinfo->hashFn(g_hashEndian);
    const int    hashbytes = hinfo->bits / 8;
    seed_t       seed      = hinfo->Seed(0, HashInfo::SEED_FORCED); // not const!

    const int reps         = 5;
    const int keymax       = 128;
    const int pad          = 16; // Max alignment offset tested
    const int buflen       = keymax + pad * 3;

    // XXX Check alignment!?!
    uint8_t * buffer1 = new uint8_t[buflen   ];
    uint8_t * buffer2 = new uint8_t[buflen   ];
    uint8_t * hash1   = new uint8_t[hashbytes];
    uint8_t * hash2   = new uint8_t[hashbytes];
    uint8_t * hash3   = new uint8_t[hashbytes];

    maybeprintf("Running sanity check 2       ");

    for (int irep = 0; irep < reps; irep++) {
        for (int len = 1; len <= keymax; len++) {
            ExtBlob key1( &buffer1[pad], len );

            // Fill the first buffer with random data
            r.rand_n(buffer1, buflen);

            if (REPORT(PROGRESS, flags)) {
                progressdots(len + irep * keymax, 1, reps * keymax, 10);
            }
            // Record the hash of key1. hash1 becomes the correct
            // answer that the rest of the loop will test against.
            hash(key1, len, seed, hash1);
            addVCodeOutput(hash1, hashbytes);

            // See if the hash behaves sanely using only key1
            for (int bit = 0; bit < (len * 8); bit++) {
                // Flip a key bit, hash the key -> we should get a different result.
                key1.flipbit(bit);
                hash(key1, len, seed, hash2);
                addVCodeOutput(hash2, hashbytes);

                if (unlikely(memcmp(hash1, hash2, hashbytes) == 0)) {
                    maybeprintf(" flipped bit %d/%d, got identical output:", bit, len*8);
                    result = false;
                    goto end_sanity;
                }

                // Flip it back, hash again -> we should get the original result.
                key1.flipbit(bit);
                hash(key1, len, seed, hash2);

                if (!verify_hashmatch<false>(hash1, hash2, hashbytes, flags)) {
                    result = false;
                    goto end_sanity;
                }
            }

            for (int bit = 0; bit < 64; bit++) {
                // Flip a seed bit, hash the key -> we should get a different result.
                seed = hinfo->Seed(UINT64_C(1) << bit, HashInfo::SEED_FORCED);
                hash(key1, len, seed, hash2);
                addVCodeOutput(hash2, hashbytes);

                if (unlikely(memcmp(hash1, hash2, hashbytes) == 0)) {
                    if ((bit < 32) || !hinfo->is32BitSeed()) {
                        maybeprintf(" flipped seed bit %d, got identical output:", bit);
                        result = false;
                        goto end_sanity;
                    }
                } else if ((bit >= 32) && hinfo->is32BitSeed()) {
                    maybeprintf(" flipped seed bit %d for hash marked as 32-bit seed,\n"
                            "                             got different output:", bit);
                    result = false;
                    goto end_sanity;
                }

                // Flip it back, hash again -> we should get the original result.
                seed = hinfo->Seed(0, HashInfo::SEED_FORCED);
                hash(key1, len, seed, hash2);

                if (!verify_hashmatch<false>(hash1, hash2, hashbytes, flags)) {
                    result = false;
                    goto end_sanity;
                }
            }

            for (int offset = pad; offset < pad * 2; offset++) {
                // Make key2 have alignment independent of key1
                ExtBlob key2( &buffer2[offset], len );

                // Fill the second buffer with different random data
                r.rand_n(buffer2, buflen);

                // Make key2 have the same data as key1. The rest of
                // buffer2 is still random data that differs from
                // buffer1, including data before the keys.
                memcpy(key2, key1, len);

                // Now see if key2's hash matches
                hash(key2, len, seed, hash2);
                addVCodeOutput(hash2, hashbytes);

                // If it doesn't, then try seeing why.
                //
                // Make buffer2 an offset-copy of buffer1. Then try
                // altering bytes in buffer2 that aren't key bytes and
                // making sure the hash doesn't change, to try to
                // catch hashes that depend on out-of-bounds key
                // bytes.
                //
                // I don't know how to catch hashes that merely read
                // out-of-bounds key bytes, but doing that isn't
                // necessarily an error or even unsafe; see:
                // https://stackoverflow.com/questions/37800739/
                if (unlikely(memcmp(hash1, hash2, hashbytes) != 0)) {
                    memcpy(buffer2 + offset - pad, buffer1, len + 2 * pad);
                    uint8_t * const key2_start = buffer2 + offset;
                    uint8_t * const key2_end   = buffer2 + offset + len;
                    for (uint8_t * ptr = key2_start - pad; ptr < key2_end + pad; ptr++) {
                        if ((ptr >= key2_start) && (ptr < key2_end)) { continue; }
                        *ptr ^= 0xFF;
                        hash(key2, len, seed, hash3);
                        if (memcmp(hash1, hash3, hashbytes) != 0) {
                            maybeprintf(" changing single non-key byte (%s %zd) altered hash: ",
                                    ptr < key2_start ? "head -" : "tail +",
                                    ptr < key2_start ? key2_start - ptr : ptr - key2_end + 1);
                            result = false;
                            goto end_sanity;
                        }
                    }
                    // Just in case the reason couldn't be pinpointed...
                    maybeprintf(" changing some non-key byte altered hash: ");
                    result = false;
                    goto end_sanity;
                }
            }
        }
    }

  end_sanity:
    if (result == false) {
        printf("%s", REPORT(VERBOSE, flags) ? " FAIL  !!!!!\n" : " ... FAIL");
    } else {
        printf("%s", REPORT(VERBOSE, flags) ? " PASS\n"        : " ... pass");
    }

    recordTestResult(result, "Sanity", "Basic 2");

    addVCodeResult(result);

    delete [] buffer1;
    delete [] buffer2;

    delete [] hash1;
    delete [] hash2;
    delete [] hash3;

    return result;
}

//----------------------------------------------------------------------------
// Make sure results are consistent across threads, both 1) when
// Seed() is first called once in the main process, and 2) when Seed()
// is called per-hash inside each thread.

template <bool reseed>
static void hashthings( const HashInfo * hinfo, seed_t seed, uint32_t reps, uint32_t order,
        std::vector<uint8_t> & keys, std::vector<uint8_t> & hashes, flags_t flags ) {
    const HashFn   hash      = hinfo->hashFn(g_hashEndian);
    const uint32_t hashbytes = hinfo->bits / 8;

    // Each thread should hash the keys in a different, random order
    std::vector<uint32_t> idxs( reps );

    if (order != 0) {
        Rand r( {583015, order} );
        for (uint32_t i = 0; i < reps; i++) { idxs[i] = i; }
        for (uint32_t i = reps - 1; i > 0; i--) {
            std::swap(idxs[i], idxs[r.rand_range(i + 1)]);
        }
    }

    // Hash each key, and put the result into its spot in hashes[].
    // If we're testing #2 above, then reseed per-key.
    // Add each key to the input VCode, but only on the main proc.
    // Print out progress dots on the main proc AND thread #0.
    for (uint32_t i = 0; i < reps; i++) {
        const uint32_t idx = (order == 0) ? i : idxs[i];
        if (reseed) { seed = hinfo->Seed(idx * UINT64_C(0xa5), HashInfo::SEED_FORCED, 1); }
        hash(&keys[idx * reps], idx + 1, seed, &hashes[idx * hashbytes]);
        if (REPORT(PROGRESS, flags) && (order < 2)) { progressdots(i, 0, reps - 1, 4); }
        if (order == 0) { addVCodeInput(&keys[idx * reps], idx + 1); }
    }
}

template <bool seedthread>
static bool ThreadingTest( const HashInfo * hinfo, flags_t flags ) {
    Rand r( 955165 );

    const uint32_t       hashbytes = hinfo->bits / 8;
    const uint32_t       reps      = 1024 * 16;
    const uint32_t       keybytes  = (reps * reps);
    std::vector<uint8_t> keys( keybytes );
    std::vector<uint8_t> mainhashes( reps * hashbytes );
    const seed_t         seed = seedthread ? 0 : hinfo->Seed(0x12345, HashInfo::SEED_FORCED, 1);
    bool result = true;

    maybeprintf("Running thread-safety test %d ", seedthread ? 2 : 1);

    if ((g_NCPU > 1) || g_doVCode) {
        // Generate a bunch of key data. Key 0 is 1 byte, key 1 is 2
        // bytes, etc. We really only need (reps*(reps+1)/2) bytes,
        // but this is just easier to code and slightly easier to
        // understand.
        r.rand_n(&keys[0], keybytes);
        maybeprintf(".");

        // Compute all the hashes in order on the main process in order
        hashthings<seedthread>(hinfo, seed, reps, 0, keys, mainhashes, flags);
        addVCodeOutput(&mainhashes[0], reps * hashbytes);
    } else {
        maybeprintf(".....");
    }

    if (g_NCPU > 1) {
#if defined(HAVE_THREADS)
        // Compute all the hashes in different random orders in threads
        std::vector<std::vector<uint8_t>> threadhashes( g_NCPU, std::vector<uint8_t>(reps * hashbytes));
        std::vector<std::thread> t(g_NCPU);
        for (unsigned i = 0; i < g_NCPU; i++) {
            t[i] = std::thread {
                hashthings<seedthread>, hinfo, seed, reps, i + 1, std::ref(keys), std::ref(threadhashes[i]), flags
            };
        }
        for (unsigned i = 0; i < g_NCPU; i++) {
            t[i].join();
        }
        // Make sure all thread results match the main process
        maybeprintf(".");
        for (unsigned i = 0; i < g_NCPU; i++) {
            if (!memcmp(&mainhashes[0], &threadhashes[i][0], reps * hashbytes)) {
                continue;
            }
            if (!REPORT(VERBOSE, flags)) {
                result = false;
                break;
            }
            for (uint32_t j = 0; j < reps; j++) {
                if (memcmp(&mainhashes[j * hashbytes], &threadhashes[i][j * hashbytes], hashbytes) != 0) {
                    maybeprintf("\nMismatch between main process and thread #%d at index %d\n", i, j);
                    if (REPORT(VERBOSE, flags)) {
                        ExtBlob(&mainhashes[j * hashbytes], hashbytes).printhex("  main   :");
                        ExtBlob(&threadhashes[i][j * hashbytes], hashbytes).printhex("  thread :");
                    }
                    result = false;
                    break; // Only breaks out of j loop
                }
            }
        }

        if (result == false) {
            printf("%s", REPORT(VERBOSE, flags) ? " FAIL  !!!!!\n\n" : " ... FAIL");
        } else {
            printf("%s", REPORT(VERBOSE, flags) ? " PASS\n"         : " ... pass");
        }

        recordTestResult(result, "Sanity", "Thread safety");
    } else {
        printf("%s", REPORT(VERBOSE, flags) ? "..... SKIPPED (ncpu set to 1)\n" : " ... skip");
#else
    } else {
        printf("%s", REPORT(VERBOSE, flags) ? "..... SKIPPED (compiled without threads)\n" : " ... skip");
#endif // HAVE_THREADS
    }

    // Don't add the result to the vcode, because it's too
    // platform-dependent.

    return result;
}

//----------------------------------------------------------------------------
// Appending zero bytes to a key should always cause it to produce a different
// hash value
bool AppendedZeroesTest( const HashInfo * hinfo, flags_t flags ) {
    Rand r( 434201 );

    const HashFn hash      = hinfo->hashFn(g_hashEndian);
    const int    hashbytes = hinfo->bits / 8;
    const seed_t seed      = hinfo->Seed(0, HashInfo::SEED_FORCED);
    bool         result    = true;

    maybeprintf("Running append zeroes test   ");

    for (int rep = 0; rep < 100; rep++) {
        if (REPORT(PROGRESS, flags)) {
            progressdots(rep, 0, 99, 10);
        }

        unsigned char key[256];
        memset(key, 0, sizeof(key));

        r.rand_n(key, 32);
        // This test can halt early, so don't add input bytes to the VCode.

        std::vector<std::vector<uint8_t>> hashes;

        for (int i = 0; i < 32; i++) {
            std::vector<uint8_t> h( hashbytes );
            hash(key, 32 + i, seed, &h[0]);
            hashes.push_back(h);
            addVCodeOutput(&h[0], hashbytes);
        }

        // Sort in little-endian order, for human friendliness
        std::sort(hashes.begin(), hashes.end(), []( const std::vector<uint8_t> & a, const std::vector<uint8_t> & b ) {
                for (int i = a.size() - 1; i >= 0; i--) {
                    if (a[i] != b[i]) {
                        return a[i] < b[i];
                    }
                }
                return false;
            });

        for (int i = 1; i < 32; i++) {
            if (memcmp(&hashes[i][0], &hashes[i - 1][0], hashbytes) == 0) {
                result = false;
                goto done;
            }
        }
    }

  done:
    if (result == false) {
        printf("%s", REPORT(VERBOSE, flags) ? " FAIL  !!!!!\n" : " ... FAIL");
    } else {
        printf("%s", REPORT(VERBOSE, flags) ? " PASS\n"        : " ... pass");
    }

    recordTestResult(result, "Sanity", "Append zeroes");

    addVCodeResult(result);

    return result;
}

//----------------------------------------------------------------------------
// Prepending zero bytes to a key should also always cause it to
// produce a different hash value
bool PrependedZeroesTest( const HashInfo * hinfo, flags_t flags ) {
    Rand r( 14465 );

    const HashFn hash      = hinfo->hashFn(g_hashEndian);
    const int    hashbytes = hinfo->bits / 8;
    const seed_t seed      = hinfo->Seed(0, HashInfo::SEED_FORCED);
    bool         result    = true;

    maybeprintf("Running prepend zeroes test  ");

    for (int rep = 0; rep < 100; rep++) {
        if (REPORT(PROGRESS, flags)) {
            progressdots(rep, 0, 99, 10);
        }

        unsigned char key[256];
        memset(key, 0, sizeof(key));

        r.rand_n(key + 32, 32);
        // This test can halt early, so don't add input bytes to the VCode.

        std::vector<std::vector<uint8_t>> hashes;

        for (int i = 0; i < 32; i++) {
            std::vector<uint8_t> h( hashbytes );
            hash(key + 32 - i, 32 + i, seed, &h[0]);
            hashes.push_back(h);
            addVCodeOutput(&h[0], hashbytes);
        }

        // Sort in little-endian order, for human friendliness
        std::sort(hashes.begin(), hashes.end(), []( const std::vector<uint8_t> & a, const std::vector<uint8_t> & b ) {
                for (int i = a.size() - 1; i >= 0; i--) {
                    if (a[i] != b[i]) {
                        return a[i] < b[i];
                    }
                }
                return false;
            });

        for (int i = 1; i < 32; i++) {
            if (memcmp(&hashes[i][0], &hashes[i - 1][0], hashbytes) == 0) {
                result = false;
                goto done;
            }
        }
    }

  done:
    if (result == false) {
        printf("%s", REPORT(VERBOSE, flags) ? " FAIL  !!!!!\n" : " ... FAIL");
    } else {
        printf("%s", REPORT(VERBOSE, flags) ? " PASS\n"        : " ... pass");
    }

    recordTestResult(result, "Sanity", "Prepend zeroes");

    addVCodeResult(result);

    return result;
}

void SanityTestHeader( flags_t flags ) {
    if (REPORT(VERBOSE, flags)) {
        printf("%-25s  %-10s   %13s     %13s     %13s\n",
                "Name", "Impl   ", " Sanity 1+2  ", "   Zeroes    ", " Thread-safe ");
        printf("%-25s  %-10s   %13s     %13s     %13s\n",
                "-------------------------", "----------", "-------------", "-------------", "-------------");
    } else {
        printf("%-25s   %13s     %13s     %13s\n",
                "Name", " Sanity 1+2  ", "   Zeroes    ", " Thread-safe ");
        printf("%-25s   %13s     %13s     %13s\n",
                "-------------------------", "-------------", "-------------", "-------------");
    }
}

bool SanityTest( const HashInfo * hinfo, flags_t flags, bool oneline ) {
    bool result       = true;
    bool threadresult = true;

    if (oneline) {
        if (REPORT(VERBOSE, flags)) {
            printf("%-25s  %-10s  ", hinfo->name, hinfo->impl);
        } else {
            printf("%-25s  ", hinfo->name);
        }
    }

    // Subtests are verbose unless oneline mode is enabled
    if (oneline) {
        flags &= ~FLAG_REPORT_VERBOSE;
        flags &= ~FLAG_REPORT_PROGRESS;
    } else {
        flags |= FLAG_REPORT_VERBOSE;
    }

    result       &= SanityTest1(hinfo, flags);
    result       &= SanityTest2(hinfo, flags);
    result       &= AppendedZeroesTest(hinfo, flags);
    result       &= PrependedZeroesTest(hinfo, flags);
    threadresult &= ThreadingTest<false>(hinfo, flags);
    threadresult &= ThreadingTest<true>(hinfo, flags);

    // If threading test cannot give meaningful results, then don't
    // bother printing them out. :) But still run them above so the
    // user can see *why* they were skipped.
    if (g_NCPU == 1) {
        goto out;
    }

    if (!oneline && !threadresult) {
        DisableThreads();
    }

    result &= threadresult;

    if ((hinfo->impl_flags & FLAG_IMPL_SANITY_FAILS) && result) {
        printf("%sSANITY_FAILS set, but hash passed", oneline ? "\t" : "");
    } else if (!(hinfo->impl_flags & FLAG_IMPL_SANITY_FAILS) && !result) {
        printf("%sSANITY_FAILS unset, but hash failed", oneline ? "\t" : "");
    }

  out:
    if (oneline) {
        printf("\n");
    }
    return result;
}
