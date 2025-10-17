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
 *     Copyright (c) 2019-2020 Yann Collet
 *     Copyright (c) 2021      Jim Apple
 *     Copyright (c) 2021      Ori Livneh
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
#include "Stats.h" // for combinatoric math
#include "Analyze.h"
#include "Instantiate.h"
#include "VCode.h"

#include "TwoBytesKeysetTest.h"

//-----------------------------------------------------------------------------
// Keyset 'TwoBytesLen' - generate all keys with length N with one or two non-zero bytes

static constexpr size_t MAX_TWOBYTES = 56;

template <typename hashtype>
static void TwoBytesLenKeygen( HashFn hash, const seed_t seed, size_t keylen, std::vector<hashtype> & hashes ) {
    //----------
    // Compute # of keys
    size_t keycount = 0;

    if (keylen < MAX_TWOBYTES) {
        keycount += (size_t)chooseK(keylen, 2);
        keycount *= 255 * 255;
    }
    keycount += keylen * 255;

    if (keylen < MAX_TWOBYTES) {
        printf("Keyset 'TwoBytes' - all %zd-byte keys with 1 or 2 non-zero bytes - %zd keys\n", keylen, keycount);
    } else {
        printf("Keyset 'OneByte ' - all %zd-byte keys with 1 non-zero byte  - %zd keys\n", keylen, keycount);
    }

    //----------
    // Add all keys with one non-zero byte
    VLA_ALLOC(uint8_t, key, keylen);
    memset(&key[0], 0, keylen);
    hashes.reserve(keycount);

    hashtype h( 0 );
    for (size_t byteA = 0; byteA < keylen; byteA++) {
        for (unsigned valA = 1; valA <= 255; valA++) {
            key[byteA] = (uint8_t)valA;
            hash(&key[0], keylen, seed, &h);
            addVCodeInput(&key[0], keylen);
            hashes.push_back(h);
        }
        key[byteA] = 0;
    }

    if (keylen >= MAX_TWOBYTES) {
        return;
    }

    //----------
    // Add all keys with two non-zero bytes
    for (size_t byteA = 0; byteA < keylen - 1; byteA++) {
        for (size_t byteB = byteA + 1; byteB < keylen; byteB++) {
            for (unsigned valA = 1; valA <= 255; valA++) {
                key[byteA] = (uint8_t)valA;
                for (unsigned valB = 1; valB <= 255; valB++) {
                    key[byteB] = (uint8_t)valB;
                    hash(&key[0], keylen, seed, &h);
                    addVCodeInput(&key[0], keylen);
                    hashes.push_back(h);
                }
                key[byteB] = 0;
            }
            key[byteA] = 0;
        }
    }
}

template <typename hashtype>
static bool TwoBytesTestLen( HashFn hash, const seed_t seed, size_t keylen, flags_t flags, const bool extra ) {
    std::vector<hashtype> hashes;

    TwoBytesLenKeygen(hash, seed, keylen, hashes);

    auto keyprint = [&]( hidx_t i ) {
                VLA_ALLOC(uint8_t, key, keylen);
                memset(&key[0], 0, keylen);

                if (i < (keylen * 255)) {
                    uint8_t val = (i % 255) + 1;
                    key[i / 255] = val;
                    printf("0x%016" PRIx64 "\t%4zd zeroes except key[%4d] = 0x%02x                  \t",
                            g_seed, keylen, i / 255, val);
                } else {
                    i -= keylen * 255;
                    uint8_t  valB = (i % 255) + 1; i /= 255;
                    uint8_t  valA = (i % 255) + 1; i /= 255;
                    uint32_t posA, posB;
                    GetDoubleLoopIndices(keylen, i, posA, posB);
                    key[posA] = valA;
                    key[posB] = valB;
                    printf("0x%016" PRIx64 "\t%4zd zeroes except key[%4d] = 0x%02x, key[%4d] = 0x%02x\t",
                            g_seed, keylen, posA, valA, posB, valB);
                }

                hashtype v( 0 );
                hash(&key[0], keylen, seed, &v);
                v.printhex(NULL);
            };

    bool result = TestHashList(hashes).reportFlags(flags).testDeltas(1).
            testDistribution(extra).dumpFailKeys(keyprint);

    printf("\n");

    recordTestResult(result, "TwoBytes", keylen);

    addVCodeResult(result);

    return result;
}

//-----------------------------------------------------------------------------
// Keyset 'TwoBytesUpToLen' - generate all keys up to length N with one or two non-zero bytes

template <typename hashtype>
static void TwoBytesUpToLenKeygen( HashFn hash, const seed_t seed, size_t maxlen, std::vector<hashtype> & hashes ) {
    //----------
    // Compute # of keys
    size_t keycount = 0;

    for (size_t i = 2; i <= maxlen; i++) {
        keycount += (size_t)chooseK(i, 2);
    }
    keycount *= 255 * 255;
    for (size_t i = 2; i <= maxlen; i++) {
        keycount += i * 255;
    }

    printf("Keyset 'TwoBytes' - all [2, %zd]-byte keys with 1 or 2 non-zero bytes - %zd keys\n", maxlen, keycount);

    //----------
    // Add all keys with one non-zero byte
    VLA_ALLOC(uint8_t, key, maxlen);
    memset(&key[0], 0, maxlen);
    hashes.reserve(keycount);

    hashtype h( 0 );
    for (size_t keylen = 2; keylen <= maxlen; keylen++) {
        for (size_t byteA = 0; byteA < keylen; byteA++) {
            for (unsigned valA = 1; valA <= 255; valA++) {
                key[byteA] = (uint8_t)valA;
                hash(&key[0], keylen, seed, &h);
                addVCodeInput(&key[0], keylen);
                hashes.push_back(h);
            }
            key[byteA] = 0;
        }
    }

    //----------
    // Add all keys with two non-zero bytes
    for (size_t keylen = 2; keylen <= maxlen; keylen++) {
        for (size_t byteA = 0; byteA < keylen - 1; byteA++) {
            for (size_t byteB = byteA + 1; byteB < keylen; byteB++) {
                for (unsigned valA = 1; valA <= 255; valA++) {
                    key[byteA] = (uint8_t)valA;
                    for (unsigned valB = 1; valB <= 255; valB++) {
                        key[byteB] = (uint8_t)valB;
                        hash(&key[0], keylen, seed, &h);
                        addVCodeInput(&key[0], keylen);
                        hashes.push_back(h);
                    }
                    key[byteB] = 0;
                }
                key[byteA] = 0;
            }
        }
    }
}

template <typename hashtype>
static bool TwoBytesTestUpToLen( HashFn hash, const seed_t seed, size_t maxlen, flags_t flags, const bool extra ) {
    std::vector<hashtype> hashes;

    TwoBytesUpToLenKeygen(hash, seed, maxlen, hashes);

    auto keyprint = [&]( hidx_t i ) {
                const uint32_t keylencnt = Sum1toN(maxlen) - 1;
                uint32_t       keylen;

                VLA_ALLOC(uint8_t, key, maxlen);
                memset(&key[0], 0, maxlen);

                if (i < (keylencnt * 255)) {
                    // One non-zero byte
                    uint8_t val = (i % 255) + 1;    i /= 255;
                    // Keylens start at 2, not 1, so there's some off-by-1
                    keylen = InverseSum1toN(i + 1); i -= Sum1toN(keylen) - 1; keylen++;
                    key[i] = val;
                    printf("0x%016" PRIx64 "\t%4d zeroes except key[%4d] = 0x%02x                  \t",
                            g_seed, keylen, i, val);
                } else {
                    // Two non-zero bytes
                    i -= keylencnt * 255;
                    uint8_t valB = (i % 255) + 1; i /= 255;
                    uint8_t valA = (i % 255) + 1; i /= 255;
                    keylen = InverseNChooseUpToK(i, 2, maxlen, 2);
                    uint32_t posA, posB;
                    GetDoubleLoopIndices(keylen, i, posA, posB);
                    key[posA] = valA;
                    key[posB] = valB;
                    printf("0x%016" PRIx64 "\t%4d zeroes except key[%4d] = 0x%02x, key[%4d] = 0x%02x\t",
                            g_seed, keylen, posA, valA, posB, valB);
                }

                hashtype v( 0 );
                hash(&key[0], keylen, seed, &v);
                v.printhex(NULL);
            };

    bool result = TestHashList(hashes).reportFlags(flags).testDeltas(1).
            testDistribution(extra).dumpFailKeys(keyprint);
    printf("\n");

    recordTestResult(result, "TwoBytes", maxlen);

    addVCodeResult(result);

    return result;
}

//-----------------------------------------------------------------------------
template <typename hashtype>
bool TwoBytesKeyTest( const HashInfo * hinfo, bool extra, flags_t flags ) {
    const HashFn hash   = hinfo->hashFn(g_hashEndian);
    bool         result = true;

    printf("[[[ Keyset 'TwoBytes' Tests ]]]\n\n");

    const seed_t seed = hinfo->Seed(g_seed);

    if (hinfo->isVerySlow()) {
        result &= TwoBytesTestUpToLen<hashtype>(hash, seed, 8, flags, true);
    } else {
        result &= TwoBytesTestUpToLen<hashtype>(hash, seed, 20, flags, extra);
        result &= TwoBytesTestLen    <hashtype>(hash, seed, 32, flags, extra);
        if (!hinfo->isSlow()) {
            result &= TwoBytesTestLen<hashtype>(hash, seed, 48, flags, extra);
        }
    }
    result &= TwoBytesTestLen<hashtype>(hash, seed, 1024, flags, true);
    result &= TwoBytesTestLen<hashtype>(hash, seed, 2048, flags, true);
    result &= TwoBytesTestLen<hashtype>(hash, seed, 4096, flags, true);

    printf("%s\n", result ? "" : g_failstr);

    return result;
}

INSTANTIATE(TwoBytesKeyTest, HASHTYPELIST);
