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
#include "Stats.h" // for chooseK
#include "Analyze.h"
#include "Instantiate.h"
#include "VCode.h"

#include "TwoBytesKeysetTest.h"

//-----------------------------------------------------------------------------
// Keyset 'TwoBytesLen' - generate all keys with length N with one or two non-zero bytes

static constexpr int MAX_TWOBYTES = 56;

template <typename hashtype>
static void TwoBytesLenKeygen( HashFn hash, const seed_t seed, int keylen, std::vector<hashtype> & hashes ) {
    //----------
    // Compute # of keys
    int keycount = 0;

    if (keylen < MAX_TWOBYTES) {
        keycount += (int)chooseK(keylen, 2);
        keycount *= 255 * 255;
    }
    keycount += keylen * 255;

    if (keylen < MAX_TWOBYTES) {
        printf("Keyset 'TwoBytes' - all %d-byte keys with 1 or 2 non-zero bytes - %d keys\n", keylen, keycount);
    } else {
        printf("Keyset 'OneByte ' - all %d-byte keys with 1 non-zero byte  - %d keys\n", keylen, keycount);
    }

    //----------
    // Add all keys with one non-zero byte
    uint8_t key[keylen];
    memset(key, 0, keylen);
    hashes.reserve(keycount);

    for (int byteA = 0; byteA < keylen; byteA++) {
        for (int valA = 1; valA <= 255; valA++) {
            hashtype h;
            key[byteA] = (uint8_t)valA;
            hash(key, keylen, seed, &h);
            addVCodeInput(key, keylen);
            hashes.push_back(h);
        }
        key[byteA] = 0;
    }

    if (keylen >= MAX_TWOBYTES) {
        return;
    }

    //----------
    // Add all keys with two non-zero bytes
    for (int byteA = 0; byteA < keylen - 1; byteA++) {
        for (int byteB = byteA + 1; byteB < keylen; byteB++) {
            for (int valA = 1; valA <= 255; valA++) {
                key[byteA] = (uint8_t)valA;
                for (int valB = 1; valB <= 255; valB++) {
                    hashtype h;
                    key[byteB] = (uint8_t)valB;
                    hash(key, keylen, seed, &h);
                    addVCodeInput(key, keylen);
                    hashes.push_back(h);
                }
                key[byteB] = 0;
            }
            key[byteA] = 0;
        }
    }
}

template <typename hashtype>
static bool TwoBytesTestLen( HashFn hash, const seed_t seed, int keylen, bool verbose, const bool extra ) {
    std::vector<hashtype> hashes;

    TwoBytesLenKeygen(hash, seed, keylen, hashes);

    bool result = TestHashList(hashes).drawDiagram(verbose).testDeltas(1).testDistribution(extra);
    printf("\n");

    recordTestResult(result, "TwoBytes", keylen);

    addVCodeResult(result);

    return result;
}

//-----------------------------------------------------------------------------
// Keyset 'TwoBytesUpToLen' - generate all keys up to length N with one or two non-zero bytes

template <typename hashtype>
static void TwoBytesUpToLenKeygen( HashFn hash, const seed_t seed, int maxlen, std::vector<hashtype> & hashes ) {
    //----------
    // Compute # of keys
    int keycount = 0;

    for (int i = 2; i <= maxlen; i++) {
        keycount += (int)chooseK(i, 2);
    }
    keycount *= 255 * 255;
    for (int i = 2; i <= maxlen; i++) {
        keycount += i * 255;
    }

    printf("Keyset 'TwoBytes' - all [2, %d]-byte keys with 1 or 2 non-zero bytes - %d keys\n", maxlen, keycount);

    //----------
    // Add all keys with one non-zero byte
    uint8_t key[maxlen];
    memset(key, 0, maxlen);
    hashes.reserve(keycount);

    for (int keylen = 2; keylen <= maxlen; keylen++) {
        for (int byteA = 0; byteA < keylen; byteA++) {
            for (int valA = 1; valA <= 255; valA++) {
                hashtype h;
                key[byteA] = (uint8_t)valA;
                hash(key, keylen, seed, &h);
                addVCodeInput(key, keylen);
                hashes.push_back(h);
            }
            key[byteA] = 0;
        }
    }

    //----------
    // Add all keys with two non-zero bytes
    for (int keylen = 2; keylen <= maxlen; keylen++) {
        for (int byteA = 0; byteA < keylen - 1; byteA++) {
            for (int byteB = byteA + 1; byteB < keylen; byteB++) {
                for (int valA = 1; valA <= 255; valA++) {
                    key[byteA] = (uint8_t)valA;
                    for (int valB = 1; valB <= 255; valB++) {
                        hashtype h;
                        key[byteB] = (uint8_t)valB;
                        hash(key, keylen, seed, &h);
                        addVCodeInput(key, keylen);
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
static bool TwoBytesTestUpToLen( HashFn hash, const seed_t seed, int maxlen, bool verbose, const bool extra ) {
    std::vector<hashtype> hashes;

    TwoBytesUpToLenKeygen(hash, seed, maxlen, hashes);

    bool result = TestHashList(hashes).drawDiagram(verbose).testDeltas(1).testDistribution(extra);
    printf("\n");

    recordTestResult(result, "TwoBytes", maxlen);

    addVCodeResult(result);

    return result;
}

//-----------------------------------------------------------------------------
template <typename hashtype>
bool TwoBytesKeyTest( const HashInfo * hinfo, const bool verbose, const bool extra ) {
    const HashFn hash   = hinfo->hashFn(g_hashEndian);
    bool         result = true;

    printf("[[[ Keyset 'TwoBytes' Tests ]]]\n\n");

    const seed_t seed = hinfo->Seed(g_seed);

    if (hinfo->isVerySlow()) {
        result &= TwoBytesTestUpToLen<hashtype>(hash, seed, 8, verbose, true);
    } else {
        result &= TwoBytesTestUpToLen<hashtype>(hash, seed, 20, verbose, extra);
        result &= TwoBytesTestLen    <hashtype>(hash, seed, 32, verbose, extra);
        if (!hinfo->isSlow()) {
            result &= TwoBytesTestLen<hashtype>(hash, seed, 48, verbose, extra);
        }
    }
    result &= TwoBytesTestLen<hashtype>(hash, seed, 1024, verbose, true);
    result &= TwoBytesTestLen<hashtype>(hash, seed, 2048, verbose, true);
    result &= TwoBytesTestLen<hashtype>(hash, seed, 4096, verbose, true);

    printf("%s\n", result ? "" : g_failstr);

    return result;
}

INSTANTIATE(TwoBytesKeyTest, HASHTYPELIST);
