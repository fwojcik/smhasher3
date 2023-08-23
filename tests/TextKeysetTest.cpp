/*
 * SMHasher3
 * Copyright (C) 2021-2023  Frank J. T. Wojcik
 * Copyright (C) 2023       jason
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
 *     Copyright (c) 2019-2021 Reini Urban
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
#include "Random.h"
#include "Analyze.h"
#include "Instantiate.h"
#include "VCode.h"
#include "Wordlist.h"

#include <string>
#include <math.h>

//-----------------------------------------------------------------------------
// Keyset 'Num' - generate all keys from 0 through numcount-1 in string form,
// either with or without commas.

template <typename hashtype, bool commas>
static bool TextNumImpl( HashFn hash, const seed_t seed, const uint64_t numcount, bool verbose ) {
    std::vector<hashtype> hashes;
    hashes.resize(numcount);

    printf("Keyset 'TextNum' - numbers in text form %s commas - %ld keys\n", commas ? "with" : "without", numcount);

    for (uint64_t n = 0; n < numcount; n++) {
        std::string nstr = std::to_string(n);
        if (commas) {
            for (size_t i = nstr.length(); i > 3; i -= 3) {
                nstr.insert(i - 3, ",");
            }
        }
        hash(nstr.c_str(), nstr.length(), seed, &hashes[n]);
        addVCodeInput(nstr.c_str(), nstr.length());
    }

    //----------
    bool result = TestHashList(hashes).drawDiagram(verbose);
    printf("\n");

    recordTestResult(result, "TextNum", commas ? "with commas" : "without commas");

    addVCodeResult(result);

    return result;
}

//-----------------------------------------------------------------------------
// Keyset 'Text' - generate all keys of the form "prefix"+"core"+"suffix",
// where "core" consists of all possible combinations of the given character
// set of length N.

template <typename hashtype>
static bool TextKeyImpl( HashFn hash, const seed_t seed, const char * prefix, const char * coreset,
        const int corelen, const char * suffix, bool verbose ) {
    const int prefixlen = (int)strlen(prefix);
    const int suffixlen = (int)strlen(suffix);
    const int corecount = (int)strlen(coreset);

    const int keybytes  = prefixlen + corelen + suffixlen;
    long      keycount  = (long)pow(double(corecount), double(corelen));

    if (keycount > INT32_MAX / 8) {
        keycount = INT32_MAX / 8;
    }

    uint8_t * key = new uint8_t[std::min(keybytes + 1, 64)];
    memcpy(key, prefix, prefixlen);
    memset(key + prefixlen, 'X', corelen);
    memcpy(key + prefixlen + corelen, suffix, suffixlen);
    key[keybytes] = 0;

    printf("Keyset 'Text' - keys of form \"%s\" - %ld keys\n", key, keycount);

    //----------

    std::vector<hashtype> hashes;
    hashes.resize(keycount);

    for (int i = 0; i < (int)keycount; i++) {
        int t = i;

        for (int j = 0; j < corelen; j++) {
            key[prefixlen + j] = coreset[t % corecount]; t /= corecount;
        }

        hash(key, keybytes, seed, &hashes[i]);
        addVCodeInput(key, keybytes);
    }

    //----------
    bool result = TestHashList(hashes).drawDiagram(verbose);
    printf("\n");

    memset(key + prefixlen, 'X', corelen);
    recordTestResult(result, "Text", (const char *)key);

    addVCodeResult(result);

    delete [] key;

    return result;
}

//-----------------------------------------------------------------------------
// Keyset 'Words' - pick random chars from coreset (alnum or password chars)

template <typename hashtype>
static bool WordsKeyImpl( HashFn hash, const seed_t seed, const uint32_t keycount, const uint32_t minlen,
        const uint32_t maxlen, const char * coreset, const char * name, bool verbose ) {
    const uint32_t corecount = strlen(coreset);
    assert(maxlen >= minlen);
    assert(corecount <= 256);

    // Compute how many of each key length to do by dividing keys among
    // lengths evenly, except when there aren't enough keys of a given
    // length to take on their fair share.
    //
    // This could be done "in line" in the for() loop below, but this makes
    // things clearer, and can catch some parameter errors early.
    //
    // maxprefix is the highest key length where the number of possible
    // keys can fit into a 64-bit integer.
    const uint32_t maxprefix = floor(64.0 / log2(corecount));
    uint32_t *     lencount  = new uint32_t[maxlen + 1];
    uint32_t       remaining = keycount;
    double         maxkeys   = pow((double)corecount, (double)minlen);
    for (unsigned len = minlen; len <= maxlen; len++) {
        lencount[len] = lround(std::min(maxkeys, (double)remaining / (double)(maxlen - len + 1)));
        remaining    -= lencount[len];
        if (len < maxprefix) {
            maxkeys  *= corecount;
        }
        //printf("Len %2d == %d; remaining = %d\n", len, lencount[len], remaining);
    }
    if (remaining > 0) {
        printf("WARNING: skipping %d keys; maxlen and/or coreset parameters are bad\n", remaining);
    }

    printf("Keyset 'Words' - %d-%d random chars from %s charset - %d keys\n",
            minlen, maxlen, name, keycount - remaining);

    std::vector<hashtype> hashes(keycount - remaining);
    char *   key = new char[maxlen];
    Rand     r1( 483723 + minlen, maxlen );
    uint64_t itemnum;
    uint32_t cnt = 0;
    for (uint32_t len = minlen; len <= maxlen; len++) {
        // Generate lencount[len] keys of this length. For the first
        // prefixlen characters, convert a random numeric sequence element
        // into characters from coreset. This prevents duplicate random
        // words from being generated. If there are remaining characters,
        // just pick any random ones from coreset.
        const uint32_t prefixlen = std::min(len, maxprefix);
        const uint64_t curcount  = pow((double)corecount, (double)prefixlen);

        RandSeq rs = r1.get_seq(SEQ_NUM, curcount - 1);
        Rand r2( r1.rand_u64() );
        for (uint32_t i = 0; i < lencount[len]; i++) {
            rs.write(&itemnum, i, 1);
            for (unsigned j = 0; j < prefixlen; j++) {
                key[j] = coreset[itemnum % corecount]; itemnum /= corecount;
            }
            for (unsigned j = prefixlen; j < len; j++) {
                key[j] = coreset[r2.rand_range(corecount)];
            }

            hash(key, len, seed, &hashes[cnt++]);
            addVCodeInput(key, len);
            //fprintf(stderr, "%ld\t%d:%ld\t%.*s\n", i, len, nnn, len, key);
        }
    }

    //----------
    bool result = TestHashList(hashes).drawDiagram(verbose);
    printf("\n");

    char buf[32];
    snprintf(buf, sizeof(buf), "Words %s %d-%d", name, minlen, maxlen);
    recordTestResult(result, "Text", buf);

    addVCodeResult(result);

    delete [] lencount;
    delete [] key;

    return result;
}

//-----------------------------------------------------------------------------
// Keyset 'Long' - hash very long strings of text with small changes

template <typename hashtype, bool varyprefix>
static bool WordsLongImpl( HashFn hash, const seed_t seed, const long keycount, const int varylen, const int minlen,
        const int maxlen, const char * coreset, const char * name, bool verbose ) {
    const int    corecount = (int)strlen(coreset);
    const size_t totalkeys = keycount * (corecount - 1) * varylen;
    char *       key       = new char[maxlen + 1];

    printf("Keyset 'Long' - %d-%d random chars from %s charset - varying %s %d chars - %ld keys\n",
            minlen, maxlen, name, varyprefix ? "first" : "last", varylen, totalkeys);
    assert(minlen >= 0    );
    assert(maxlen > minlen);

    std::vector<hashtype> hashes;
    hashes.resize(totalkeys);
    Rand r2, r1( 425379 + 604 * varyprefix + minlen, maxlen );
    size_t cnt = 0;

    for (long i = 0; i < keycount; i++) {
        r2.reseed(r1.rand_u64());

        // These words are long enough that we don't explicitly avoid collisions.
        const int len = minlen + r2.rand_range(maxlen - minlen + 1);
        key[len] = 0;
        for (int j = 0; j < len; j++) {
            key[j] = coreset[r2.rand_range(corecount)];
        }

        for (int offset = 0; offset < varylen; offset++) {
            size_t j = offset + (varyprefix ? 0 : (len - varylen));
            uint8_t prv = key[j];
            for (int k = 0; k < corecount; k++) {
                if (prv == coreset[k]) {
                    continue;
                }
                key[j] = coreset[k];
                hash(key, len, seed, &hashes[cnt++]);
                addVCodeInput(key, len);
            }
            key[j] = prv;
        }
    }
    delete [] key;

    //----------
    bool result = TestHashList(hashes).drawDiagram(verbose).testDistribution(true).testDeltas(1);
    printf("\n");

    char buf[64];
    snprintf(buf, sizeof(buf), "Long %s %s %d-%d", name, varyprefix ? "first" : "last", minlen, maxlen);
    recordTestResult(result, "Text", buf);

    addVCodeResult(result);

    return result;
}

//-----------------------------------------------------------------------------
// Keyset 'Dict' - hash a list of dictionary words, all-lowercase or all-uppercase

template <typename hashtype>
static bool WordsDictImpl( HashFn hash, const seed_t seed, bool verbose ) {
    std::vector<std::string> words = GetWordlist(CASE_LOWER_UPPER, verbose);
    const size_t wordscount = words.size();

    printf("Keyset 'Dict' - dictionary words - %zd keys\n", wordscount);

    std::vector<hashtype> hashes;
    hashes.resize(wordscount);

    for (size_t i = 0; i < wordscount; i++) {
        const int    len = words[i].length();
        const char * key = words[i].c_str();
        hash(key, len, seed, &hashes[i]);
        addVCodeInput(key, len);
    }

    //----------
    bool result = TestHashList(hashes).drawDiagram(verbose);
    printf("\n");

    recordTestResult(result, "Text", "dictionary");

    addVCodeResult(result);

    return result;
}

//-----------------------------------------------------------------------------

template <typename hashtype>
bool TextKeyTest( const HashInfo * hinfo, const bool verbose ) {
    const HashFn hash  = hinfo->hashFn(g_hashEndian);
    const seed_t seed  = hinfo->Seed(g_seed);
    const char * alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 ";

    printf("[[[ Keyset 'Text' Tests ]]]\n\n");

    bool result = true;

    // Dictionary words
    result &= WordsDictImpl<hashtype>(hash, seed, verbose);

    // Numbers in text form, without and with commas
    result &= TextNumImpl<hashtype, false>(hash, seed, 10000000, verbose);
    result &= TextNumImpl<hashtype,  true>(hash, seed, 10000000, verbose);

    // 6-byte keys, varying only in middle 4 bytes
    result &= TextKeyImpl<hashtype>(hash, seed, "F" , alnum, 4, "B" , verbose);
    result &= TextKeyImpl<hashtype>(hash, seed, "FB", alnum, 4, ""  , verbose);
    result &= TextKeyImpl<hashtype>(hash, seed, ""  , alnum, 4, "FB", verbose);

    // 10-byte keys, varying only in middle 4 bytes
    result &= TextKeyImpl<hashtype>(hash, seed, "Foo"   , alnum, 4, "Bar"   , verbose);
    result &= TextKeyImpl<hashtype>(hash, seed, "FooBar", alnum, 4, ""      , verbose);
    result &= TextKeyImpl<hashtype>(hash, seed, ""      , alnum, 4, "FooBar", verbose);

    // 14-byte keys, varying only in middle 4 bytes
    result &= TextKeyImpl<hashtype>(hash, seed, "Foooo"     , alnum, 4, "Baaar"     , verbose);
    result &= TextKeyImpl<hashtype>(hash, seed, "FooooBaaar", alnum, 4, ""          , verbose);
    result &= TextKeyImpl<hashtype>(hash, seed, ""          , alnum, 4, "FooooBaaar", verbose);

    // 18-byte keys, varying only in middle 4 bytes
    result &= TextKeyImpl<hashtype>(hash, seed, "Foooooo"       , alnum, 4, "Baaaaar"       , verbose);
    result &= TextKeyImpl<hashtype>(hash, seed, "FooooooBaaaaar", alnum, 4, ""              , verbose);
    result &= TextKeyImpl<hashtype>(hash, seed, ""              , alnum, 4, "FooooooBaaaaar", verbose);

    // 22-byte keys, varying only in middle 4 bytes
    result &= TextKeyImpl<hashtype>(hash, seed, "Foooooooo"         , alnum, 4, "Baaaaaaar"         , verbose);
    result &= TextKeyImpl<hashtype>(hash, seed, "FooooooooBaaaaaaar", alnum, 4, ""                  , verbose);
    result &= TextKeyImpl<hashtype>(hash, seed, ""                  , alnum, 4, "FooooooooBaaaaaaar", verbose);

    // 26-byte keys, varying only in middle 4 bytes
    result &= TextKeyImpl<hashtype>(hash, seed, "Foooooooooo"           , alnum, 4, "Baaaaaaaaar"           , verbose);
    result &= TextKeyImpl<hashtype>(hash, seed, "FooooooooooBaaaaaaaaar", alnum, 4, ""                      , verbose);
    result &= TextKeyImpl<hashtype>(hash, seed, ""                      , alnum, 4, "FooooooooooBaaaaaaaaar", verbose);

    // Random sets of 1..4 word-like characters
    result &= WordsKeyImpl<hashtype>(hash, seed, 1000000, 1,  4, alnum, "alnum", verbose);

    // Random sets of 5..8 word-like characters
    result &= WordsKeyImpl<hashtype>(hash, seed, 1000000, 5,  8, alnum, "alnum", verbose);

    // Random sets of 1..16 word-like characters
    result &= WordsKeyImpl<hashtype>(hash, seed, 1000000, 1, 16, alnum, "alnum", verbose);

    // Random sets of 1..32 word-like characters
    result &= WordsKeyImpl<hashtype>(hash, seed, 1000000, 1, 32, alnum, "alnum", verbose);

    // Random sets of many word-like characters, with small changes
    for (auto blksz: { 2048, 4096, 8192 }) {
        result &= WordsLongImpl<hashtype,  true>(hash, seed, 1000, 80, blksz - 80, blksz + 80, alnum, "alnum", verbose);
        result &= WordsLongImpl<hashtype, false>(hash, seed, 1000, 80, blksz - 80, blksz + 80, alnum, "alnum", verbose);
    }

    printf("%s\n", result ? "" : g_failstr);

    return result;
}

INSTANTIATE(TextKeyTest, HASHTYPELIST);
