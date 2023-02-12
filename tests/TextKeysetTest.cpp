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

#include <unordered_set>
#include <string>
#include <math.h>

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
static bool WordsKeyImpl( HashFn hash, const seed_t seed, const long keycount, const int minlen,
        const int maxlen, const char * coreset, const char * name, bool verbose ) {
    const int corecount = (int)strlen(coreset);

    printf("Keyset 'Words' - %d-%d random chars from %s charset - %ld keys\n", minlen, maxlen, name, keycount);
    assert(minlen >= 0    );
    assert(maxlen > minlen);

    std::unordered_set<std::string> words; // need to be unique, otherwise we report collisions
    std::vector<hashtype>           hashes;
    hashes.resize(keycount);
    Rand r( 483723 + 2944 * minlen + maxlen );

    char *      key = new char[std::min(maxlen + 1, 64)];
    std::string key_str;

    for (long i = 0; i < keycount; i++) {
        const int len = minlen + r.rand_range(maxlen - minlen + 1);
        key[len] = 0;
        for (int j = 0; j < len; j++) {
            key[j] = coreset[r.rand_range(corecount)];
        }
        key_str = key;
        if (words.count(key_str) > 0) { // not unique
            i--;
            continue;
        }
        words.insert(key_str);

        hash(key, len, seed, &hashes[i]);
        addVCodeInput(key, len);

#if 0 && defined DEBUG
        uint64_t h;
        memcpy(&h, &hashes[i], std::max(sizeof(hashtype), 8));
        printf("%d %s %lx\n", i, (char *)key, h);
#endif
    }
    delete [] key;

    //----------
    bool result = TestHashList(hashes).drawDiagram(verbose);
    printf("\n");

    char buf[32];
    snprintf(buf, sizeof(buf), "Words %s %d-%d", name, minlen, maxlen);
    recordTestResult(result, "Text", buf);

    addVCodeResult(result);

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
    Rand r( 425379 + 94 * varyprefix + 604 * minlen + maxlen );
    size_t cnt = 0;

    for (long i = 0; i < keycount; i++) {
        const int len = minlen + r.rand_range(maxlen - minlen + 1);
        key[len] = 0;
        for (int j = 0; j < len; j++) {
            key[j] = coreset[r.rand_range(corecount)];
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

    char buf[32];
    snprintf(buf, sizeof(buf), "Long %s %s %d-%d", name, varyprefix ? "first" : "last", minlen, maxlen);
    recordTestResult(result, "Text", buf);

    addVCodeResult(result);

    return result;
}

//-----------------------------------------------------------------------------
// Keyset 'Dict' - hash a list of dictionary words, all-lowercase or all-uppercase

template <typename hashtype>
static bool WordsDictImpl( HashFn hash, const seed_t seed, bool verbose ) {
    std::vector<std::string> words = GetWordlist(false, verbose);
    long wordscount = words.size();

    printf("Keyset 'Dict' - dictionary words - %ld keys\n", wordscount);

    std::unordered_set<std::string> wordset; // need to be unique, otherwise we report collisions
    std::vector<hashtype>           hashes;
    hashes.resize(wordscount);

    for (int i = 0; i < (int)wordscount; i++) {
        if (wordset.count(words[i]) > 0) { // not unique
            continue;
        }
        wordset.insert(words[i]);
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
