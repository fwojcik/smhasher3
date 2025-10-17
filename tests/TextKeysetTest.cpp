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

template <typename hashtype>
static void PrintTextKeyHash( HashFn hash, seed_t seed, const char * key, const uint32_t len ) {
    hashtype v( 0 );

    printf("0x%016" PRIx64 "\t\"%.*s\"\t", g_seed, len, key);
    hash(key, len, seed, &v);
    v.printhex(NULL);
}

//-----------------------------------------------------------------------------
// Keyset 'Num' - generate all keys from 0 through numcount-1 in string form,
// either with or without commas.

template <typename hashtype, bool commas>
static bool TextNumImpl( const HashInfo * hinfo, const seed_t seed, const uint64_t numcount, flags_t flags ) {
    const HashFn          hash = hinfo->hashFn(g_hashEndian);
    std::vector<hashtype> hashes( numcount );
    std::string           nstr;

    if (hinfo->isDoNothing()) {
        std::fill(hashes.begin(), hashes.end(), 0);
    }

    printf("Keyset 'TextNum' - numbers in text form %s commas - %" PRIu64 " keys\n",
            commas ? "with" : "without", numcount);

    //----------
    auto keybuild = [&]( hidx_t n ) {
                nstr = std::to_string(n);
                if (commas) {
                    for (size_t i = nstr.length(); i > 3; i -= 3) {
                        nstr.insert(i - 3, ",");
                    }
                }
            };

    auto keyprint = [&]( hidx_t n ) {
                keybuild(n);
                PrintTextKeyHash<hashtype>(hash, seed, nstr.c_str(), nstr.length());
            };

    //----------
    for (uint64_t n = 0; n < numcount; n++) {
        keybuild(n);
        hash(nstr.c_str(), nstr.length(), seed, &hashes[n]);
        addVCodeInput(nstr.c_str(), nstr.length());
    }

    //----------
    bool result = TestHashList(hashes).reportFlags(flags).dumpFailKeys(keyprint);

    printf("\n");

    recordTestResult(result, "Text", commas ? "numbers with commas" : "numbers without commas");

    addVCodeResult(result);

    return result;
}

//-----------------------------------------------------------------------------
// Keyset 'Text' - generate all keys of the form "prefix"+"core"+"suffix",
// where "core" consists of all possible combinations of the given character
// set of length N.

template <typename hashtype>
static bool TextKeyImpl( const HashInfo * hinfo, const seed_t seed, const char * prefix, const char * coreset,
        const unsigned corelen, const char * suffix, flags_t flags ) {
    const HashFn   hash      = hinfo->hashFn(g_hashEndian);
    const unsigned prefixlen = (unsigned)strlen(prefix);
    const unsigned suffixlen = (unsigned)strlen(suffix);
    const unsigned corecount = (unsigned)strlen(coreset);

    const unsigned keybytes  = prefixlen + corelen + suffixlen;
    unsigned       keycount  = std::min((uint64_t)pow(double(corecount), double(corelen)), (uint64_t)(INT32_MAX / 8));

    std::vector<hashtype> hashes( keycount );

    char * key = new char[keybytes + 1];

    memcpy(key, prefix, prefixlen);
    memset(key + prefixlen, 'X', corelen);
    memcpy(key + prefixlen + corelen, suffix, suffixlen);
    key[keybytes] = 0;
    if (hinfo->isDoNothing()) {
        std::fill(hashes.begin(), hashes.end(), 0);
    }

    printf("Keyset 'Text' - keys of form \"%s\" - %d keys\n", key, keycount);

    //----------
    auto keybuild = [&]( hidx_t n ) {
                for (unsigned j = 0; j < corelen; j++) {
                    key[prefixlen + j] = coreset[n % corecount]; n /= corecount;
                }
            };

    auto keyprint = [&]( hidx_t n ) {
                keybuild(n);
                PrintTextKeyHash<hashtype>(hash, seed, key, keybytes);
            };

    //----------
    for (unsigned i = 0; i < keycount; i++) {
        keybuild(i);
        hash(key, keybytes, seed, &hashes[i]);
        addVCodeInput(key, keybytes);
    }

    //----------
    bool result = TestHashList(hashes).reportFlags(flags).dumpFailKeys(keyprint);

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
static bool WordsKeyImpl( const HashInfo * hinfo, const seed_t seed, const uint32_t keycount, const uint32_t minlen,
        const uint32_t maxlen, const char * coreset, const char * name, flags_t flags ) {
    const HashFn   hash      = hinfo->hashFn(g_hashEndian);
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
            maxkeys *= corecount;
        }
        // printf("Len %2d == %d; remaining = %d\n", len, lencount[len], remaining);
    }
    if (remaining > 0) {
        printf("WARNING: skipping %d keys; maxlen and/or coreset parameters are bad\n", remaining);
    }

    std::vector<hashtype> hashes( keycount - remaining );
    Rand     r( 708218, minlen, maxlen );
    char *   key = new char[maxlen];
    uint32_t cnt = 0;

    if (hinfo->isDoNothing()) {
        std::fill(hashes.begin(), hashes.end(), 0);
    }

    printf("Keyset 'Words' - %d-%d random chars from %s charset - %d keys\n",
            minlen, maxlen, name, keycount - remaining);

    //----------
    auto keybuild = [&]( uint64_t itemnum, uint32_t prefixlen, uint32_t len ) {
                for (unsigned j = 0; j < prefixlen; j++) {
                    key[j] = coreset[itemnum % corecount]; itemnum /= corecount;
                }
                for (unsigned j = prefixlen; j < len; j++) {
                    key[j] = coreset[r.rand_range(corecount)];
                }
            };

    auto keyprint = [&]( hidx_t n ) {
                // Prepare the state to match the n'th key generation
                uint32_t len, rngpos = 0, prefixlen = std::min(minlen, maxprefix);
                uint64_t itemnum;

                for (len = minlen; len <= maxlen; len++) {
                    prefixlen = std::min(len, maxprefix);
                    if (n < lencount[len]) { break; }
                    n        -= lencount[len];
                    rngpos   += lencount[len] * (len - prefixlen) + 1;
                }

                const uint64_t curcount = pow((double)corecount, (double)prefixlen);

                // Regenerate the RandSeq for this key length
                r.seek(rngpos);
                RandSeq rs = r.get_seq(SEQ_NUM, curcount - 1);
                rs.write(&itemnum, n, 1);

                // Seek the RNG for this specific key
                r.seek(rngpos + n * (len - prefixlen) + 1);

                // Build the n'th key, and print it out
                keybuild(itemnum, prefixlen, len);
                PrintTextKeyHash<hashtype>(hash, seed, key, len);
            };

    //----------
    for (uint32_t len = minlen; len <= maxlen; len++) {
        // Generate lencount[len] keys of this length. For the first
        // prefixlen characters, convert a random numeric sequence element
        // into characters from coreset. This prevents duplicate random
        // words from being generated. If there are remaining characters,
        // just pick any random ones from coreset.
        const uint32_t prefixlen = std::min(len, maxprefix);
        const uint64_t curcount  = pow((double)corecount, (double)prefixlen);
        RandSeq        rs        = r.get_seq(SEQ_NUM, curcount - 1);
        uint64_t       itemnum;

        for (uint32_t i = 0; i < lencount[len]; i++) {
            rs.write(&itemnum, i, 1);
            keybuild(itemnum, prefixlen, len);
            hash(key, len, seed, &hashes[cnt++]);
            addVCodeInput(key, len);
            // fprintf(stderr, "%ld\t%d:%ld\t%.*s\n", i, len, nnn, len, key);
        }
    }

    //----------
    bool result = TestHashList(hashes).reportFlags(flags).dumpFailKeys(keyprint);

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
static bool WordsLongImpl( const HashInfo * hinfo, const seed_t seed, const long keycount, const unsigned varylen,
        const unsigned minlen, const unsigned maxlen, const char * coreset, const char * name, flags_t flags ) {
    const HashFn   hash      = hinfo->hashFn(g_hashEndian);
    const unsigned corecount = (unsigned)strlen(coreset);
    const size_t   totalkeys = keycount * (corecount - 1) * varylen;
    char *         key       = new char[maxlen];
    char *         keyorig   = new char[maxlen];
    unsigned       keylen;
    size_t         basepos;

    printf("Keyset 'Long' - %d-%d random chars from %s charset - varying %s %d chars - %zu keys\n",
            minlen, maxlen, name, varyprefix ? "first" : "last", varylen, totalkeys);
    assert(maxlen > minlen);

    Rand r( 312318, varyprefix, minlen, maxlen );
    std::vector<hashtype> hashes( totalkeys );
    hidx_t cnt = 0;

    if (hinfo->isDoNothing()) {
        std::fill(hashes.begin(), hashes.end(), 0);
    }

    //----------
    auto keybuild = [&]( hidx_t basenum ) {
                r.seek(basenum * (maxlen + 1));

                // These words are long enough that we don't explicitly avoid collisions.
                keylen  = minlen + r.rand_range(maxlen - minlen + 1);
                basepos = varyprefix ? 0 : (keylen - varylen);
                for (unsigned j = 0; j < keylen; j++) {
                    key[j] = coreset[r.rand_range(corecount)];
                }
                memcpy(keyorig, key, keylen);
            };

    auto keyrestore = [&]( size_t idx ) {
                key[idx] = keyorig[idx];
            };

    auto keytweak = [&]( size_t idx, unsigned charnum ) {
                // Avoid repeating the base key
                if (keyorig[idx] <= coreset[charnum]) {
                    charnum++;
                }
                key[idx] = coreset[charnum];
            };

    auto keyprint = [&]( hidx_t n ) {
                unsigned charnum = n % (corecount - 1); n /= (corecount - 1);
                size_t   offset  = n % varylen;         n /= varylen;

                keybuild(n);

                size_t idx = basepos + offset;
                keytweak(idx, charnum);

                PrintTextKeyHash<hashtype>(hash, seed, key, keylen);
                printf("  [key[%zd]=\'%c\']", idx, key[idx]);
            };

    //----------
    for (hidx_t i = 0; i < keycount; i++) {
        keybuild(i);

        for (size_t offset = 0; offset < varylen; offset++) {
            size_t idx = basepos + offset;
            for (unsigned charnum = 0; charnum < corecount - 1; charnum++) {
                keytweak(idx, charnum);

                hash(key, keylen, seed, &hashes[cnt++]);
                addVCodeInput(key, keylen);
            }

            keyrestore(idx);
        }
    }

    //----------
    bool result = TestHashList(hashes).reportFlags(flags).testDistribution(true).
            testDeltas(1).dumpFailKeys(keyprint);

    printf("\n");

    char buf[64];
    snprintf(buf, sizeof(buf), "Long %s %s %d-%d", name, varyprefix ? "first" : "last", minlen, maxlen);
    recordTestResult(result, "Text", buf);

    addVCodeResult(result);

    delete [] key;
    delete [] keyorig;

    return result;
}

//-----------------------------------------------------------------------------
// Keyset 'Dict' - hash a list of dictionary words, all-lowercase or all-uppercase

template <typename hashtype>
static bool WordsDictImpl( const HashInfo * hinfo, const seed_t seed, flags_t flags ) {
    const HashFn hash              = hinfo->hashFn(g_hashEndian);
    std::vector<std::string> words = GetWordlist(CASE_LOWER_UPPER, REPORT(VERBOSE, flags));
    const size_t wordscount        = words.size();

    printf("Keyset 'Dict' - dictionary words - %zd keys\n", wordscount);

    std::vector<hashtype> hashes( wordscount );

    if (hinfo->isDoNothing()) {
        std::fill(hashes.begin(), hashes.end(), 0);
    }

    for (size_t i = 0; i < wordscount; i++) {
        const unsigned len = words[i].length();
        const char *   key = words[i].c_str();
        hash(key, len, seed, &hashes[i]);
        addVCodeInput(key, len);
    }

    //----------
    bool result = TestHashList(hashes).reportFlags(flags).dumpFailKeys([&]( hidx_t i ) {
            PrintTextKeyHash<hashtype>(hash, seed, words[i].c_str(), words[i].length());
        });
    printf("\n");

    recordTestResult(result, "Text", "dictionary");

    addVCodeResult(result);

    return result;
}

//-----------------------------------------------------------------------------

static void VerifyCharset( const char * charset, const char * name ) {
    const size_t len = strlen(charset);

    for (unsigned i = 1; i < len; i++) {
        if (charset[i] <= charset[i - 1]) {
            printf("INTERNAL ERROR: coreset \"%s\" is not in order, or has dups!\n", name);
            exit(9);
        }
    }
}

template <typename hashtype>
bool TextKeyTest( const HashInfo * hinfo, flags_t flags ) {
    const seed_t seed  = hinfo->Seed(g_seed);
    const char * alnum = " 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    printf("[[[ Keyset 'Text' Tests ]]]\n\n");

    bool result = true;

    // The values in character sets MUST be in ascending order, with no duplicates
    VerifyCharset(alnum, "alnum");

    // Dictionary words
    result &= WordsDictImpl<hashtype>(hinfo, seed, flags);

    // Numbers in text form, without and with commas
    result &= TextNumImpl<hashtype, false>(hinfo, seed, 10000000, flags);
    result &= TextNumImpl<hashtype,  true>(hinfo, seed, 10000000, flags);

    // 6-byte keys, varying only in middle 4 bytes
    result &= TextKeyImpl<hashtype>(hinfo, seed, "F" , alnum, 4, "B" , flags);
    result &= TextKeyImpl<hashtype>(hinfo, seed, "FB", alnum, 4, ""  , flags);
    result &= TextKeyImpl<hashtype>(hinfo, seed, ""  , alnum, 4, "FB", flags);

    // 10-byte keys, varying only in middle 4 bytes
    result &= TextKeyImpl<hashtype>(hinfo, seed, "Foo"   , alnum, 4, "Bar"   , flags);
    result &= TextKeyImpl<hashtype>(hinfo, seed, "FooBar", alnum, 4, ""      , flags);
    result &= TextKeyImpl<hashtype>(hinfo, seed, ""      , alnum, 4, "FooBar", flags);

    // 14-byte keys, varying only in middle 4 bytes
    result &= TextKeyImpl<hashtype>(hinfo, seed, "Foooo"     , alnum, 4, "Baaar"     , flags);
    result &= TextKeyImpl<hashtype>(hinfo, seed, "FooooBaaar", alnum, 4, ""          , flags);
    result &= TextKeyImpl<hashtype>(hinfo, seed, ""          , alnum, 4, "FooooBaaar", flags);

    // 18-byte keys, varying only in middle 4 bytes
    result &= TextKeyImpl<hashtype>(hinfo, seed, "Foooooo"       , alnum, 4, "Baaaaar"       , flags);
    result &= TextKeyImpl<hashtype>(hinfo, seed, "FooooooBaaaaar", alnum, 4, ""              , flags);
    result &= TextKeyImpl<hashtype>(hinfo, seed, ""              , alnum, 4, "FooooooBaaaaar", flags);

    // 22-byte keys, varying only in middle 4 bytes
    result &= TextKeyImpl<hashtype>(hinfo, seed, "Foooooooo"         , alnum, 4, "Baaaaaaar"         , flags);
    result &= TextKeyImpl<hashtype>(hinfo, seed, "FooooooooBaaaaaaar", alnum, 4, ""                  , flags);
    result &= TextKeyImpl<hashtype>(hinfo, seed, ""                  , alnum, 4, "FooooooooBaaaaaaar", flags);

    // 26-byte keys, varying only in middle 4 bytes
    result &= TextKeyImpl<hashtype>(hinfo, seed, "Foooooooooo"           , alnum, 4, "Baaaaaaaaar"           , flags);
    result &= TextKeyImpl<hashtype>(hinfo, seed, "FooooooooooBaaaaaaaaar", alnum, 4, ""                      , flags);
    result &= TextKeyImpl<hashtype>(hinfo, seed, ""                      , alnum, 4, "FooooooooooBaaaaaaaaar", flags);

    // Random sets of 1..4 word-like characters
    result &= WordsKeyImpl<hashtype>(hinfo, seed, 1000000, 1,  4, alnum, "alnum", flags);

    // Random sets of 5..8 word-like characters
    result &= WordsKeyImpl<hashtype>(hinfo, seed, 1000000, 5,  8, alnum, "alnum", flags);

    // Random sets of 1..16 word-like characters
    result &= WordsKeyImpl<hashtype>(hinfo, seed, 1000000, 1, 16, alnum, "alnum", flags);

    // Random sets of 1..32 word-like characters
    result &= WordsKeyImpl<hashtype>(hinfo, seed, 1000000, 1, 32, alnum, "alnum", flags);

    // Random sets of many word-like characters, with small changes
    for (auto blksz: { 2048, 4096, 8192 }) {
        result &= WordsLongImpl<hashtype,  true>(hinfo, seed, 1000, 80, blksz - 80, blksz + 80, alnum, "alnum", flags);
        result &= WordsLongImpl<hashtype, false>(hinfo, seed, 1000, 80, blksz - 80, blksz + 80, alnum, "alnum", flags);
    }

    printf("%s\n", result ? "" : g_failstr);

    return result;
}

INSTANTIATE(TextKeyTest, HASHTYPELIST);
