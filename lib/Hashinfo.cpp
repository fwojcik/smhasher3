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
#include "Hashlib.h"
#include "VCode.h"

#include <cstdio>
#include <string>
#include <algorithm>

const char * HashInfo::_fixup_name( const char * in ) {
    // Since dashes can't be in C/C++ identifiers, but humans want
    // them in names, replace underscores with dashes. Similarly,
    // replace double underscores with dots.
    std::string out( in );

    do {
        size_t p = out.find("__");
        if (p == std::string::npos) { break; }
        out.replace(p, 2, ".");
    } while (true);
    std::replace(&out[0], &out[out.length()], '_', '-');
    return strdup(out.c_str());
}

const char * HashFamilyInfo::_fixup_name( const char * in ) {
    return HashInfo::_fixup_name(in);
}

//-----------------------------------------------------------------------------
// This should hopefully be a thorough and uambiguous test of whether a hash
// is correctly implemented on a given platform.

uint32_t HashInfo::_ComputedVerifyImpl( const HashInfo * hinfo, enum HashInfo::endianness endian ) const {
    const HashFn   hash      = hinfo->hashFn(endian);
    const uint32_t hashbits  = hinfo->bits;
    const uint32_t hashbytes = hashbits / 8;

    uint8_t * key    = new uint8_t[            256];
    uint8_t * hashes = new uint8_t[hashbytes * 256];
    uint8_t * total  = new uint8_t[hashbytes      ];

    memset(key   , 0,             256);
    memset(hashes, 0, hashbytes * 256);
    memset(total , 0,       hashbytes);

    // Hash keys of the form {}, {0}, {0,1}, {0,1,2}... up to N=255, using
    // 256-N as the seed
    for (int i = 0; i < 256; i++) {
        seed_t seed = 256 - i;
        seed = hinfo->Seed(seed, SEED_FORCED, 1);
        hash(key, i, seed, &hashes[i * hashbytes]);
        addVCodeInput(key, i);
        key[i] = (uint8_t)i;
    }

    // Then hash the result array
    seed_t seed = 0;
    seed = hinfo->Seed(0, SEED_FORCED, 1);
    hash(hashes, hashbytes * 256, seed, total);
    addVCodeOutput(hashes, 256 * hashbytes);
    addVCodeOutput(total , hashbytes);

    // The first four bytes of that hash, interpreted as a little-endian
    // integer, is our verification value
    uint32_t verification = (total[0] << 0) | (total[1] << 8) |
            (total[2] << 16) | (total[3] << 24);
    addVCodeResult(verification);

    delete [] total;
    delete [] hashes;
    delete [] key;

    return verification;
}

//-----------------------------------------------------------------------------
// Utility function for hashes to easily specify that any seeds in
// their badseed set should be excluded when their FixupSeed() method
// is called.
seed_t excludeBadseeds( const HashInfo * hinfo, const seed_t seed ) {
    seed_t newseed = seed;
    auto   endp    = hinfo->badseeds.end();

    while (hinfo->badseeds.find(newseed) != endp) {
        newseed++;
    }
    return newseed;
}
