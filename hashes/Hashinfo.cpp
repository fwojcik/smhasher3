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
#include "Types.h"
#include "LegacyHashes.h"
#include "Hashlib.h"
#include "VCode.h"

#include <cstdio>

//-----------------------------------------------------------------------------
// This should hopefully be a thorough and uambiguous test of whether a hash
// is correctly implemented on a given platform.

static uint32_t calcVerification(const HashInfo * hinfo, enum HashInfo::endianness end) {
  const HashFn hash = hinfo->hashFn(end);
  const uint32_t hashbits = hinfo->bits;
  const uint32_t hashbytes = hashbits / 8;

  uint8_t * key    = new uint8_t[256];
  uint8_t * hashes = new uint8_t[hashbytes * 256];
  uint8_t * final  = new uint8_t[hashbytes];

  memset(key,0,256);
  memset(hashes,0,hashbytes*256);
  memset(final,0,hashbytes);

  // Hash keys of the form {0}, {0,1}, {0,1,2}... up to N=255, using
  // 256-N as the seed
  for(int i = 0; i < 256; i++) {
    seed_t seed = 256 - i;
    hinfo->Seed(seed, 1);
    key[i] = (uint8_t)i;
    hash(key,i,seed,&hashes[i*hashbytes]);
    addVCodeInput(key, i);
  }

  // Then hash the result array
  hinfo->Seed(0, 1);
  hash(hashes,hashbytes*256,0,final);
  addVCodeOutput(hashes, 256*hashbytes);
  addVCodeOutput(final, hashbytes);

  // The first four bytes of that hash, interpreted as a little-endian
  // integer, is our verification value
  uint32_t verification =
      (final[0] << 0) | (final[1] << 8) | (final[2] << 16) | (final[3] << 24);
  addVCodeResult(verification);

  delete [] final;
  delete [] hashes;
  delete [] key;

  return verification;
}

static bool compareVerification(uint32_t expected, uint32_t actual,
        const char * endstr, const char * name,
        bool verbose, bool prefix) {
    const char * result_str;
    bool result = true;

    if (expected == actual) {
        result_str = (actual != 0) ? "PASS\n" : "INSECURE (should not be 0)\n";
    } else if (expected == 0) {
        result_str = "SKIP (unverifiable)\n";
    } else {
        result_str = "FAIL! (Expected 0x%08x)\n";
        result = false;
    }

    if (verbose) {
        if (prefix) {
            printf("%20s - ", name);
        }
        printf("Verification value %2s 0x%08X ..... ", endstr, actual);
        printf(result_str, expected);
    }

    return result;
}

static const char * endianstr(enum HashInfo::endianness e) {
    switch(e) {
    case HashInfo::ENDIAN_LITTLE     : return "LE"; // "Little endian"
    case HashInfo::ENDIAN_BIG        : return "BE"; // "Big endian"
    case HashInfo::ENDIAN_NATIVE     : return isLE() ? "LE" : "BE";
    case HashInfo::ENDIAN_BYTESWAPPED: return isLE() ? "BE" : "LE";
    case HashInfo::ENDIAN_DEFAULT    : return "CE"; // "Canonical endianness"
    case HashInfo::ENDIAN_NONDEFAULT : return "NE"; // "Non-canonical endianness"
    }
    return NULL; /* unreachable */
}

bool HashInfo::VerifyImpl(const HashInfo * hinfo, enum HashInfo::endianness endian,
        bool verbose, bool prefix) const {
  bool result = true;

  const bool wantLE = isBE() ^ _is_native(endian);
  const uint32_t actual = calcVerification(hinfo, endian);
  const uint32_t expected = wantLE ?
      hinfo->verification_LE : hinfo->verification_BE;

  result &= compareVerification(expected, actual, endianstr(endian),
          hinfo->name, verbose, prefix);

  return result;
}

//-----------------------------------------------------------------------------
// Utility function for hashes to easily specify that any seeds in
// their badseed set should be excluded when their FixupSeed() method
// is called.
seed_t excludeBadseeds(const HashInfo * hinfo, const seed_t seed) {
    seed_t newseed = seed;
    auto endp = hinfo->badseeds.end();
    while (hinfo->badseeds.find(newseed) != endp) {
        newseed++;
    }
    return newseed;
}

// Utility function for hashes to easily specify that the seed value
// should not be 0.
seed_t excludeZeroSeed(const HashInfo * hinfo, const seed_t seed) {
    return (seed == 0) ? 1 : seed;
}

//-----------------------------------------------------------------------------
// This is ugly, but it will be gone soon-ish.
LegacyHashInfo * legacyHash;

void legacyHashFnWrapper(const void * in, const size_t len, const seed_t seed, void * out) {
    return legacyHash->hash(in, len, (uint32_t)seed, out);
}

bool legacyHashInit(void) {
    Hash_init(legacyHash);
    return true;
}

uintptr_t legacyHashSeed(const seed_t seed) {
    bool exists = Hash_Seed_init(legacyHash->hash, seed);
    return exists ? 1 : 0;
}

seed_t legacyHashSeedfix(const seed_t seed) {
    uint32_t seed32 = seed;
    Bad_Seed_init(legacyHash->hash, seed32);
    return (seed_t)seed32;
}

HashInfo * convertLegacyHash(LegacyHashInfo * linfo) {
    HashInfo * hinfo     = new HashInfo(linfo->name, "LEGACY");

    hinfo->desc            = linfo->desc;
    hinfo->bits            = linfo->hashbits;
    hinfo->badseeds        = std::set<seed_t>(linfo->secrets.begin(), linfo->secrets.end());

    hinfo->hash_flags      = FLAG_HASH_LEGACY;
    if (linfo->quality == SKIP) {
        hinfo->hash_flags |= FLAG_HASH_MOCK;
    }
    hinfo->impl_flags      = 0;
    if (hash_is_very_slow(linfo->hash)) {
        hinfo->impl_flags |= FLAG_IMPL_VERY_SLOW;
    } else if (hash_is_slow(linfo->hash)) {
        hinfo->impl_flags |= FLAG_IMPL_SLOW;
    }

    hinfo->initfn          = legacyHashInit;
    hinfo->seedfixfn       = NULL;
    hinfo->seedfn          = legacyHashSeed;

    hinfo->hashfn_native   = legacyHashFnWrapper;
    hinfo->hashfn_bswap    = NULL;
    hinfo->verification_LE = linfo->verification;
    hinfo->verification_BE = 0;
    if (isBE()) {
        std::swap(hinfo->verification_LE, hinfo->verification_BE);
    }

    legacyHash             = linfo;

    return hinfo;
}
