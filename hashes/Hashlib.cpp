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
#include <string>
#include <unordered_map>

//-----------------------------------------------------------------------------
// These are here only so that the linker will consider all the
// translation units as "referred to", so it won't ignore them during
// link time, so that all the global static initializers across all
// the hash functions will actually fire. :-{

unsigned refs();
static unsigned dummy = refs();

//-----------------------------------------------------------------------------
typedef std::unordered_map<std::string, const HashInfo *> HashMap;
typedef std::vector<const HashInfo *> HashMapOrder;

HashMap& hashMap() {
  static HashMap * map = new HashMap;
  return *map;
}

HashMapOrder defaultSort(HashMap & map) {
    HashMapOrder hashes;
    hashes.reserve(map.size());
    for (auto kv : map) {
        hashes.push_back(kv.second);
    }
    std::sort(hashes.begin(), hashes.end(),
            [](const HashInfo * a, const HashInfo * b) {
                int r;
                if (a->isMock() != b->isMock())               return a->isMock();
                if ((r = strcmp(a->family, b->family)) != 0)  return (r < 0);
                if (a->bits != b->bits)                       return (a->bits < b->bits);
                if ((r = strcmp(a->name, b->name)) != 0)      return (r < 0);
                return false;
            });
    return hashes;
}

unsigned register_hash(const HashInfo * hinfo) {
  if (strcmp(hinfo->family, "LEGACY") == 0) return 0;
  std::string name = hinfo->name;
  std::transform(name.begin(), name.end(), name.begin(), ::tolower);
  if (hashMap().find(name) != hashMap().end()) {
    printf("Hash names must be unique; \"%s\" was added multiple times.\n", hinfo->name);
    printf("Note that hash names are using a case-insensitive comparison.\n");
    exit(1);
  }
  hashMap()[name] = hinfo;
  return hashMap().size();
}

const HashInfo * findHash(const char * name) {
  std::string n = name;
  const auto it = hashMap().find(n);
  if (it == hashMap().end()) {
    return NULL;
  }
  return it->second;
}

void listHashes(bool nameonly) {
    if (!nameonly) {
        printf("%-20s %4s %-50s %4s\n",
            "Name", "Bits", "Description", "Type");
        printf("%-20s %4s %-50s %4s\n",
            "----", "----", "-----------", "----");
    }
    for (const HashInfo * h : defaultSort(hashMap())) {
        if (!nameonly) {
            printf("%-20s %4d %-50s %4s\n",
                h->name, h->bits, h->desc,
                (h->hash_flags & FLAG_HASH_MOCK) ? "MOCK" : "");
        } else {
            printf("%s\n", h->name);
        }
    }
    printf("\n");
}

bool verifyAllHashes(bool verbose) {
    bool result = true;
    for (const HashInfo * h : defaultSort(hashMap())) {
        if (isLE()) {
            result &= h->Verify(HashInfo::ENDIAN_NATIVE, verbose);
        }
        result &= h->Verify(HashInfo::ENDIAN_BYTESWAPPED, verbose);
        if (!isLE()) {
            result &= h->Verify(HashInfo::ENDIAN_NATIVE, verbose);
        }
    }
    printf("\n");
    return result;
}

//-----------------------------------------------------------------------------
// This should hopefully be a thorough and uambiguous test of whether a hash
// is correctly implemented on a given platform.

static uint32_t calcVerification(const HashInfo * hinfo, enum HashInfo::endianness bswap) {
  const HashFn hash = hinfo->hashFn(bswap);
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
    hinfo->Seed(seed);
    key[i] = (uint8_t)i;
    hash(key,i,seed,&hashes[i*hashbytes]);
    addVCodeInput(key, i);
  }

  // Then hash the result array
  hinfo->Seed(0);
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
         const char * endstr, const char * name, bool verbose) {
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
        printf("%20s - Verification value %2s 0x%08X ........ ", name, endstr, actual);
        printf(result_str, expected);
    }

    return result;
}

// This function MUST seed the hash with a value of 0 before returning.
bool HashInfo::VerifyImpl(const HashInfo * hinfo, enum HashInfo::endianness endian,
        bool verbose) const {
  bool result = true;

  const bool wantLE = isLE() ^ (endian == HashInfo::ENDIAN_BYTESWAPPED);
  const uint32_t actual = calcVerification(hinfo, endian);
  const uint32_t expected = wantLE ?
      hinfo->verification_LE : hinfo->verification_BE;

  result &= compareVerification(expected, actual, wantLE ? "LE" : "BE",
          hinfo->name, verbose);

  return result;
}

//-----------------------------------------------------------------------------
// This is ugly, but it will be gone soon-ish.
LegacyHashInfo * legacyHash;

void legacyHashFnWrapper(const void * in, const size_t len, const seed_t seed, void * out) {
    return legacyHash->hash(in, len, (uint32_t)seed, out);
}

void legacyHashInit(void) {
    Hash_init(legacyHash);
}

uintptr_t legacyHashSeed(const seed_t seed, const size_t hint) {
    bool exists = Hash_Seed_init(legacyHash->hash, seed, hint);
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
    hinfo->badseeds        = linfo->secrets;

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
