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


// The sort_order field is intended to be used for people adding
// hashes which should appear inside their family in
// other-than-alphabetical order.
//
// This is overloaded for mock hashes to also override the sorting for
// _family name_, which is not something general users should do.
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
                if (a->isMock() && (a->sort_order != b->sort_order))
                                                              return (a->sort_order < b->sort_order);
                if ((r = strcmp(a->family, b->family)) != 0)  return (r < 0);
                if (a->bits != b->bits)                       return (a->bits < b->bits);
                if (a->sort_order != b->sort_order)           return (a->sort_order < b->sort_order);
                if ((r = strcmp(a->name, b->name)) != 0)      return (r < 0);
                return false;
            });
    return hashes;
}

// FIXME Verify hinfo is all filled out.
unsigned register_hash(const HashInfo * hinfo) {
  if (strcmp(hinfo->family, "LEGACY") == 0) return 0;
  std::string name = hinfo->name;
  std::transform(name.begin(), name.end(), name.begin(), ::tolower);
  std::replace(name.begin(), name.end(), '_', '-');
  name.resize(std::min((int)name.length(), 20));

  if (hashMap().find(name) != hashMap().end()) {
    printf("Hash names must be unique.\n");
    printf("\"%s\" (\"%s\") was added multiple times.\n", hinfo->name, name);
    printf("Note that hash names are using a case-insensitive comparison.\n");
    exit(1);
  }
  hashMap()[name] = hinfo;
  return hashMap().size();
}

const HashInfo * findHash(const char * name) {
  std::string n = name;
  std::transform(n.begin(), n.end(), n.begin(), ::tolower);
  n.resize(std::min((int)n.length(), 20));

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
    // Always verify little-endian first, and always verify NATIVE
    // regardless of isBE() and isLE() results.
    for (const HashInfo * h : defaultSort(hashMap())) {
        if (isBE()) {
            result &= h->Verify(HashInfo::ENDIAN_BYTESWAPPED, verbose);
        }
        result &= h->Verify(HashInfo::ENDIAN_NATIVE, verbose);
        if (isLE()) {
            result &= h->Verify(HashInfo::ENDIAN_BYTESWAPPED, verbose);
        }
    }
    printf("\n");
    return result;
}
