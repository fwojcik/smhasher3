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
#include "Hashinfo.h"

#include <vector>

// Interface for hash implementations
unsigned register_hash( const HashInfo * hinfo );

// Interface for consumer for getting hashes
const HashInfo * findHash( const char * name );
std::vector<const HashInfo *> findAllHashes( void );
void listHashes( bool nameonly );

// Interface for ensuring hash is giving expected results
bool verifyAllHashes( bool verbose );
bool verifyHash( const HashInfo * hinfo, enum HashInfo::endianness endian, bool verbose, bool prefix );

//-----------------------------------------------------------------------------

#define CONCAT_INNER(x, y) x ## y
#define CONCAT(x, y) CONCAT_INNER(x, y)

#define REGISTER_FAMILY(N, ...)                    \
  static_assert(sizeof(#N) > 1,                    \
      "REGISTER_FAMILY() needs a non-empty name"); \
  static HashFamilyInfo THIS_HASH_FAMILY = []{     \
    HashFamilyInfo $(#N);                          \
    __VA_ARGS__;                                   \
    return $;                                      \
  }();                                             \
  unsigned CONCAT(N,_ref)

#define REGISTER_HASH(N, ...)                    \
  static_assert(sizeof(#N) > 1,                  \
      "REGISTER_HASH() needs a non-empty name"); \
  static HashInfo CONCAT(Hash_,N) = []{          \
    HashInfo $(#N, THIS_HASH_FAMILY.name);       \
    __VA_ARGS__;                                 \
    register_hash(&$);                           \
    return $;                                    \
  }()

#define USE_FAMILY(N)               \
    extern unsigned CONCAT(N,_ref); \
    CONCAT(N,_ref) = 1
