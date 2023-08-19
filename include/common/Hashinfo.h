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
#define HAVE_HASHINFO
#include <cstdlib>
#include <set>

#define HASH_FLAGS                       \
    FLAG_EXPAND(HASH_MOCK)               \
    FLAG_EXPAND(HASH_CRYPTOGRAPHIC)      \
    FLAG_EXPAND(HASH_CRYPTOGRAPHIC_WEAK) \
    FLAG_EXPAND(HASH_CRC_BASED)          \
    FLAG_EXPAND(HASH_AES_BASED)          \
    FLAG_EXPAND(HASH_CLMUL_BASED)        \
    FLAG_EXPAND(HASH_LOOKUP_TABLE)       \
    FLAG_EXPAND(HASH_XL_SEED)            \
    FLAG_EXPAND(HASH_SMALL_SEED)         \
    FLAG_EXPAND(HASH_NO_SEED)            \
    FLAG_EXPAND(HASH_SYSTEM_SPECIFIC)    \
    FLAG_EXPAND(HASH_ENDIAN_INDEPENDENT) \
    FLAG_EXPAND(HASH_FLOATING_POINT)

#define IMPL_FLAGS                          \
    FLAG_EXPAND(IMPL_SANITY_FAILS)          \
    FLAG_EXPAND(IMPL_SLOW)                  \
    FLAG_EXPAND(IMPL_VERY_SLOW)             \
    FLAG_EXPAND(IMPL_READ_PAST_EOB)         \
    FLAG_EXPAND(IMPL_TYPE_PUNNING)          \
    FLAG_EXPAND(IMPL_INCREMENTAL)           \
    FLAG_EXPAND(IMPL_INCREMENTAL_DIFFERENT) \
    FLAG_EXPAND(IMPL_128BIT)                \
    FLAG_EXPAND(IMPL_MULTIPLY)              \
    FLAG_EXPAND(IMPL_MULTIPLY_64_64)        \
    FLAG_EXPAND(IMPL_MULTIPLY_64_128)       \
    FLAG_EXPAND(IMPL_MULTIPLY_128_128)      \
    FLAG_EXPAND(IMPL_ROTATE)                \
    FLAG_EXPAND(IMPL_ROTATE_VARIABLE)       \
    FLAG_EXPAND(IMPL_SHIFT_VARIABLE)        \
    FLAG_EXPAND(IMPL_MODULUS)               \
    FLAG_EXPAND(IMPL_ASM)                   \
    FLAG_EXPAND(IMPL_CANONICAL_LE)          \
    FLAG_EXPAND(IMPL_CANONICAL_BE)          \
    FLAG_EXPAND(IMPL_CANONICAL_BOTH)        \
    FLAG_EXPAND(IMPL_SEED_WITH_HINT)        \
    FLAG_EXPAND(IMPL_LICENSE_PUBLIC_DOMAIN) \
    FLAG_EXPAND(IMPL_LICENSE_BSD)           \
    FLAG_EXPAND(IMPL_LICENSE_MIT)           \
    FLAG_EXPAND(IMPL_LICENSE_APACHE2)       \
    FLAG_EXPAND(IMPL_LICENSE_ZLIB)          \
    FLAG_EXPAND(IMPL_LICENSE_GPL3)

#define FLAG_EXPAND(name) FLAG_ENUM_ ## name,
typedef enum {
    HASH_FLAGS
} hashflag_enum_t;
typedef enum {
    IMPL_FLAGS
} implflag_enum_t;
#undef FLAG_EXPAND

#define FLAG_EXPAND(name) FLAG_ ## name = (1ULL << FLAG_ENUM_ ## name),
typedef enum : uint64_t {
    HASH_FLAGS
} HashFlags;
typedef enum : uint64_t {
    IMPL_FLAGS
} ImplFlags;
#undef FLAG_EXPAND

//-----------------------------------------------------------------------------
class HashInfo;

typedef bool       (* HashInitFn)( void );
typedef seed_t     (* HashSeedfixFn)( const HashInfo * hinfo, const seed_t seed );
typedef uintptr_t  (* HashSeedFn)( const seed_t seed );
typedef void       (* HashFn)( const void * in, const size_t len, const seed_t seed, void * out );

seed_t excludeBadseeds( const HashInfo * hinfo, const seed_t seed );

class HashInfo {
    friend class HashFamilyInfo;

  public:
    enum endianness : uint32_t {
        ENDIAN_DEFAULT,
        ENDIAN_NONDEFAULT,
        ENDIAN_NATIVE,
        ENDIAN_BYTESWAPPED,
        ENDIAN_LITTLE,
        ENDIAN_BIG
    };

    enum fixupseed : size_t {
        SEED_ALLOWFIX = 0,  // Seed via a SeedfixFn, if the hash has one
        SEED_FORCED   = 1   // Seed using the given seed, always
    };

  protected:
    static const char * _fixup_name( const char * in );

  private:
    uint32_t _ComputedVerifyImpl( const HashInfo * hinfo, enum HashInfo::endianness endian ) const;

    bool _is_native( enum endianness e ) const {
        bool is_native = true;

        switch (e) {
        case ENDIAN_NATIVE     : is_native = true; break;
        case ENDIAN_BYTESWAPPED: is_native = false; break;
        case ENDIAN_LITTLE     : is_native = isLE(); break;
        case ENDIAN_BIG        : is_native = isBE(); break;
        case ENDIAN_DEFAULT    : /* fallthrough */
        case ENDIAN_NONDEFAULT : {
            // Compute is_native for the DEFAULT case
            if (hash_flags & FLAG_HASH_ENDIAN_INDEPENDENT) {
                if (impl_flags & FLAG_IMPL_CANONICAL_BOTH) {
                    is_native = true;
                } else if (impl_flags & FLAG_IMPL_CANONICAL_LE) {
                    is_native = isLE();
                } else if (impl_flags & FLAG_IMPL_CANONICAL_BE) {
                    is_native = isBE();
                }
            } else {
                is_native = true;
            }
            // Invert it for the NONDEFAULT case
            if (e == ENDIAN_NONDEFAULT) { is_native = !is_native; }
            break;
        }
        }
        return is_native;
    }

  public:
    const char *      name;
    const char *      family;
    const char *      desc;
    const char *      impl;
    uint64_t          hash_flags;
    uint64_t          impl_flags;
    uint32_t          sort_order;
    uint32_t          bits;
    uint32_t          verification_LE;
    uint32_t          verification_BE;
    HashInitFn        initfn;
    HashSeedfixFn     seedfixfn;
    HashSeedFn        seedfn;
    HashFn            hashfn_native;
    HashFn            hashfn_bswap;
    std::set<seed_t>  badseeds;
    const char *      badseeddesc;

    HashInfo( const char * n, const char * f ) :
        name( _fixup_name( n ) ), family( f ), desc( "" ), impl( "" ),
        initfn( NULL ), seedfixfn( NULL ), seedfn( NULL ),
        hashfn_native( NULL ), hashfn_bswap( NULL ), badseeddesc( NULL ) {}

    ~HashInfo() {
        free((char *)name);
    }

    // The hash will be seeded with a value of 0 before this fn returns
    uint32_t ComputedVerify( enum HashInfo::endianness endian ) const {
        return _ComputedVerifyImpl(this, endian);
    }

    uint32_t ExpectedVerify( enum HashInfo::endianness endian ) const {
        const bool wantLE = isBE() ^ _is_native(endian);

        return wantLE ? this->verification_LE : this->verification_BE;
    }

    FORCE_INLINE HashFn hashFn( enum HashInfo::endianness endian ) const {
        return _is_native(endian) ? hashfn_native : hashfn_bswap;
    }

    FORCE_INLINE bool Init( void ) const {
        if (initfn != NULL) {
            return initfn();
        }
        return true;
    }

    FORCE_INLINE seed_t Seed( seed_t seed, enum fixupseed fixup = SEED_ALLOWFIX, uint64_t hint = 0 ) const {
        if (unlikely(seedfixfn != NULL)) {
            if (unlikely(impl_flags & FLAG_IMPL_SEED_WITH_HINT)) {
                seedfixfn(NULL, hint);
            } else if (fixup == SEED_ALLOWFIX) {
                seed = seedfixfn(this, seed);
            }
        }
        if (unlikely(seedfn != NULL)) {
            seed_t newseed = (seed_t)seedfn(seed);
            if (newseed != 0) {
                seed = newseed;
            }
        }
        return seed;
    }

    FORCE_INLINE seed_t getFixedSeed( seed_t seed ) const {
        if (unlikely(seedfixfn != NULL)) {
            seed = (seed_t)seedfixfn(this, seed);
        }
        return seed;
    }

    FORCE_INLINE bool isMock( void ) const {
        return !!(hash_flags & FLAG_HASH_MOCK);
    }

    FORCE_INLINE bool is32BitSeed( void ) const {
        return !!(hash_flags & FLAG_HASH_SMALL_SEED);
    }

    FORCE_INLINE bool isEndianDefined( void ) const {
        return !!(hash_flags & FLAG_HASH_ENDIAN_INDEPENDENT);
    }

    FORCE_INLINE bool isCrypto( void ) const {
        return !!(hash_flags & FLAG_HASH_CRYPTOGRAPHIC);
    }

    FORCE_INLINE bool isSlow( void ) const {
        return !!(impl_flags & (FLAG_IMPL_SLOW | FLAG_IMPL_VERY_SLOW));
    }

    FORCE_INLINE bool isVerySlow( void ) const {
        return !!(impl_flags & FLAG_IMPL_VERY_SLOW);
    }
}; // class HashInfo

class HashFamilyInfo {
  public:
    const char * name;
    const char * src_url;
    enum SrcStatus : uint32_t {
        SRC_UNKNOWN,
        SRC_FROZEN,    // Very unlikely to change
        SRC_STABLEISH, // Fairly unlikely to change
        SRC_ACTIVE,    // Likely to change
    }  src_status;

    HashFamilyInfo( const char * n ) :
        name( _fixup_name( n )),
        src_url( NULL ), src_status( SRC_UNKNOWN ) {}

  private:
    static const char * _fixup_name( const char * in );
}; // class HashFamilyInfo
