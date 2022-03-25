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
#define HASH_FLAGS                                     \
    FLAG_EXPAND(HASH_LEGACY)                           \
    FLAG_EXPAND(HASH_MOCK)                             \
    FLAG_EXPAND(HASH_CRYPTOGRAPHIC)                    \
    FLAG_EXPAND(HASH_CRYPTOGRAPHIC_WEAK)               \
    FLAG_EXPAND(HASH_CRC_BASED)                        \
    FLAG_EXPAND(HASH_SHA_BASED)                        \
    FLAG_EXPAND(HASH_AES_BASED)                        \
    FLAG_EXPAND(HASH_CLMUL_BASED)                      \
    FLAG_EXPAND(HASH_LOOKUP_TABLE)                     \
    FLAG_EXPAND(HASH_SMALL_SEED)                       \
    FLAG_EXPAND(HASH_NO_SEED)                          \
    FLAG_EXPAND(HASH_SYSTEM_SPECIFIC)                  \
    FLAG_EXPAND(HASH_ENDIAN_INDEPENDENT)               \
    FLAG_EXPAND(HASH_FLOATING_POINT)

#define IMPL_FLAGS                                     \
    FLAG_EXPAND(IMPL_SANITY_FAILS)                     \
    FLAG_EXPAND(IMPL_SLOW)                             \
    FLAG_EXPAND(IMPL_VERY_SLOW)                        \
    FLAG_EXPAND(IMPL_READ_PAST_EOB)                    \
    FLAG_EXPAND(IMPL_READ_UNALIGNED)                   \
    FLAG_EXPAND(IMPL_INCREMENTAL)                      \
    FLAG_EXPAND(IMPL_INCREMENTAL_DIFFERENT)            \
    FLAG_EXPAND(IMPL_64BIT)                            \
    FLAG_EXPAND(IMPL_128BIT)                           \
    FLAG_EXPAND(IMPL_MULTIPLY)                         \
    FLAG_EXPAND(IMPL_MULTIPLY_64_64)                   \
    FLAG_EXPAND(IMPL_MULTIPLY_64_128)                  \
    FLAG_EXPAND(IMPL_MULTIPLY_128_128)                 \
    FLAG_EXPAND(IMPL_ROTATE)                           \
    FLAG_EXPAND(IMPL_DIVISION)                         \
    FLAG_EXPAND(IMPL_MODULUS)                          \
    FLAG_EXPAND(IMPL_ASM)                              \
    FLAG_EXPAND(IMPL_SSE2)                             \
    FLAG_EXPAND(IMPL_SSE2_REQUIRED)                    \
    FLAG_EXPAND(IMPL_SSE42)                            \
    FLAG_EXPAND(IMPL_SSE42_REQUIRED)                   \
    FLAG_EXPAND(IMPL_AVX)                              \
    FLAG_EXPAND(IMPL_AVX_REQUIRED)                     \
    FLAG_EXPAND(IMPL_AVX2)                             \
    FLAG_EXPAND(IMPL_AVX2_REQUIRED)                    \
    FLAG_EXPAND(IMPL_NEON)                             \
    FLAG_EXPAND(IMPL_THUMB)                            \
    FLAG_EXPAND(IMPL_CANONICAL_LE)                     \
    FLAG_EXPAND(IMPL_CANONICAL_BE)                     \
    FLAG_EXPAND(IMPL_SEED_WITH_HINT)                   \
    FLAG_EXPAND(IMPL_LICENSE_PUBLIC_DOMAIN)            \
    FLAG_EXPAND(IMPL_LICENSE_BSD)                      \
    FLAG_EXPAND(IMPL_LICENSE_MIT)                      \
    FLAG_EXPAND(IMPL_LICENSE_APACHE)                   \
    FLAG_EXPAND(IMPL_LICENSE_ZLIB)                     \
    FLAG_EXPAND(IMPL_LICENSE_GPL3)

#define FLAG_EXPAND(name) FLAG_ENUM_##name,
typedef enum {
    HASH_FLAGS
} hashflag_enum_t;
typedef enum {
    IMPL_FLAGS
} implflag_enum_t;
#undef FLAG_EXPAND

#define FLAG_EXPAND(name) FLAG_##name=(1ULL << FLAG_ENUM_##name),
typedef enum : uint64_t {
    HASH_FLAGS
} HashFlags;
typedef enum : uint64_t {
    IMPL_FLAGS
} ImplFlags;
#undef FLAG_EXPAND

//-----------------------------------------------------------------------------
// seed_t must be large enough to be able to hold a 64-bit integer
// value OR an integer representation of a pointer.
typedef std::conditional<sizeof(uintptr_t) <= sizeof(uint64_t),
  uint64_t, uintptr_t>::type seed_t;

class HashInfo;

typedef bool      (*HashInitFn)(void);
typedef seed_t    (*HashSeedfixFn)(const HashInfo * hinfo, const seed_t seed);
typedef uintptr_t (*HashSeedFn)(const seed_t seed);
typedef void      (*HashFn)(const void * in, const size_t len, const seed_t seed, void * out);

unsigned register_hash(const HashInfo * hinfo);
seed_t excludeBadseeds(const HashInfo * hinfo, const seed_t seed);
seed_t excludeZeroSeed(const HashInfo * hinfo, const seed_t seed);

class HashInfo {
  public:
    enum endianness : uint32_t {
        ENDIAN_DEFAULT,
        ENDIAN_NONDEFAULT,
        ENDIAN_NATIVE,
        ENDIAN_BYTESWAPPED,
        ENDIAN_LITTLE,
        ENDIAN_BIG
    };

  private:
    char * _fixup_name(const char * in) {
        // Since dashes can't be in C/C++ identifiers, but humans want them
        // in names, replace underscores with dashes.
        char * out = strdup(in);
        std::replace(&out[0], &out[strlen(out)], '_', '-');
        return out;
    }

    bool _is_native(enum endianness e) const {
        bool is_native = true;
        switch(e) {
        case ENDIAN_NATIVE     : is_native = true; break;
        case ENDIAN_BYTESWAPPED: is_native = false; break;
        case ENDIAN_LITTLE     : is_native = isLE(); break;
        case ENDIAN_BIG        : is_native = isBE(); break;
        case ENDIAN_DEFAULT    : /* fallthrough */
        case ENDIAN_NONDEFAULT :
            // Compute is_native for the DEFAULT case
            if (hash_flags & FLAG_HASH_ENDIAN_INDEPENDENT) {
                if (impl_flags & FLAG_IMPL_CANONICAL_LE) {
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
        return is_native;
    }

  public:
    const char * family;
    const char * name;
    const char * desc;
    uint64_t hash_flags;
    uint64_t impl_flags;
    uint32_t sort_order;
    uint32_t bits;
    uint32_t verification_LE;
    uint32_t verification_BE;
    HashInitFn initfn;
    HashSeedfixFn seedfixfn;
    HashSeedFn seedfn;
    HashFn hashfn_native;
    HashFn hashfn_bswap;
    std::set<seed_t> badseeds;

    HashInfo(const char * n, const char * f) :
        name(_fixup_name(n)), family(f), desc(""),
        initfn(NULL), seedfixfn(NULL), seedfn(NULL),
        hashfn_native(NULL), hashfn_bswap(NULL)
    { register_hash(this); }

    ~HashInfo() {
        free((char *)name);
    }

    // The hash will be seeded with a value of 0 before this fn returns
    bool VerifyImpl(const HashInfo * hinfo, enum HashInfo::endianness endian,
            bool verbose, bool prefix) const;

    FORCE_INLINE bool Verify(enum HashInfo::endianness endian,
            bool verbose, bool prefix = true) const {
        return VerifyImpl(this, endian, verbose, prefix);
    }

    FORCE_INLINE HashFn hashFn(enum HashInfo::endianness endian) const {
        return _is_native(endian) ? hashfn_native : hashfn_bswap;
    }

    FORCE_INLINE bool Init(void) const {
        if (initfn != NULL) {
            return initfn();
        }
        return true;
    }

    // Returns true if seeding was done
    FORCE_INLINE bool Seed(seed_t seed, uint64_t hint = 0) const {
        if (impl_flags & FLAG_IMPL_SEED_WITH_HINT) {
            return !!(seedfn(hint));
        } else if (seedfn != NULL) {
            return !!(seedfn(seed));
        } else if (isLegacy()) {
            return false;
        }
        return true;
    }

    FORCE_INLINE void FixupSeed(seed_t & seed) const {
        if (seedfixfn != NULL) {
            seed = seedfixfn(this, seed);
        }
    }

    FORCE_INLINE bool isMock(void) const {
        return !!(hash_flags & FLAG_HASH_MOCK);
    }

    FORCE_INLINE bool isLegacy(void) const {
        return !!(hash_flags & FLAG_HASH_LEGACY);
    }

    FORCE_INLINE bool is32BitSeed(void) const {
        return !!(hash_flags & FLAG_HASH_SMALL_SEED);
    }

    FORCE_INLINE bool isEndianDefined(void) const {
        return !!(hash_flags & FLAG_HASH_ENDIAN_INDEPENDENT);
    }

    FORCE_INLINE bool isCrypto(void) const {
        return !!(hash_flags & FLAG_HASH_CRYPTOGRAPHIC);
    }

    FORCE_INLINE bool isSlow(void) const {
        return !!(impl_flags & (FLAG_IMPL_SLOW | FLAG_IMPL_VERY_SLOW));
    }

    FORCE_INLINE bool isVerySlow(void) const {
        return !!(impl_flags & FLAG_IMPL_VERY_SLOW);
    }
};
