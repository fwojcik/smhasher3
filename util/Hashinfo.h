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
    FLAG_EXPAND(HASH_CRC_BASED)                        \
    FLAG_EXPAND(HASH_SHA_BASED)                        \
    FLAG_EXPAND(HASH_AES_BASED)                        \
    FLAG_EXPAND(HASH_CLMUL_BASED)                      \
    FLAG_EXPAND(HASH_LOOKUP_TABLE)                     \
    FLAG_EXPAND(HASH_SMALL_SEED)                       \
    FLAG_EXPAND(HASH_NO_SEED)                          \
    FLAG_EXPAND(HASH_SYSTEM_SPECIFIC)                  \
    FLAG_EXPAND(HASH_FLOATING_POINT)

#define IMPL_FLAGS                                     \
    FLAG_EXPAND(IMPL_SANITY_PASSES)                    \
    FLAG_EXPAND(IMPL_SLOW)                             \
    FLAG_EXPAND(IMPL_VERY_SLOW)                        \
    FLAG_EXPAND(IMPL_READ_PAST_EOB)                    \
    FLAG_EXPAND(IMPL_INCREMENTAL)                      \
    FLAG_EXPAND(IMPL_INCREMENTAL_DIFFERENT)            \
    FLAG_EXPAND(IMPL_32BIT)                            \
    FLAG_EXPAND(IMPL_64BIT)                            \
    FLAG_EXPAND(IMPL_128BIT)                           \
    FLAG_EXPAND(IMPL_MULTIPLY_64_64)                   \
    FLAG_EXPAND(IMPL_MULTIPLY_64_128)                  \
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

typedef void      (*HashInitFn)(void);
typedef seed_t    (*HashSeedfixFn)(const HashInfo * hinfo, const seed_t seed);
typedef uintptr_t (*HashSeedFn)(const seed_t seed, const size_t hint);
typedef void      (*HashFn)(const void * in, const size_t len, const seed_t seed, void * out);

unsigned register_hash(const HashInfo * hinfo);
seed_t excludeBadseeds(const HashInfo * hinfo, const seed_t seed);

class HashInfo {
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
        name(n), family(f), desc(""),
        initfn(NULL), seedfixfn(NULL), seedfn(NULL),
        hashfn_native(NULL), hashfn_bswap(NULL)
    { register_hash(this); }

    enum endianness : uint32_t {
        ENDIAN_NATIVE,
        ENDIAN_BYTESWAPPED
    };

    // The hash will be seeded with a value of 0 before this fn returns
    bool VerifyImpl(const HashInfo * hinfo, enum HashInfo::endianness endian,
            bool verbose, bool prefix) const;

    FORCE_INLINE bool Verify(enum HashInfo::endianness endian,
            bool verbose, bool prefix = true) const {
        return VerifyImpl(this, endian, verbose, prefix);
    }

    FORCE_INLINE HashFn hashFn(enum HashInfo::endianness endian) const {
        return (endian == HashInfo::ENDIAN_NATIVE) ?
                hashfn_native : hashfn_bswap;
    }

    FORCE_INLINE void Init(void) const {
        if (initfn != NULL) {
            initfn();
        }
    }

    FORCE_INLINE bool Seed(seed_t seed, uint64_t hint = 0) const {
        if (seedfn != NULL) {
            return !!(seedfn(seed, hint));
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

    FORCE_INLINE bool isSlow(void) const {
        return !!(impl_flags & (FLAG_IMPL_SLOW | FLAG_IMPL_VERY_SLOW));
    }

    FORCE_INLINE bool isVerySlow(void) const {
        return !!(impl_flags & FLAG_IMPL_VERY_SLOW);
    }
};
