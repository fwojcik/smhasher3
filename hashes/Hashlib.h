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
const HashInfo * findHash(const char * name);
void listHashes(bool nameonly);
bool verifyAllHashes(bool verbose);

HashInfo * convertLegacyHash(LegacyHashInfo * linfo);

#define CONCAT_INNER(x, y) x##y
#define CONCAT(x,y) CONCAT_INNER(x, y)

#define REGISTER_FAMILY(N)                                  \
    static const char * THIS_HASH_FAMILY = #N;              \
    unsigned CONCAT(N,_ref)

#define REGISTER_HASH(N, ...)                               \
    static HashInfo CONCAT(Details,N) = []{                 \
        HashInfo $(#N, THIS_HASH_FAMILY);                   \
        __VA_ARGS__;                                        \
        return $;                                           \
    }();

#define USE_FAMILY(N)                                       \
    extern unsigned CONCAT(N,_ref);                         \
    CONCAT(N,_ref) = 1

// FIXME Make this code properly portable
template < typename T >
static FORCE_INLINE T BSWAP(T value) {
    switch(sizeof(T)) {
    case 2:  value = __builtin_bswap16((uint16_t)value); break;
    case 4:  value = __builtin_bswap32((uint32_t)value); break;
    case 8:  value = __builtin_bswap64((uint64_t)value); break;
#if 0
#ifdef HAVE_INT128
    case 16: value = __builtin_bswap128((uint128_t)value); break;
#endif
#endif
    default: break;
    }
    return value;
}

template < typename T >
static FORCE_INLINE T COND_BSWAP(T value, bool doit) {
    if (!doit || (sizeof(T) < 2)) { return value; }
    return BSWAP(value);
}

//-----------------------------------------------------------------------------
// 32-bit integer manipulation functions. These move data in
// alignment-safe ways, with optional byte swapping.
template < bool bswap >
static FORCE_INLINE uint64_t GET_U64(const uint8_t * b, const uint32_t i) {
    uint64_t n;
    memcpy(&n, &b[i], 8);
    n = COND_BSWAP(n, bswap);
    return n;
}

template < bool bswap >
static FORCE_INLINE uint32_t GET_U32(const uint8_t * b, const uint32_t i) {
    uint32_t n;
    memcpy(&n, &b[i], 4);
    n = COND_BSWAP(n, bswap);
    return n;
}

template < bool bswap >
static FORCE_INLINE uint16_t GET_U16(const uint8_t * b, const uint32_t i) {
    uint16_t n;
    memcpy(&n, &b[i], 2);
    n = COND_BSWAP(n, bswap);
    return n;
}

template < bool bswap >
static FORCE_INLINE void PUT_U32(uint32_t n, uint8_t * b, const uint32_t i) {
    n = COND_BSWAP(n, bswap);
    memcpy(&b[i], &n, 4);
}

template < bool bswap >
static FORCE_INLINE void PUT_U64(uint64_t n, uint8_t * b, const uint32_t i) {
    n = COND_BSWAP(n, bswap);
    memcpy(&b[i], &n, 8);
}
