/*
 * o1hash
 * This is free and unencumbered software released into the public
 * domain under The Unlicense (http://unlicense.org/).
 *
 * main repo: https://github.com/wangyi-fudan/wyhash
 * author: 王一 Wang Yi <godspeed_china@yeah.net>
 * contributors: Frank J. T. Wojcik, Reini Urban, Dietrich Epp, Joshua
 * Haberman, Tommy Ettinger, Daniel Lemire, Otmar Ertl, cocowalla,
 * leo-yuriev, Diego Barrios Romero, paulie-g, dumblob, Yann Collet,
 * ivte-ms, hyb, James Z.M. Gao, easyaspi314 (Devin), TheOneric
 *
 * This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a
 * compiled binary, for any purpose, commercial or non-commercial, and
 * by any means.
 *
 * In jurisdictions that recognize copyright laws, the author or
 * authors of this software dedicate any and all copyright interest in
 * the software to the public domain. We make this dedication for the
 * benefit of the public at large and to the detriment of our heirs
 * and successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to
 * this software under copyright law.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
 * CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * For more information, please refer to <http://unlicense.org/>
 */
#include "Platform.h"
#include "Hashlib.h"

/*
 * This is a quick and dirty hash function designed for O(1) speed.
 * It makes your hash table application fly in most cases.
 * It samples first, middle and last 4 bytes to produce the hash.
 * Do not use it in very serious applications as it's not secure.
 */

//------------------------------------------------------------
// Includes homegrown seeding for SMHasher3
template <bool bswap>
static void o1hash( const void * in, const size_t len, const seed_t seed, void * out ) {
    const uint8_t * p = (const uint8_t *)in;
    uint64_t        h;

    if (len >= 4) {
        uint64_t first  = GET_U32<bswap>(p, 0);
        uint64_t middle = GET_U32<bswap>(p, ((len >> 1) - 2));
        uint64_t last   = GET_U32<bswap>(p, len - 4);
        h = (middle + (uint64_t)seed) * (first + last);
    } else if (len > 0) {
        uint64_t tail = seed + (
            (((uint64_t)p[0       ]) << 16) |
            (((uint64_t)p[len >> 1]) <<  8) |
            (((uint64_t)p[len -  1])      ) );
        h = tail * UINT64_C(0xa0761d6478bd642f);
    } else {
        h = 0;
    }
    PUT_U64<bswap>(h, (uint8_t *)out, 0);
}

//------------------------------------------------------------
REGISTER_FAMILY(o1hash,
   $.src_url    = "https://github.com/wangyi-fudan/wyhash/blob/master/old_versions/o1hash.h",
   $.src_status = HashFamilyInfo::SRC_FROZEN
 );

REGISTER_HASH(o1hash,
   $.desc       = "o(1) hash, from wyhash",
   $.sort_order = 45,
   $.hash_flags =
         FLAG_HASH_MOCK                  |
         FLAG_HASH_NO_SEED,
   $.impl_flags =
         FLAG_IMPL_SANITY_FAILS          |
         FLAG_IMPL_MULTIPLY              |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits = 64,
   $.verification_LE = 0xAE049F09,
   $.verification_BE = 0x299BD16A,
   $.hashfn_native   = o1hash<false>,
   $.hashfn_bswap    = o1hash<true>
 );
