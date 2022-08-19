/*
 * Pearson hashing
 * This is free and unencumbered software released into the public
 * domain under The Unlicense (http://unlicense.org/).
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
static void pearson_hash_256( uint8_t * out, const uint8_t * in, size_t len, uint64_t hash_in ) {
    size_t i;
    /*
     * initial values -  astonishingly, assembling using SHIFTs and ORs (in register)
     * works faster on well pipelined CPUs than loading the 64-bit value from memory.
     * however, there is one advantage to loading from memory: as we also store back to
     * memory at the end, we do not need to care about endianess!
     */
    uint8_t upper[8]              = { 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08 };
    uint8_t lower[8]              = { 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 };

    uint64_t upper_hash_mask      = GET_U64<false>(upper, 0);
    uint64_t lower_hash_mask      = GET_U64<false>(lower, 0);
    uint64_t high_upper_hash_mask = upper_hash_mask + UINT64_C(0x1010101010101010);
    uint64_t high_lower_hash_mask = lower_hash_mask + UINT64_C(0x1010101010101010);

    // The one nod to endianness is that the hash_in value needs be in
    // little-endian format always, to match up with the byte ordering
    // of upper[] and lower[] above.
    hash_in = COND_BSWAP(hash_in, isBE());
    uint64_t upper_hash      = hash_in;
    uint64_t lower_hash      = hash_in;
    uint64_t high_upper_hash = hash_in;
    uint64_t high_lower_hash = hash_in;

    for (i = 0; i < len; i++) {
        // broadcast the character, xor into hash, make them different permutations
        uint64_t c = (uint8_t)in[i];
        c |= c <<  8;
        c |= c << 16;
        c |= c << 32;
        upper_hash      ^= c ^ upper_hash_mask;
        lower_hash      ^= c ^ lower_hash_mask;
        high_upper_hash ^= c ^ high_upper_hash_mask;
        high_lower_hash ^= c ^ high_lower_hash_mask;

        // table lookup
        uint64_t h = 0;
        uint16_t x;
        x = upper_hash; x = t16[x]; upper_hash >>= 16; h  = x; h = ROTR64(h, 16);
        x = upper_hash; x = t16[x]; upper_hash >>= 16; h |= x; h = ROTR64(h, 16);
        x = upper_hash; x = t16[x]; upper_hash >>= 16; h |= x; h = ROTR64(h, 16);
        x = upper_hash; x = t16[x];                    h |= x; h = ROTR64(h, 16);
        upper_hash = h;

        h = 0;
        x = lower_hash; x = t16[x]; lower_hash >>= 16; h  = x; h = ROTR64(h, 16);
        x = lower_hash; x = t16[x]; lower_hash >>= 16; h |= x; h = ROTR64(h, 16);
        x = lower_hash; x = t16[x]; lower_hash >>= 16; h |= x; h = ROTR64(h, 16);
        x = lower_hash; x = t16[x];                    h |= x; h = ROTR64(h, 16);
        lower_hash = h;

        h = 0;
        x = high_upper_hash; x = t16[x]; high_upper_hash >>= 16; h  = x; h = ROTR64(h, 16);
        x = high_upper_hash; x = t16[x]; high_upper_hash >>= 16; h |= x; h = ROTR64(h, 16);
        x = high_upper_hash; x = t16[x]; high_upper_hash >>= 16; h |= x; h = ROTR64(h, 16);
        x = high_upper_hash; x = t16[x];                         h |= x; h = ROTR64(h, 16);
        high_upper_hash = h;

        h = 0;
        x = high_lower_hash; x = t16[x]; high_lower_hash >>= 16; h  = x; h = ROTR64(h, 16);
        x = high_lower_hash; x = t16[x]; high_lower_hash >>= 16; h |= x; h = ROTR64(h, 16);
        x = high_lower_hash; x = t16[x]; high_lower_hash >>= 16; h |= x; h = ROTR64(h, 16);
        x = high_lower_hash; x = t16[x];                         h |= x; h = ROTR64(h, 16);
        high_lower_hash = h;
    }
    // store output
    PUT_U64<false>(high_upper_hash, out,  0);
    PUT_U64<false>(high_lower_hash, out,  8);
    PUT_U64<false>(upper_hash     , out, 16);
    PUT_U64<false>(lower_hash     , out, 24);
}

static void pearson_hash_128( uint8_t * out, const uint8_t * in, size_t len, uint64_t hash_in ) {
    size_t i;
    /*
     * initial values -  astonishingly, assembling using SHIFTs and ORs (in register)
     * works faster on well pipelined CPUs than loading the 64-bit value from memory.
     * however, there is one advantage to loading from memory: as we also store back to
     * memory at the end, we do not need to care about endianess!
     */
    uint8_t upper[8]         = { 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08 };
    uint8_t lower[8]         = { 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 };

    uint64_t upper_hash_mask = GET_U64<false>(upper, 0);
    uint64_t lower_hash_mask = GET_U64<false>(lower, 0);

    // The one nod to endianness is that the hash_in value needs be in
    // little-endian format always, to match up with the byte ordering
    // of upper[] and lower[] above.
    hash_in = COND_BSWAP(hash_in, isBE());
    uint64_t upper_hash = hash_in;
    uint64_t lower_hash = hash_in;

    for (i = 0; i < len; i++) {
        // broadcast the character, xor into hash, make them different permutations
        uint64_t c = (uint8_t)in[i];
        c |= c <<  8;
        c |= c << 16;
        c |= c << 32;
        upper_hash ^= c ^ upper_hash_mask;
        lower_hash ^= c ^ lower_hash_mask;

        // table lookup
        uint64_t h = 0;
        uint16_t x;
        x = upper_hash; x = t16[x]; upper_hash >>= 16; h  = x; h = ROTR64(h, 16);
        x = upper_hash; x = t16[x]; upper_hash >>= 16; h |= x; h = ROTR64(h, 16);
        x = upper_hash; x = t16[x]; upper_hash >>= 16; h |= x; h = ROTR64(h, 16);
        x = upper_hash; x = t16[x];                    h |= x; h = ROTR64(h, 16);
        upper_hash = h;

        h = 0;
        x = lower_hash; x = t16[x]; lower_hash >>= 16; h  = x; h = ROTR64(h, 16);
        x = lower_hash; x = t16[x]; lower_hash >>= 16; h |= x; h = ROTR64(h, 16);
        x = lower_hash; x = t16[x]; lower_hash >>= 16; h |= x; h = ROTR64(h, 16);
        x = lower_hash; x = t16[x];                    h |= x; h = ROTR64(h, 16);
        lower_hash = h;
    }
    // store output
    PUT_U64<false>(upper_hash, out, 0);
    PUT_U64<false>(lower_hash, out, 8);
}

static void pearson_hash_64( uint8_t * out, const uint8_t * in, size_t len, uint64_t hash_in ) {
    size_t   i;
    uint64_t hash_mask = UINT64_C(0x0706050403020100);
    uint64_t hash      = hash_in;

    for (i = 0; i < len; i++) {
        // broadcast the character, xor into hash, make them different permutations
        uint64_t c = (uint8_t)in[i];
        c    |= c <<  8;
        c    |= c << 16;
        c    |= c << 32;
        hash ^= c ^ hash_mask;
        // table lookup

        uint64_t h = 0;
        h    = (t16[(uint16_t)(hash >> 16)] << 16) + t16[(uint16_t)hash];
        h  <<= 32;
        h   |= (uint32_t)((t16[(uint16_t)(hash >> 48)] << 16)) + t16[(uint16_t)(hash >> 32)];
        hash = ROTR64(h, 32);
    }
    // store output
    if (isBE()) {
        PUT_U64<true>(hash, out, 0);
    } else {
        PUT_U64<false>(hash, out, 0);
    }
}
