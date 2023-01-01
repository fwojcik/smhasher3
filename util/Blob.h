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
 *
 * This file incorporates work covered by the following copyright and
 * permission notice:
 *
 *     Copyright (c) 2010-2012 Austin Appleby
 *     Copyright (c) 2019-2021 Reini Urban
 *     Copyright (c) 2019-2020 Yann Collet
 *
 *     Permission is hereby granted, free of charge, to any person
 *     obtaining a copy of this software and associated documentation
 *     files (the "Software"), to deal in the Software without
 *     restriction, including without limitation the rights to use,
 *     copy, modify, merge, publish, distribute, sublicense, and/or
 *     sell copies of the Software, and to permit persons to whom the
 *     Software is furnished to do so, subject to the following
 *     conditions:
 *
 *     The above copyright notice and this permission notice shall be
 *     included in all copies or substantial portions of the Software.
 *
 *     THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *     EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 *     OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *     NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 *     HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 *     WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 *     FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 *     OTHER DEALINGS IN THE SOFTWARE.
 */
#include <algorithm>

extern const uint32_t hzb[256];

//-----------------------------------------------------------------------------
#define _bytes ((_bits + 7) / 8)
template <unsigned _bits>
class Blob {
  public:
    //----------
    // constructors

    Blob() {
        memset(bytes, 0, sizeof(bytes));
    }

    Blob( const void * p, size_t len ) {
        len = std::min(len, sizeof(bytes));
        memcpy(bytes, p, len);
        memset(&bytes[len], 0, sizeof(bytes) - len);
    }

    Blob( uint64_t x ) :
        Blob((x = COND_BSWAP( x, isBE()), &x), sizeof(x)) {}

    //----------
    // unary operators

    uint8_t & operator [] ( int i ) {
        // assert(i < sizeof(bytes));
        return bytes[i];
    }

    const uint8_t & operator [] ( int i ) const {
        // assert(i < sizeof(bytes));
        return bytes[i];
    }

    Blob & operator = ( const Blob & k ) {
        memcpy(bytes, k.bytes, sizeof(bytes));
        return *this;
    }

    Blob & operator = ( const uint32_t & x ) {
        const uint32_t y = COND_BSWAP(x, isBE());

        memcpy(bytes, &y, std::min(sizeof(y), sizeof(bytes)));
        return *this;
    }

    //----------
    // boolean operators

    bool operator < ( const Blob & k ) const {
        for (int i = sizeof(bytes) - 1; i >= 0; i--) {
            if (bytes[i] < k.bytes[i]) { return true; }
            if (bytes[i] > k.bytes[i]) { return false; }
        }
        return false;
    }

    bool operator == ( const Blob & k ) const {
        int r = memcmp(&bytes[0], &k.bytes[0], sizeof(bytes));

        return (r == 0) ? true : false;
    }

    bool operator != ( const Blob & k ) const {
        return !(*this == k);
    }

    //----------
    // bitwise operations

    Blob operator ^ ( const Blob & k ) const {
        Blob t;

        for (size_t i = 0; i < sizeof(bytes); i++) {
            t.bytes[i] = bytes[i] ^ k.bytes[i];
        }

        return t;
    }

    Blob & operator ^= ( const Blob & k ) {
        for (size_t i = 0; i < sizeof(bytes); i++) {
            bytes[i] ^= k.bytes[i];
        }
        return *this;
    }

    //----------
    // interface

    FORCE_INLINE uint32_t getbit( size_t bit ) const {
        return _getbit(bit, bytes, sizeof(bytes));
    }

    FORCE_INLINE void printhex( const char * prefix = "" ) const {
        _printhex(prefix, bytes, sizeof(bytes));
    }

    FORCE_INLINE void printbits( const char * prefix = "" ) const {
        _printbits(prefix, bytes, sizeof(bytes));
    }

    FORCE_INLINE uint32_t highzerobits( void ) const {
        return _highzerobits(bytes, sizeof(bytes));
    }

    FORCE_INLINE uint32_t window( size_t start, size_t count ) const {
        return _window(start, count, bytes, sizeof(bytes));
    }

    FORCE_INLINE void flipbit( size_t bit ) {
        _flipbit(bit, bytes, sizeof(bytes));
    }

    FORCE_INLINE void reversebits( void ) {
        _reversebits(bytes, sizeof(bytes));
    }

    FORCE_INLINE void lrot( size_t c ) {
        _lrot(c, bytes, sizeof(bytes));
    }

  protected:
    //----------
    // implementations

    static FORCE_INLINE uint32_t _getbit( size_t bit, const uint8_t * bytes, const size_t len ) {
        size_t byte = bit >> 3;

        bit &= 7;
        if (byte > len) { return 0; }
        return (bytes[byte] >> bit) & UINT32_C(1);
    }

    static void _printhex( const char * prefix, const uint8_t * bytes, const size_t len ) {
        const size_t buflen = 4 + 2 * len + ((len + 3) / 4);
        char         buf[buflen];
        char *       p;

        buf[0] = '[';
        buf[1] = ' ';
        // Space preceding the closing ']' gets added by the loop below
        buf[buflen - 2] = ']';
        buf[buflen - 1] = '\0';

        // Print using MSB-first notation
        p = &buf[2];
        for (size_t i = len; i != 0; i--) {
            uint8_t vh = (bytes[i - 1] >> 4);
            uint8_t vl = (bytes[i - 1] & 15);
            *p++       = vh + ((vh <= 9) ? '0' : 'W'); // 'W' + 10 == 'a'
            *p++       = vl + ((vl <= 9) ? '0' : 'W');
            if ((i & 3) == 1) {
                *p++ = ' ';
            }
        }

        printf("%s%s\n", prefix, buf);
    }

    static void _printbits( const char * prefix, const uint8_t * bytes, const size_t len ) {
        const size_t buflen = 4 + 9 * len;
        char         buf[buflen];
        char *       p;

        buf[0] = '[';
        buf[1] = ' ';
        // Space preceding the closing ']' gets added by the loop below
        buf[buflen - 2] = ']';
        buf[buflen - 1] = '\0';

        // Print using MSB-first notation
        p = &buf[2];
        for (size_t i = len; i != 0; i--) {
            uint8_t v = bytes[i - 1];
            for (int j = 7; j >= 0; j--) {
                *p++ = (v & (1 << j)) ? '1' : '0';
            }
            *p++ = ' ';
        }

        printf("%s%s\n", prefix, buf);
    }

    static FORCE_INLINE uint32_t _highzerobits( const uint8_t * bytes, const size_t len ) {
        uint32_t zb = 0;

        for (ssize_t i = len - 1; i >= 0; i--) {
            zb += hzb[bytes[i]];
            if (bytes[i] != 0) {
                break;
            }
        }
        return zb;
    }

    // Bit-windowing function.
    // Select some N-bit subset of the Blob, where N <= 24.
    static FORCE_INLINE uint32_t _window( size_t start, size_t count, const uint8_t * bytes, const size_t len ) {
        assume(count <= 24);
        const size_t   bitlen = 8 * len;
        const uint32_t mask   = (1 << count) - 1;
        uint32_t       v;

        if (start <= (bitlen - 25)) {
            memcpy(&v, &bytes[start >> 3], 4);
            v   = COND_BSWAP(v, isBE());
            v >>= (start & 7);
        } else {
            memcpy(&v, &bytes[len - 4], 4);
            v   = COND_BSWAP(v, isBE());
            v >>= (32 + start - bitlen);
            if ((start + count) > bitlen) {
                uint32_t v2;
                memcpy(&v2, bytes, 4);
                v2   = COND_BSWAP(v2, isBE());
                v2 <<= bitlen - start;
                v   |= v2;
            }
        }
        return v & mask;
    }

    static FORCE_INLINE void _flipbit( size_t bit, uint8_t * bytes, const size_t len ) {
        const size_t byteoffset = bit >> 3;
        const size_t bitoffset  = bit & 7;

        if (byteoffset < len) {
            bytes[byteoffset] ^= (1 << bitoffset);
        }
    }

    // from the "Bit Twiddling Hacks" webpage
    static FORCE_INLINE uint8_t _byterev( uint8_t b ) {
        return ((b * UINT64_C(0x0802) & UINT64_C(0x22110)) |
               (b * UINT64_C(0x8020) & UINT64_C(0x88440)))  * UINT64_C(0x10101) >> 16;
    }

    // 0xf00f1001 => 0x8008f00f
    static FORCE_INLINE void _reversebits( uint8_t * bytes, const size_t len ) {
        uint8_t tmp[len];

        for (size_t i = 0; i < len; i++) {
            tmp[len - i - 1] = _byterev(bytes[i]);
        }
        memcpy(bytes, tmp, len);
    }

    static void _lrot( size_t c, uint8_t * bytes, const size_t len ) {
        const size_t byteoffset = c >> 3;
        const size_t bitoffset  = c & 7;
        uint8_t      tmp[len];

        for (size_t i = 0; i < len; i++) {
            tmp[(i + byteoffset) % len] = bytes[i];
        }
        if (bitoffset == 0) {
            memcpy(bytes, tmp, len);
        } else {
            for (size_t i = 0; i < len; i++) {
                uint8_t a = tmp[i];
                uint8_t b = (i == 0) ? tmp[len - 1] : tmp[i - 1];
                bytes[i] = (a << bitoffset) | (b >> (8 - bitoffset));
            }
        }
    }

  private:
    //----------
    uint8_t  bytes[_bytes];
}; // class Blob

template <>
FORCE_INLINE void Blob<32>::flipbit( size_t bit ) {
    uint32_t v;
    memcpy(&v, bytes, 4);
    v ^= 1 << bit;
    memcpy(bytes, &v, 4);
}

template <>
FORCE_INLINE void Blob<64>::flipbit( size_t bit ) {
    uint64_t v;
    memcpy(&v, bytes, 8);
    v ^= UINT64_C(1) << bit;
    memcpy(bytes, &v, 8);
}

template <>
FORCE_INLINE uint32_t Blob<32>::getbit( size_t bit ) const {
    uint32_t v;
    memcpy(&v, bytes, 4);
    return (v >> bit) & 1;
}

template <>
FORCE_INLINE uint32_t Blob<64>::getbit( size_t bit ) const {
    uint64_t v;
    memcpy(&v, bytes, 8);
    return (v >> bit) & 1;
}

// from the "Bit Twiddling Hacks" webpage
template <>
FORCE_INLINE void Blob<32>::reversebits( void ) {
    uint32_t v = GET_U32<false>(bytes, 0);

    // swap odd and even bits
    v = ((v >>  1) & 0x55555555) | ((v & 0x55555555) <<  1);
    // swap consecutive pairs
    v = ((v >>  2) & 0x33333333) | ((v & 0x33333333) <<  2);
    // swap nibbles ...
    v = ((v >>  4) & 0x0F0F0F0F) | ((v & 0x0F0F0F0F) <<  4);
    // swap bytes
    v = ((v >>  8) & 0x00FF00FF) | ((v & 0x00FF00FF) <<  8);
    // swap 2-byte long pairs
    v = ((v >> 16)             ) | ((v             ) << 16);
    PUT_U32<false>(v, bytes, 0);
}

template <>
FORCE_INLINE void Blob<64>::reversebits( void ) {
    uint64_t v = GET_U64<false>(bytes, 0);

    // swap odd and even bits
    v = ((v >>  1) & UINT64_C(0x5555555555555555)) | ((v & UINT64_C(0x5555555555555555)) <<  1);
    // swap consecutive pairs
    v = ((v >>  2) & UINT64_C(0x3333333333333333)) | ((v & UINT64_C(0x3333333333333333)) <<  2);
    // swap nibbles ...
    v = ((v >>  4) & UINT64_C(0x0F0F0F0F0F0F0F0F)) | ((v & UINT64_C(0x0F0F0F0F0F0F0F0F)) <<  4);
    // swap bytes
    v = ((v >>  8) & UINT64_C(0x00FF00FF00FF00FF)) | ((v & UINT64_C(0x00FF00FF00FF00FF)) <<  8);
    // swap 2-byte long pairs
    v = ((v >> 16) & UINT64_C(0x0000FFFF0000FFFF)) | ((v & UINT64_C(0x0000FFFF0000FFFF)) << 16);
    // swap 4-byte long pairs
    v = ((v >> 32)                               ) | ((v                               ) << 32);
    PUT_U64<false>(v, bytes, 0);
}

//-----------------------------------------------------------------------------
// Blob-like class for externally managed buffers.
// The operator overloads of Blob<> are made private, and so are not exposed.

typedef void *       voidptr_t;
typedef const void * constvoidptr_t;

class ExtBlob : private Blob<0> {
  public:
    //----------
    // constructors

    ExtBlob( uint8_t * p, size_t l ) {
        ptr = p;
        len = l;
    }

    ExtBlob( uint8_t * p, const uint8_t * i, size_t l ) {
        ptr = p;
        len = l;
        memcpy(ptr, i, len);
    }

    //----------
    // conversion operators

    operator voidptr_t () const {
        return (voidptr_t)ptr;
    }

    operator constvoidptr_t () const {
        return (constvoidptr_t)ptr;
    }

    //----------
    // interface

    FORCE_INLINE uint32_t getbit( size_t bit ) const {
        return _getbit(bit, ptr, len);
    }

    FORCE_INLINE void printhex( const char * prefix = "" ) const {
        _printhex(prefix, ptr, len);
    }

    FORCE_INLINE void printbits( const char * prefix = "" ) const {
        _printbits(prefix, ptr, len);
    }

    FORCE_INLINE uint32_t highzerobits( void ) const {
        return _highzerobits(ptr, len);
    }

    FORCE_INLINE uint32_t window( size_t start, size_t count ) const {
        return _window(start, count, ptr, len);
    }

    FORCE_INLINE void flipbit( size_t bit ) {
        _flipbit(bit, ptr, len);
    }

    FORCE_INLINE void reversebits( void ) {
        _reversebits(ptr, len);
    }

    FORCE_INLINE void lrot( size_t c ) {
        _lrot(c, ptr, len);
    }

  private:
    uint8_t * ptr;
    size_t    len;
}; // class ExtBlob
