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
 *     Copyright (c) 2014-2021 Reini Urban
 *     Copyright (c) 2015      Ivan Kruglov
 *     Copyright (c) 2015      Paul G
 *     Copyright (c) 2016      Jason Schulz
 *     Copyright (c) 2016-2018 Leonid Yuriev
 *     Copyright (c) 2016      Sokolov Yura aka funny_falcon
 *     Copyright (c) 2016      Vlad Egorov
 *     Copyright (c) 2018      Jody Bruchon
 *     Copyright (c) 2019      Niko Rebenich
 *     Copyright (c) 2019-2020 Yann Collet
 *     Copyright (c) 2019-2021 data-man
 *     Copyright (c) 2019      王一 WangYi
 *     Copyright (c) 2020      Cris Stringfellow
 *     Copyright (c) 2020      HashTang
 *     Copyright (c) 2020      Jim Apple
 *     Copyright (c) 2020      Thomas Dybdahl Ahle
 *     Copyright (c) 2020      Tom Kaitchuck
 *     Copyright (c) 2021      Logan oos Even
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
#include "Platform.h"
#include "Types.h"
#include "Hashes.h"
#include "LegacyHashes.h"
#include "VCode.h"

hash_state ltc_state;

// sorted by quality and speed. the last is the list of internal secrets to be tested against bad seeds.
// marked with !! are known bad seeds, which either hash to 0 or create collisions.
static LegacyHashInfo g_hashes[] =
{
 // here start the real hashes. first the problematic ones:

  // totally broken seed mixin
  { sha2_224,            224, 0x407AA518, "sha2-224",     "SHA2-224", GOOD, {0xc1059ed8} /* >100 bad seeds */ },
  { sha2_224_64,          64, 0xF3E40ECA, "sha2-224_64",  "SHA2-224, low 64 bits", GOOD, {0xc1059ed8} },
  { sha2_256,            256, 0xEBDA2FB1, "sha2-256",     "SHA2-256", POOR, {0x6a09e667} },
  { sha2_256_64,          64, 0xC1C4FA72, "sha2-256_64",  "SHA2-256, low 64 bits", POOR, {0x6a09e667} },
#if defined(HAVE_SHANI) && defined(__x86_64__)
  { sha2ni_256,          256, 0x4E3BB25E, "sha2ni-256",   "SHA2_NI-256 (amd64 HW SHA ext)", POOR, {0x6a09e667} },
  { sha2ni_256_64,        64, 0xF938E80E, "sha2ni-256_64","hardened SHA2_NI-256 (amd64 HW SHA ext), low 64 bits", POOR, {0x6a09e667} },
#endif
  { sha3_256,            256, 0x21048CE3, "sha3-256",     "SHA3-256 (Keccak)", GOOD, {0x1UL} },
  { sha3_256_64,          64, 0xE62E5CC0, "sha3-256_64",  "SHA3-256 (Keccak), low 64 bits", GOOD, {0x1UL} },
  { rmd128,              128, 0xFF576977, "rmd128",       "RIPEMD-128", GOOD, {0x67452301} },
  { rmd160,              160, 0x30B37AC6, "rmd160",       "RIPEMD-160", GOOD, {0x67452301} },
  { rmd256,              256, 0xEB16FAD7, "rmd256",       "RIPEMD-256", GOOD, {0x67452301} },
#if defined(HAVE_BIT32) && !defined(_WIN32)
#  define BLAKE3_VERIF   0x58571F56
#else
#  define BLAKE3_VERIF   0x50E4CD91
#endif
  { blake3c_test,        256, BLAKE3_VERIF, "blake3_c",   "BLAKE3 c",   GOOD, {0x6a09e667} },
#if defined(HAVE_BLAKE3)
  { blake3_test,         256, 0x0, "blake3",       "BLAKE3 Rust", GOOD, {} },
  { blake3_64,            64, 0x0, "blake3_64",    "BLAKE3 Rust, low 64 bits", GOOD, {} },
#endif
  { blake2s128_test,     128, 0xE8D8FCDF, "blake2s-128",  "blake2s-128", GOOD, {0x6a09e667} },
  { blake2s160_test,     160, 0xD50FF144, "blake2s-160",  "blake2s-160", GOOD, {0x6a09e667} },
  { blake2s224_test,     224, 0x19B36D2C, "blake2s-224",  "blake2s-224", GOOD, {0x6a09e667} },
  { blake2s256_test,     256, 0x841D6354, "blake2s-256",  "blake2s-256", GOOD,
    {0x31, 0x32, 0x15e, 0x432, 0x447, 0x8000001e, 0x80000021 } /* !! and >1000 more */ },
  { blake2s256_64,        64, 0x53000BB2, "blake2s-256_64","blake2s-256, low 64 bits", GOOD,
    {0xa, 0xe, 0x2d, 0x2f, 0x53, 0x40000003, 0x40000005, 0x40000006 } /* !! and >1000 more */ },
  { blake2b160_test,     160, 0x28ADDA30, "blake2b-160",  "blake2b-160", GOOD,
    {0x4a, 0x5a, 0x5e, 0x74, 0x7f, 0x81} /* !! and >1000 more */ },
  { blake2b224_test,     224, 0x101A62A4, "blake2b-224",  "blake2b-224", GOOD,
    {0x12, 0x2e, 0x32, 0x99a, 0xc80, 0xc98, 0xc9c} /* !! and >1000 more */ },
  { blake2b256_test,     256, 0xC9D8D995, "blake2b-256",  "blake2b-256", POOR, {} },
  { blake2b256_64,        64, 0xCF4F7EC3, "blake2b-256_64","blake2b-256, low 64 bits", GOOD, {} },


#ifdef __SIZEOF_INT128__
  // M. Dietzfelbinger, T. Hagerup, J. Katajainen, and M. Penttonen. A reliable randomized
  // algorithm for the closest-pair problem. J. Algorithms, 25:19–51, 1997.
  { multiply_shift,       64, 0x6DE70D61, "multiply_shift", "Dietzfelbinger Multiply-shift on strings", POOR,
    { 0xfffffff0, 0x1fffffff0, 0xb13dea7c9c324e51ULL, 0x75f17d6b3588f843ULL } /* !! all & 0xfffffff0 (2^32 bad seeds) */ },
  { pair_multiply_shift,  64, 0x3CB18128, "pair_multiply_shift", "Pair-multiply-shift", POOR,
    { 0xb13dea7c9c324e51ULL, 0x75f17d6b3588f843ULL } },
#endif

  { asconhashv12_256,    256, 0xA969C160, "asconhashv12", "asconhashv12 256bit", GOOD,
    { 0xee9398aadb67f03dULL } },
  { asconhashv12_64,      64, 0xE7DEF300, "asconhashv12_64", "asconhashv12, low 64 bits", GOOD,
    { 0xee9398aadb67f03dULL } },
#if defined(HAVE_SSE2)
  { hasshe2_test,        256, 0xF5D39DFE, "hasshe2",     "SSE2 hasshe2, 256-bit", POOR, {} },
#endif

  // too fragile
#ifdef __SIZEOF_INT128__
#ifdef __FreeBSD__
#  define TABUL_VERIF   0x0534C36E
#elif defined __apple_build_version__ && defined __clang__
#  define TABUL_VERIF   0x91618263
#else
#  define TABUL_VERIF   0xB49C607C
#endif
  { tabulation_test,      64, TABUL_VERIF, "tabulation",      "64-bit Tabulation with Multiply-Shift Mixer", GOOD, {} },
#endif
#if defined(_MSC_VER) /* truncated long to 32 */
#  define TABUL32_VERIF   0x3C3B7BDD
#elif defined __FreeBSD__
#  define TABUL32_VERIF   0x4D28A619
#elif defined __apple_build_version__ && defined __clang__
#  define TABUL32_VERIF   0x2C8EDFFE
#else
#  define TABUL32_VERIF   0x335F64EA
#endif
  { tabulation_32_test,   32, TABUL32_VERIF, "tabulation32",    "32-bit Tabulation with Multiply-Shift Mixer", POOR, {} },
  // 32bit crashes
#ifdef HAVE_INT64
  { o1hash_test,          64, 0x85051E87, "o1hash",       "o(1)hash unseeded, from wyhash", POOR, {0x0} /* !! */ },
#endif
#if 0 && defined(__x86_64__) && (defined(__linux__) || defined(__APPLE__))
  // elf64 or macho64 only
  { fhtw_test,            64, 0x0,        "fhtw",        "fhtw asm", POOR, {} },
#endif
#ifndef HAVE_ALIGNED_ACCESS_REQUIRED
  { khash32_test,         32, 0x99B3FFCD, "k-hash32",    "K-Hash mixer, 32-bit", POOR, {0,1,2,3,5,0x40000001} /*... !!*/},
  { khash64_test,         64, 0xAB5518A1, "k-hash64",    "K-Hash mixer, 64-bit", POOR, {0,1,2,3,4,5} /*...!!*/},
#endif
  { fletcher2_test,       64, 0x890767C0, "fletcher2",   "fletcher2 ZFS", POOR, {0UL} /* !! */ },
  { fletcher4_test,       64, 0x47660EB7, "fletcher4",   "fletcher4 ZFS", POOR, {0UL} /* !! */ },
  { Bernstein_test,       32, 0xBDB4B640, "bernstein",   "Bernstein, 32-bit", POOR, {0UL} /* !! */ },
  { sdbm_test,            32, 0x582AF769, "sdbm",        "sdbm as in perl5", POOR, {0UL} /* !! */ },
  { x17_test,             32, 0x8128E14C, "x17",         "x17", POOR, {} },
  // also called jhash:
  { JenkinsOOAT_test,     32, 0x83E133DA, "JenkinsOOAT", "Bob Jenkins' OOAT as in perl 5.18", POOR, {0UL} /* !! */ },
  { JenkinsOOAT_perl_test,32, 0xEE05869B, "JenkinsOOAT_perl", "Bob Jenkins' OOAT as in old perl5", POOR, {0UL} /* !! */},
#if defined(HAVE_SSE42) && defined(__x86_64__) && !defined(_MSC_VER)
  // empty verify with msvc. avoid
  { pearson64_test,       64, 0x12E4C8CD, "pearsonhash64",    "Pearson hash, 64-bit SSSE3", POOR, {}},
  { pearson128_test,     128, 0x6CCBB7B3, "pearsonhash128",   "Pearson hash, 128-bit SSSE3, low 64-bit", POOR, {}},
  { pearson256_test,     256, 0x7F8BEB21, "pearsonhash256",   "Pearson hash, 256-bit SSSE3, low 64-bit", POOR, {}},
#endif
#ifdef HAVE_INT64
  { pearsonb64_test,      64, 0xB6FF2DFC, "pearsonbhash64",  "Pearson block hash, 64-bit", GOOD, {}},
  { pearsonb128_test,    128, 0x6BEFE6EA, "pearsonbhash128", "Pearson block hash, 128-bit, low 64-bit", GOOD, {}},
  { pearsonb256_test,    256, 0x999B3C19, "pearsonbhash256", "Pearson block hash, 256-bit, low 64-bit", GOOD, {}},
#endif
  // FIXME: seed
#ifdef __aarch64__
  #define VHASH32_VERIF 0x0F02AEFD
  #define VHASH64_VERIF 0xFAAEE597
#else
  #define VHASH32_VERIF 0xF0077651
  #define VHASH64_VERIF 0xF97D84FE
#endif
  { VHASH_32,             32, VHASH32_VERIF, "VHASH_32",    "VHASH_32 by Ted Krovetz and Wei Dai", POOR, {} },
  { VHASH_64,             64, VHASH64_VERIF, "VHASH_64",    "VHASH_64 by Ted Krovetz and Wei Dai", POOR, {} },
  { MicroOAAT_test,       32, 0x16F1BA97,    "MicroOAAT",   "Small non-multiplicative OAAT (by funny-falcon)", POOR,
    {0x3b00} },
#ifdef HAVE_SSE2
  { farsh32_test,         32, 0xBCDE332C, "farsh32",     "FARSH 32bit", POOR, {} }, // insecure
  { farsh64_test,         64, 0xDE2FDAEE, "farsh64",     "FARSH 64bit", POOR, {} }, // insecure
  { farsh128_test,       128, 0x82B6CBEC, "farsh128",    "FARSH 128bit", POOR, {} },
  { farsh256_test,       256, 0xFEBEA0BC, "farsh256",    "FARSH 256bit", POOR, {} },
#endif
  { jodyhash32_test,      32, 0xFB47D60D, "jodyhash32",  "jodyhash, 32-bit (v5)", POOR, {} },
#ifdef HAVE_INT64
  { jodyhash64_test,      64, 0x9F09E57F, "jodyhash64",  "jodyhash, 64-bit (v5)", POOR, {} },
#endif
  { lookup3_test,         32, 0x3D83917A, "lookup3",     "Bob Jenkins' lookup3", POOR, {0x21524101} /* !! */},
#ifdef __aarch64__
  #define SFAST_VERIF 0x6306A6FE
#else
  #define SFAST_VERIF 0x0C80403A
#endif
  { SuperFastHash_test,   32, SFAST_VERIF,"superfast",   "Paul Hsieh's SuperFastHash", POOR, {0x0} /* !! */},
  { MurmurOAAT_test,      32, 0x5363BD98, "MurmurOAAT",  "Murmur one-at-a-time", POOR,
    {0x0 /*, 0x5bd1e995*/} /* !! */ },
  { Crap8_test,           32, 0x743E97A1, "Crap8",       "Crap8", POOR, {/*0x83d2e73b, 0x97e1cc59*/} },
  { xxHash32_test,        32, 0xBA88B743, "xxHash32",    "xxHash, 32-bit for x86", POOR, {} },
#if !defined(DEBUG) && !defined(CROSSCOMPILING) && !defined(__aarch64__)
# ifndef HAVE_ASAN
  // TODO seeded
  { PMPML_32_CPP,         32, 0xEAE2E3CC, "PMPML_32",    "PMP_Multilinear 32-bit unseeded", POOR, {} },
#  if defined(_WIN64) || defined(__x86_64__)
  { PMPML_64_CPP,         64, 0x584CC9DF, "PMPML_64",    "PMP_Multilinear 64-bit unseeded", POOR, {} },
#  endif
# endif
#endif
  { fasthash32_test,      32, 0xE9481AFC, "fasthash32",  "fast-hash 32bit", POOR, {0x880355f21e6d1965ULL} },
  { fasthash64_test,      64, 0xA16231A7, "fasthash64",  "fast-hash 64bit", POOR, {0x880355f21e6d1965ULL} },
  { CityHash32_test,      32, 0x5C28AD62, "City32",      "Google CityHash32WithSeed (old)", POOR, {0x2eb38c9f} /* !! */},
#ifdef HAVE_INT64
  { metrohash64_test,      64, 0x6FA828C9, "metrohash64",    "MetroHash64, 64-bit", POOR, {} },
  { metrohash64_1_test,    64, 0xEE88F7D2, "metrohash64_1",  "MetroHash64_1, 64-bit (legacy)", POOR, {} },
  { metrohash64_2_test,    64, 0xE1FC7C6E, "metrohash64_2",  "MetroHash64_2, 64-bit (legacy)", GOOD, {} },
  { metrohash128_test,    128, 0x4A6673E7, "metrohash128",   "MetroHash128, 128-bit", GOOD, {} },
  { metrohash128_1_test,  128, 0x20E8A1D7, "metrohash128_1", "MetroHash128_1, 128-bit (legacy)", GOOD, {} },
  { metrohash128_2_test,  128, 0x5437C684, "metrohash128_2", "MetroHash128_2, 128-bit (legacy)", GOOD, {} },
#endif
#if defined(HAVE_SSE42) && (defined(__x86_64__) ||  defined(__aarch64__)) && !defined(_MSC_VER)
  { metrohash64crc_1_test, 64, 0x29C68A50, "metrohash64crc_1", "MetroHash64crc_1 for x64 (legacy)", POOR, {} },
  { metrohash64crc_2_test, 64, 0x2C00BD9F, "metrohash64crc_2", "MetroHash64crc_2 for x64 (legacy)", POOR, {} },
  { cmetrohash64_1_optshort_test,64, 0xEE88F7D2, "cmetrohash64_1o", "cmetrohash64_1 (shorter key optimized), 64-bit for x64", POOR, {} },
  { cmetrohash64_1_test,   64, 0xEE88F7D2, "cmetrohash64_1",  "cmetrohash64_1, 64-bit for x64", POOR, {} },
  { cmetrohash64_2_test,   64, 0xE1FC7C6E, "cmetrohash64_2",  "cmetrohash64_2, 64-bit for x64", GOOD, {} },
  { metrohash128crc_1_test,128, 0x5E75144E, "metrohash128crc_1", "MetroHash128crc_1 for x64 (legacy)", GOOD, {} },
  { metrohash128crc_2_test,128, 0x1ACF3E77, "metrohash128crc_2", "MetroHash128crc_2 for x64 (legacy)", GOOD, {} },
#endif
  { CityHash64noSeed_test, 64, 0x63FC6063, "City64noSeed","Google CityHash64 without seed (default version, misses one final avalanche)", POOR, {} },
  { CityHash64_test,      64, 0x25A20825, "City64",       "Google CityHash64WithSeed (old)", POOR, {} },
#if defined(HAVE_SSE2) && defined(__x86_64__) && !defined(_WIN32)
  { falkhash_test_cxx,    64, 0x2F99B071, "falkhash",    "falkhash.asm with aesenc, 64-bit for x64", POOR, {} },
#endif
#ifdef HAVE_MEOW_HASH
  { MeowHash32_test,      32, 0x8872DE1A, "MeowHash32low","MeowHash (requires x64 AES-NI)", POOR,
    {0x920e7c64} /* !! */},
  { MeowHash64_test,      64, 0xB04AC842, "MeowHash64low","MeowHash (requires x64 AES-NI)", POOR, {0x920e7c64} },
  { MeowHash128_test,    128, 0xA0D29861, "MeowHash",     "MeowHash (requires x64 AES-NI)", POOR, {0x920e7c64} },
#endif
  { t1ha1_64le_test,      64, 0xD6836381, "t1ha1_64le",  "Fast Positive Hash (portable, aims 64-bit, little-endian)", POOR, {} },
  { t1ha1_64be_test,      64, 0x93F864DE, "t1ha1_64be",  "Fast Positive Hash (portable, aims 64-bit, big-endian)", POOR, {} },
  { t1ha0_32le_test,      64, 0x7F7D7B29, "t1ha0_32le",  "Fast Positive Hash (portable, aims 32-bit, little-endian)", POOR, {} },
  { t1ha0_32be_test,      64, 0xDA6A4061, "t1ha0_32be",  "Fast Positive Hash (portable, aims 32-bit, big-endian)", POOR, {} },
#if __WORDSIZE >= 64
# define TIFU_VERIF       0x644236D4
#else
  // broken on certain travis
# define TIFU_VERIF       0x0
#endif
  // and now the quality hash funcs, slowest first
  { tifuhash_64,          64, TIFU_VERIF, "tifuhash_64", "Tiny Floatingpoint Unique Hash with continued egyptian fractions", POOR, {} },
  // different verif on gcc vs clang
  { floppsyhash_64,       64, 0x0,        "floppsyhash", "slow hash designed for floating point hardware", GOOD, {} },
  { chaskey_test,         64, 0xBB4F6706, "chaskey",     "mouha.be/chaskey/ with added seed support", GOOD, {} },
  { siphash_test,         64, 0xC58D7F9C, "SipHash",     "SipHash 2-4 - SSSE3 optimized", GOOD, {} },
  { halfsiphash_test,     32, 0xA7A05F72, "HalfSipHash", "HalfSipHash 2-4, 32bit", GOOD, {} },
  { GoodOAAT_test,        32, 0x7B14EEE5, "GoodOAAT",    "Small non-multiplicative OAAT", GOOD, {0x3b00} },
#ifdef HAVE_INT64
  { prvhash64_64mtest,    64, 0xD37C7E74, "prvhash64_64m", "prvhash64m 64bit", GOOD, {} },
  { prvhash64_64test,     64, 0xD37C7E74, "prvhash64_64",  "prvhash64 64bit", GOOD, {} },
  { prvhash64_128test,   128, 0xB447480F, "prvhash64_128", "prvhash64 128bit", GOOD, {} },
  { prvhash64s_64test,    64, 0,          "prvhash64s_64", "prvhash64s 64bit", GOOD, {} }, // seed changes
  { prvhash64s_128test,  128, 0,          "prvhash64s_128","prvhash64s 128bit", GOOD, {} }, // seed compiler-specific
#endif
  { komihash_test,        64, 0xEE0A1C4A, "komihash",      "komihash", GOOD, {} },
  // as in rust and swift:
  { siphash13_test,       64, 0x29C010BF, "SipHash13",   "SipHash 1-3 - SSSE3 optimized", GOOD, {} },
#ifndef _MSC_VER
  { tsip_test,            64, 0x75C732C0, "TSip",        "Damian Gryski's Tiny SipHash variant", GOOD, {} },
#ifdef HAVE_INT64
  { seahash_test,         64, 0xF0374078, "seahash",     "seahash (64-bit, little-endian)", GOOD, {} },
  { seahash32low,         32, 0x712F0EE8, "seahash32low","seahash - lower 32bit", GOOD, {} },
#endif /* HAVE_INT64 */
#endif /* !MSVC */
#if defined(HAVE_SSE42) && defined(__x86_64__)
  { clhash_test,          64, 0x0, "clhash",      "carry-less mult. hash -DBITMIX (64-bit for x64, SSE4.2)", GOOD,
    {0xb3816f6a2c68e530, 711} },
#endif
#ifdef HAVE_HIGHWAYHASH
  { HighwayHash64_test,   64, 0x0,        "HighwayHash64", "Google HighwayHash (portable with dylib overhead)", GOOD, {} },
#endif
#if defined __aarch64__
 #define MUM_VERIF            0x280B2CC6
 #define MUMLOW_VERIF         0xB13E0239
#elif defined(__GNUC__) && UINT_MAX != ULONG_MAX
 #define MUM_VERIF            0x3EEAE2D4
 #define MUMLOW_VERIF         0x520263F5
#else
 #define MUM_VERIF            0xA973C6C0
 #define MUMLOW_VERIF         0x7F898826
#endif
  { mum_hash_test,        64, MUM_VERIF,  "MUM",         "github.com/vnmakarov/mum-hash", POOR,
    {0x0} /* !! and many more. too many */ },
  { mum_low_test,         32, MUMLOW_VERIF,"MUMlow",     "github.com/vnmakarov/mum-hash", GOOD,
    {0x11fb062a, 0x3ca9411b, 0x3edd9a7d, 0x41f18860, 0x691457ba} /* !! */ },
#if defined(__GNUC__) && UINT_MAX != ULONG_MAX
 #define MIR_VERIF            0x00A393C8
 #define MIRLOW_VERIF         0xE320CE68
#else
 #define MIR_VERIF            0x422A66FC
 #define MIRLOW_VERIF         0xD50D1F09
#endif
#ifdef HAVE_INT64
  // improved MUM
  { mirhash_test,         64, MIR_VERIF,    "mirhash",            "mirhash", GOOD,
    {0x0, 0x5e74c778, 0xa521f17b, 0xe0ab70e3} /* 2^36 !! (plus all hi ranges) */ },
  { mirhash32low,         32, MIRLOW_VERIF, "mirhash32low",       "mirhash - lower 32bit", POOR,
    {0x0, 0x5e74c778, 0xa521f17b, 0xe0ab70e3 } /* !! */ },
  { mirhashstrict_test,   64, 0x422A66FC,   "mirhashstrict",      "mirhashstrict (portable, 64-bit, little-endian)", GOOD,
    {0x7fcc747f} /* tested ok */ },
  { mirhashstrict32low,   32, 0xD50D1F09,   "mirhashstrict32low", "mirhashstrict - lower 32bit", POOR,
    {0x7fcc747f} /* !! */ },
#endif
  { CityHash64_low_test,  32, 0xCC5BC861, "City64low",   "Google CityHash64WithSeed (low 32-bits)", GOOD, {} },
#if defined(__SSE4_2__) && defined(__x86_64__)
  { CityHash128_test,    128, 0x6531F54E, "City128",     "Google CityHash128WithSeed (old)", GOOD, {} },
  { CityHashCrc128_test, 128, 0xD4389C97, "CityCrc128",  "Google CityHashCrc128WithSeed SSE4.2 (old)", GOOD, {} },
#endif

#if defined(__FreeBSD__)
#  define FARM64_VERIF        0x0
#  define FARM128_VERIF       0x0
#else
#  define FARM64_VERIF        0xEBC4A679
#  define FARM128_VERIF       0x305C0D9A
#endif
  { FarmHash32_test,      32, 0/*0x2E226C14*/,   "FarmHash32",  "Google FarmHash32WithSeed", GOOD, {0x2b091701} /* !! */},
  { FarmHash64_test,      64, FARM64_VERIF, "FarmHash64",  "Google FarmHash64WithSeed", GOOD, {} },
 //{ FarmHash64noSeed_test,64, 0xA5B9146C,  "Farm64noSeed","Google FarmHash64 without seed (default, misses on final avalanche)", POOR, {} },
  { FarmHash128_test,    128, FARM128_VERIF,"FarmHash128", "Google FarmHash128WithSeed", GOOD, {} },
#if defined(__SSE4_2__) && defined(__x86_64__)
  { farmhash32_c_test,    32, 0/*0xA2E45238*/,   "farmhash32_c", "farmhash32_with_seed (C99)", GOOD,
    {0x2b091701} /* !! */},
  { farmhash64_c_test,    64, FARM64_VERIF, "farmhash64_c",  "farmhash64_with_seed (C99)", GOOD, {} },
  { farmhash128_c_test,  128, FARM128_VERIF,"farmhash128_c", "farmhash128_with_seed (C99)", GOOD, {} },
#endif

  { xxHash64_test,        64, 0x024B7CF4, "xxHash64",    "xxHash, 64-bit", GOOD, {} },
#if 0
  { xxhash256_test,       64, 0x024B7CF4, "xxhash256",   "xxhash256, 64-bit unportable", GOOD, {} },
#endif
  { SpookyHash32_test,    32, 0x3F798BBB, "Spooky32",    "Bob Jenkins' SpookyHash, 32-bit result", GOOD,
    { 0x111af082, 0x26bb3cda, 0x94c4f96c, 0xec24c166 } /* !! */},
  { SpookyHash64_test,    64, 0xA7F955F1, "Spooky64",    "Bob Jenkins' SpookyHash, 64-bit result", GOOD, {} },
  { SpookyHash128_test,  128, 0x8D263080, "Spooky128",   "Bob Jenkins' SpookyHash, 128-bit result", GOOD, {} },
  { SpookyV2_32_test,     32, 0xA48BE265, "SpookyV2_32",  "Bob Jenkins' SpookyV2, 32-bit result", GOOD, {} },
  { SpookyV2_64_test,     64, 0x972C4BDC, "SpookyV2_64",  "Bob Jenkins' SpookyV2, 64-bit result", GOOD, {} },
  { SpookyV2_128_test,   128, 0x893CFCBE, "SpookyV2_128", "Bob Jenkins' SpookyV2, 128-bit result", GOOD, {} },
  { pengyhash_test,       64, 0x1FC2217B, "pengyhash",   "pengyhash", GOOD, {} },
  { mx3rev1hash64_test,   64, 0x4DB51E5B, "mx3-rev1",    "mx3 revision 1 64bit", GOOD, {0x10} /* !! and all & 0x10 */},
  { mx3hash64_test,       64, 0x527399AD, "mx3",         "mx3 revision 2 64bit", GOOD, {} },
#if defined(HAVE_SSE42) &&  (defined(__x86_64__) ||  defined(__aarch64__)) && !defined(_MSC_VER)
  { umash32,              32, 0x03E16CA1, "umash32",     "umash 32", GOOD, {0x90e37057} /* !! */},
  { umash32_hi,           32, 0xE29D613C, "umash32_hi",  "umash 32 hi", GOOD, {} },
  { umash,                64, 0x4542288C, "umash64",     "umash 64", GOOD, {} },
  { umash128,            128, 0xDA4E82B6, "umash128",    "umash 128", GOOD, {} },
#endif
  { halftime_hash_style64_test,  64, 0x0, "halftime_hash64",    "NH tree hash variant", GOOD,
    {0xc61d672b, 0xcc70c4c1798e4a6f, 0xd3833e804f4c574b, 0xecfc1357d65941ae, 0xbe1927f97b8c43f1, 
     0xf4d4beb14ae042bbULL, 0x9a9b4c4e44dd48d1ULL} }, // not vulnerable
  { halftime_hash_style128_test, 64, 0x0, "halftime_hash128",   "NH tree hash variant", GOOD,
    {0xc61d672b, 0xcc70c4c1798e4a6f, 0xd3833e804f4c574b, 0xecfc1357d65941ae, 0xbe1927f97b8c43f1, 
     0xf4d4beb14ae042bbULL, 0x9a9b4c4e44dd48d1ULL} },
  { halftime_hash_style256_test, 64, 0x0, "halftime_hash256",   "NH tree hash variant", GOOD,
    {0xc61d672b, 0xcc70c4c1798e4a6f, 0xd3833e804f4c574b, 0xecfc1357d65941ae, 0xbe1927f97b8c43f1, 
     0xf4d4beb14ae042bbULL, 0x9a9b4c4e44dd48d1ULL} },
  { halftime_hash_style512_test, 64, 0x0, "halftime_hash512",   "NH tree hash variant", GOOD,
    {0xc61d672b, 0xcc70c4c1798e4a6f, 0xd3833e804f4c574b, 0xecfc1357d65941ae, 0xbe1927f97b8c43f1, 
     0xf4d4beb14ae042bbULL, 0x9a9b4c4e44dd48d1ULL} },

  { t1ha2_atonce_test,           64, 0x8F16C948, "t1ha2_atonce",    "Fast Positive Hash (portable", GOOD, {
    } },
  { t1ha2_stream_test,           64, 0xDED9B580, "t1ha2_stream",    "Fast Positive Hash (portable)", POOR, {} },
  { t1ha2_atonce128_test,       128, 0xB44C43A1, "t1ha2_atonce128", "Fast Positive Hash (portable)", GOOD, {} },
  { t1ha2_stream128_test,       128, 0xE929E756, "t1ha2_stream128", "Fast Positive Hash (portable)", POOR, {} },
#if T1HA0_AESNI_AVAILABLE
#  ifndef _MSC_VER
  { t1ha0_ia32aes_noavx_test,  64, 0xF07C4DA5, "t1ha0_aes_noavx", "Fast Positive Hash (AES-NI)", GOOD, {} },
#  endif
#  if defined(__AVX__)
  { t1ha0_ia32aes_avx1_test,   64, 0xF07C4DA5, "t1ha0_aes_avx1",  "Fast Positive Hash (AES-NI & AVX)", GOOD, {} },
#  endif /* __AVX__ */
#  if defined(__AVX2__)
  { t1ha0_ia32aes_avx2_test,   64, 0x8B38C599, "t1ha0_aes_avx2",  "Fast Positive Hash (AES-NI & AVX2)", GOOD, {} },
#  endif /* __AVX2__ */
#endif /* T1HA0_AESNI_AVAILABLE */
#ifdef HAVE_AHASH_C
  // aHash does not adhere to a fixed output
  { ahash64_test,         64, 0x00000000, "ahash64",     "ahash 64bit", GOOD, {} },
#endif
  { xxh3_test,            64, 0x39CD9E4A, "xxh3",        "xxHash v3, 64-bit", GOOD, // no known bad seeds
    {0x47ebda34,             // 32bit bad seed
     /* 0xbe4ba423396cfeb8,  // kSecret
     0x396cfeb8, 0xbe4ba423, // kSecret
     0x6782737bea4239b9,     // bitflip1 ^ input
     0xaf56bc3b0996523a,     // bitflip2 ^ input[last 8]
     */
    }},
  { xxh3low_test,         32, 0xFAE8467B, "xxh3low",     "xxHash v3, 64-bit, low 32-bits part", GOOD,
    {0x47ebda34} /* !! */},
  { xxh128_test,         128, 0xEB61B3A0, "xxh128",      "xxHash v3, 128-bit", GOOD,
    {0x47ebda34}},
  { xxh128low_test,       64, 0x54D1CC70, "xxh128low",   "xxHash v3, 128-bit, low 64-bits part", GOOD,
    {0x47ebda34}},
#ifdef HAVE_BIT32
  { wyhash32_test,        32, 0x09DE8066, "wyhash32",       "wyhash v3 (32-bit native)", GOOD,
    { 0x429dacdd, 0xd637dbf3 } /* !! */ },
#else
  { wyhash32low,          32, 0x7DB3559D, "wyhash32low",    "wyhash v3 lower 32bit", GOOD,
    { 0x429dacdd, 0xd637dbf3 } /* !! */ },
#endif
#ifdef HAVE_INT64
  { wyhash_test,          64, 0x67031D43, "wyhash",         "wyhash v3 (64-bit)", GOOD,
    // all seeds with those lower bits
    { 0x14cc886e, 0x1bf4ed84, 0x14cc886e14cc886eULL} /* !! 2^33 bad seeds, but easy to check */ },
  //{ wyhash_condom_test,   64, 0x7C62138D, "wyhash_condom",  "wyhash v3 condom 2 (64-bit)", GOOD, { } },
#endif
  { nmhash32_test,        32, 0x12A30553, "nmhash32",       "nmhash32", GOOD, {}},
  { nmhash32x_test,       32, 0xA8580227, "nmhash32x",      "nmhash32x", GOOD, {}},
};

size_t numLegacyHashes(void) {
    return sizeof(g_hashes) / sizeof(LegacyHashInfo);
}

LegacyHashInfo * numLegacyHash(size_t num) {
    if (num >= numLegacyHashes()) {
        return NULL;
    }
    return &g_hashes[num];
}

LegacyHashInfo * findLegacyHash ( const char * name )
{
  for(size_t i = 0; i < sizeof(g_hashes) / sizeof(LegacyHashInfo); i++)
  {
    if(_stricmp(name,g_hashes[i].name) == 0)
      return &g_hashes[i];
  }

  return NULL;
}

// optional hash state initializers
void Hash_init (LegacyHashInfo* info) {
  if (info->hash == sha2_224_64)
    sha224_init(&ltc_state);
  else if (info->hash == rmd128)
    rmd128_init(&ltc_state);
  else if(info->hash == tabulation_32_test)
    tabulation_32_init();
#ifdef __SIZEOF_INT128__
  else if(info->hash == multiply_shift ||
          info->hash == pair_multiply_shift)
    multiply_shift_init();
  else if(info->hash == tabulation_test)
    tabulation_init();
#endif
#if defined(HAVE_SSE42) && defined(__x86_64__)
  else if(info->hash == clhash_test)
    clhash_init();
  //else if(info->hash == umash32_test ||
  //        info->hash == umash32hi_test ||
  //        info->hash == umash64_test ||
  //        info->hash == umash128_test)
  //  umash_init();
#endif
  else if (info->hash == VHASH_32 || info->hash == VHASH_64)
    VHASH_init();
#ifdef HAVE_HIGHWAYHASH
  else if(info->hash == HighwayHash64_test)
    HighwayHash_init();
#endif
#ifndef _MSC_VER
  else if(info->hash == tsip_test)
    tsip_init();
#endif
  else if(info->hash == chaskey_test)
    chaskey_init();
  else if (info->hash == halftime_hash_style64_test ||
           info->hash == halftime_hash_style128_test ||
           info->hash == halftime_hash_style256_test ||
           info->hash == halftime_hash_style512_test)
    halftime_hash_init();
}

// Needed for hashed with a few bad seeds, to reject this seed and generate a new one.
// (GH #99)
void Bad_Seed_init (pfHash hash, uint32_t &seed) {
  if(hash ==
#ifdef HAVE_BIT32
          wyhash32_test
#else
          wyhash32low
#endif
          )
    wyhash32_seed_init(seed);
  // zero-seed hashes:
  else if (!seed && (hash == fletcher2_test ||
                     hash == fletcher4_test || hash == Bernstein_test || hash == sdbm_test ||
                     hash == JenkinsOOAT_test || hash == JenkinsOOAT_perl_test ||
                     hash == SuperFastHash_test || hash == MurmurOAAT_test ||
                     hash == o1hash_test))
    seed++;
  else if (hash == Crap8_test && (seed == 0x83d2e73b || seed == 0x97e1cc59))
    seed++;
#ifdef HAVE_INT64
  else if(hash == wyhash_test) {
    size_t seedl = seed;
    wyhash_seed_init(seedl);
    seed = seedl;
  }
  else if(hash == mirhash_test)
    mirhash_seed_init(seed);
  else if(hash == mirhash32low)
    mirhash32_seed_init(seed);
  else if(hash == mirhashstrict32low && seed == 0x7fcc747f)
    seed++;
#endif
#ifdef __SIZEOF_INT128__
  else if(hash == multiply_shift)
    multiply_shift_seed_init(seed);
#endif
#if defined(__SSE4_2__) && defined(__x86_64__)
  else if (hash == clhash_test && seed == 0x0)
    seed++;
#endif
}

// Optional hash seed initializer, for expensive seeding.
bool Hash_Seed_init (pfHash hash, size_t seed) {
  addVCodeInput(seed);

  uint32_t seed32 = seed;

  //if (hash == VHASH_32 || hash == VHASH_64)
  //  VHASH_seed_init(seed);
  if(hash == tabulation_32_test)
    tabulation_32_seed_init(seed);
#ifdef __SIZEOF_INT128__
  else if(hash == multiply_shift || hash == pair_multiply_shift)
    multiply_shift_seed_init(seed32);
  else if(hash == tabulation_test)
    tabulation_seed_init(seed);
#endif
#if defined(HAVE_SSE42) && defined(__x86_64__)
  else if (hash == clhash_test)
    clhash_seed_init(seed);
# ifndef _MSC_VER  
  else if (hash == umash32 ||
          hash == umash32_hi ||
          hash == umash ||
          hash == umash128)
    umash_seed_init(seed);
# endif
  else if (hash == halftime_hash_style64_test || hash == halftime_hash_style128_test ||
           hash == halftime_hash_style256_test || hash == halftime_hash_style512_test)
    halftime_hash_seed_init(seed);
  /*
  else if(hash == hashx_test)
    hashx_seed_init(info, seed);
  */
#endif
  else
      return false;
  return true;
}

//-----------------------------------------------------------------------------
bool hash_is_very_slow(pfHash hash) {
    // known very slow hashes (typically > 500 cycle/hash)
    const struct { pfHash h; } slowhashes[] = {
        { sha2_224                 },
        { sha2_224_64              },
        { sha2_256                 },
        { sha2_256_64              },
        { rmd128                   },
        { rmd160                   },
        { rmd256                   },
        { blake2s128_test          },
        { blake2s160_test          },
        { blake2s224_test          },
        { blake2s256_test          },
        { blake2s256_64            },
        { blake2b160_test          },
        { blake2b224_test          },
        { blake2b256_test          },
        { blake2b256_64            },
        { sha3_256                 },
        { sha3_256_64              },
        { tifuhash_64              },
        { floppsyhash_64           },
    };

    for (int i=0; i<sizeof(slowhashes)/sizeof(slowhashes[0]); i++) {
        if (slowhashes[i].h == hash) {
            return true;
        }
    }

    return false;
}

bool hash_is_slow(pfHash hash) {
    if (hash_is_very_slow(hash)) {
        return true;
    }

    // known somewhat slow hashes
    const struct { pfHash h; } slowhashes[] = {
        { o1hash_test                 },
        { halftime_hash_style64_test  },
        { halftime_hash_style128_test },
        { halftime_hash_style256_test },
        { halftime_hash_style512_test },
    };

    for (int i=0; i<sizeof(slowhashes)/sizeof(slowhashes[0]); i++) {
        if (slowhashes[i].h == hash) {
            return true;
        }
    }

    return false;
}
