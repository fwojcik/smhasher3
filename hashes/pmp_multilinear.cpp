/*
 * PMP Multilinear hashes
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
 * Copyright (c) 2014-2021 Reini Urban
 * Copyright (c) 2014, Dmytro Ivanchykhin, Sergey Ignatchenko, Daniel Lemire
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "Platform.h"
#include "Hashlib.h"

#if defined(HAVE_AVX2) || defined(HAVE_SSE_4_1) || defined(HAVE_SSE_2)
  #undef HAVE_AVX2
  #undef HAVE_SSE_4_1
  #undef HAVE_SSE_2
// #include "Intrinsics.h"
#endif

#include "Mathmult.h"

#include <functional>
using namespace std;

//-------------------------------------------------------------
// Common typedefs
#if __BYTE_ORDER == __LITTLE_ENDIAN
typedef union _ULARGE_INTEGER__XX {
    struct {
        uint32_t  LowPart;
        uint32_t  HighPart;
    };
    struct {
        uint32_t  LowPart;
        uint32_t  HighPart;
    }         u;
    uint64_t  QuadPart;
} ULARGE_INTEGER__XX;

typedef union _LARGE_INTEGER__XX {
    struct {
        uint32_t  LowPart;
        int32_t   HighPart;
    };
    struct {
        uint32_t  LowPart;
        int32_t   HighPart;
    }        u;
    int64_t  QuadPart;
} LARGE_INTEGER__XX;
#else
typedef union _ULARGE_INTEGER__XX {
    struct {
        uint32_t  HighPart;
        uint32_t  LowPart;
    };
    struct {
        uint32_t  HighPart;
        uint32_t  LowPart;
    }         u;
    uint64_t  QuadPart;
} ULARGE_INTEGER__XX;

typedef union _LARGE_INTEGER__XX {
    struct {
        int32_t   HighPart;
        uint32_t  LowPart;
    };
    struct {
        int32_t   HighPart;
        uint32_t  LowPart;
    }        u;
    int64_t  QuadPart;
} LARGE_INTEGER__XX;
#endif

typedef struct _ULARGELARGE_INTEGER__XX {
    uint64_t  LowPart;
    uint64_t  HighPart;
} ULARGELARGE_INTEGER__XX;

#if defined(__arm__)
typedef struct { uint32_t  value __attribute__((__packed__)); }  unaligned_uint32;
typedef struct { uint64_t  value __attribute__((__packed__)); }  unaligned_uint64;
#else
typedef struct { uint32_t  value; }  unaligned_uint32;
typedef struct { uint64_t  value; }  unaligned_uint64;
#endif // __arm__

//-------------------------------------------------------------
// 32-bit constants

// Theoretically-settable constants (first 2 change the hash outputs!)
#define PMPML_32_CHUNK_SIZE_LOG2 7
#define PMPML_32_WORD_SIZE_BYTES_LOG2 2
#define PMPML_32_LEVELS 8
// Derived constants
static const uint32_t PMPML_32_CHUNK_SIZE            = (1 << PMPML_32_CHUNK_SIZE_LOG2     );
static const uint32_t PMPML_32_WORD_SIZE_BYTES       = (1 << PMPML_32_WORD_SIZE_BYTES_LOG2);
static const uint32_t PMPML_32_CHUNK_SIZE_BYTES      = PMPML_32_CHUNK_SIZE * PMPML_32_WORD_SIZE_BYTES;
static const uint32_t PMPML_32_CHUNK_SIZE_BYTES_LOG2 = PMPML_32_CHUNK_SIZE_LOG2 + PMPML_32_WORD_SIZE_BYTES_LOG2;

// container for coefficients
typedef struct alignas( 32 ) _random_data_for_PMPML_32 {
    uint64_t const_term;
    uint64_t cachedSum;
    uint64_t dummy[2];
    uint32_t random_coeff[1 << PMPML_32_CHUNK_SIZE_LOG2];
} random_data_for_PMPML_32;

static thread_local random_data_for_PMPML_32 rd_for_PMPML_32[PMPML_32_LEVELS] = {
    // Level 0
    {
        UINT64_C(0xb5ae35fa), UINT64_C(0x45dfdab824), { UINT64_C(0), UINT64_C(0) }, // dummy
        {
            0x801841bb, 0x5ef2b6fc, 0xcc5a24e2, 0x1b6c5dd5, 0xeb07483b, 0xef894c5b, 0x02213973, 0x2d34d946,
            0x11af1a4d, 0xd0a96734, 0xf39454a6, 0x58574f85, 0x08bc3780, 0x3d5e4d6e, 0x72302724, 0x89d2f7d4,
            0x97d9459e, 0xba75d6d3, 0x69efa09d, 0x56f8f06a, 0x7345e990, 0x8ac230e9, 0xd21f3d0c, 0x3fffba8a,
            0xd6dd6772, 0xd8c69c6b, 0x77a68e52, 0xde17020d, 0xf969ac45, 0x4ec4e3fb, 0x66e1eaae, 0x8c3e2c33,
            0xd031a884, 0x5942d1f7, 0x355157a1, 0x79e517ce, 0x6f6e67c9, 0xdbeb2ce9, 0xaf4c5195, 0x1d72b4ce,
            0x2214d9f3, 0xdab836c3, 0x94a54c8d, 0xa259587e, 0x8e5a6bd6, 0x75d23672, 0xf08fcd74, 0x59297837,
            0xc1f093c7, 0xb1e14572, 0x84e25787, 0xfa18cbdd, 0xc0a8efe1, 0x8f746f29, 0xd1dfea17, 0xd17d1d65,
            0x99c0334e, 0xc200ce59, 0xbac039b7, 0xaa8da145, 0x91787415, 0x7478d0e6, 0xd4fcb135, 0x76c4ce66,
            0xdf1d9e9b, 0xe6a6640f, 0x94dd9b8e, 0x7f530896, 0xd5a76dff, 0xda99ae01, 0x2830dcad, 0x18421917,
            0xc98aeb4f, 0x0048fdda, 0xd5ae8cba, 0xe9d27a3f, 0xc51ba04d, 0x8f1403e7, 0x2cbc94bd, 0x2c47c847,
            0xbf127785, 0x54d2a15b, 0x6a818544, 0x993ca700, 0x31f529ed, 0x4cf30c4c, 0x386af44a, 0x1378d4c0,
            0x3c40ac83, 0x3d27aaa4, 0x9b1c685e, 0x61dbbba6, 0xe5fbbd87, 0x800c57fd, 0xccd49830, 0x1ee12d69,
            0x84868385, 0xbaf5679f, 0xd0417045, 0x4f5c30f0, 0x70558f08, 0x7c1e281d, 0xfe17014e, 0x56404d7c,
            0x77dcfdd3, 0xf0d53161, 0xf9914927, 0x69bc0362, 0x609759cb, 0xfc9afc53, 0xc5f28ba8, 0x9cbe677d,
            0x8b8311e5, 0x40a1fbde, 0x500ef7fc, 0xd51ceaa4, 0x2c666e8f, 0xbf81662b, 0xa0922fe9, 0x65a75374,
            0xc744184e, 0x1fad7a1a, 0xbc3678c2, 0xde23fbbc, 0x0403fd45, 0x69cd23ae, 0xf3dc2f19, 0x31416e93,
        },
    },
    // Level 1
    {
        UINT64_C(0xc3dbb82), UINT64_C(0x3c33d12213), { UINT64_C(0), UINT64_C(0) }, // dummy
        {
            0xd233467b, 0x72a70d41, 0x8bd6cb67, 0x2e954d02, 0x08142b46, 0xb9613249, 0x8136a81d, 0x3cdab6cf,
            0x70433dfc, 0x984d385b, 0x66f13c63, 0x392a028c, 0x84b10a87, 0xb54b7873, 0x7af58609, 0xbe835997,
            0x09878350, 0x2702ed23, 0x940ffe4b, 0x073982e4, 0x4b565486, 0xc1872a1b, 0xcb9af7a0, 0xd8a84f81,
            0xd8234048, 0x3d9a44b4, 0xfcecd1d5, 0x114fe193, 0x7e848584, 0x0082760d, 0x0ede3da7, 0x0040762c,
            0xe522397a, 0x44ec8715, 0x422bc161, 0x0764c174, 0x3c511482, 0xd7dea424, 0xa12ec3c0, 0x66d33ec0,
            0x0aaa55ce, 0x65f93ec0, 0xadaaaf7f, 0x647e772d, 0xa6b0a4fa, 0x88a72a0d, 0x1cfa03b4, 0x4f28c0c6,
            0xa7c64b56, 0xedd8af5e, 0xa47e7242, 0x99f8d210, 0x8ad70f5f, 0xa8e3cdfb, 0x0a1db865, 0x56b2e1b0,
            0x0dd7b307, 0x564a191f, 0xca38b54f, 0x61567b67, 0xd50c9644, 0x7671637e, 0x92d511cc, 0x25057afc,
            0xd286cba4, 0x71f8dda9, 0x2ad9996c, 0x75ad65f0, 0x9418c0e9, 0xe6d0066b, 0xf1d15419, 0x264afe8b,
            0x98c932e2, 0x3a6d5f8d, 0x289a7d0c, 0x3d18290d, 0xb9ecee8d, 0xdff7a79b, 0x7ecc3cde, 0x583e06a0,
            0x8e29d297, 0xdc8650cb, 0x30f7861d, 0xf2de5cf9, 0x924dc8bc, 0x5afb46e9, 0xb997b1d9, 0x463d84a2,
            0xfb8e2e7e, 0x043418b8, 0xa94e6a05, 0xae5c1efa, 0x7c7e4583, 0xcb6755ac, 0xf3359dba, 0xf05fdf94,
            0x79db25ea, 0xed490569, 0x993d8da0, 0x6593ce5a, 0x03e3ed39, 0x044f74a3, 0x84777814, 0xcb2848d7,
            0x41881b64, 0xf52d206e, 0x1fb1ebaf, 0x07a3d4b3, 0x63a5924f, 0x35c21005, 0xc981c63c, 0x9e3fdbaa,
            0x89b64b0d, 0x0f2aba74, 0x512f3cfe, 0xb053e5d0, 0x59a69c4a, 0x400c442f, 0x28afebd0, 0x4540c190,
            0xc7f5e757, 0x7d40152b, 0x321fa235, 0xb6309529, 0x021c71e1, 0x7474f524, 0xc4f2e22e, 0x778b9371,
        },
    },
    // Level 2
    {
        UINT64_C(0x4ae2b467), UINT64_C(0x41b6700d41), { UINT64_C(0), UINT64_C(0) }, // dummy
        {
            0xf8898c22, 0x863868bc, 0xd35470e9, 0x58d21ad6, 0xa2fce702, 0xe4f58530, 0x0225c8a9, 0x9b29b401,
            0xf4f6d3eb, 0xf751b2ce, 0x2afa3d7a, 0xc1edf3e9, 0x4c57e2d1, 0xc2ef970d, 0x8a70aa25, 0x887d0102,
            0xcc09e169, 0xeb5b75e2, 0x760b047e, 0xa2d21874, 0xc2bf310a, 0x8f030e02, 0x4b97fa22, 0x6a413ddb,
            0x708062b4, 0x58cc67d3, 0x52459895, 0x78d345e3, 0x2b7a9415, 0xbaf4d1fe, 0x83462969, 0x923fa257,
            0x91617494, 0xedf8d2f5, 0xc3d41302, 0xdf1934ff, 0x78a27863, 0xe7bf06a2, 0xc21b996d, 0x1e72411e,
            0x98da3053, 0x0c2195ad, 0xf984dd09, 0x4b30dac8, 0xf3a03a7a, 0xee6540ec, 0x966dffb7, 0xb463fdbe,
            0xbec26037, 0xcc9adad0, 0xdb71b8ef, 0x57341ca0, 0xa742ec7b, 0xe86321e9, 0x7a9d9f15, 0x7809e2a6,
            0x2cb6a0a0, 0x344756d0, 0x6e8e8c88, 0x7ecf3ff7, 0x129d18a0, 0x0965dc6a, 0xf6a2cad1, 0xd938681b,
            0xa1d07081, 0x4253df74, 0x774a5200, 0x59e1356d, 0x7aad36b5, 0x7dd6414a, 0x4700a70e, 0xd0da811c,
            0x1fd2a8b8, 0x1dee15ad, 0x7f15ae5a, 0xc1f74f27, 0xfd8bfb7f, 0x16815bb9, 0x64d29007, 0xc8919e9f,
            0x0b8c7e82, 0xfd5e92c2, 0x6e073fb7, 0xd52df9c2, 0x0c5c519d, 0x3ad86cb4, 0xfde300c8, 0x674c4dac,
            0x54899a0a, 0xbf9a9be5, 0xe198c073, 0x6025af27, 0x433bac50, 0x669d3281, 0xee3838b3, 0x0df3a048,
            0x2d0de6cd, 0xd289c8eb, 0x6b1c9eb1, 0x1634922b, 0x61917d41, 0x8b8bdeec, 0x12b73dcf, 0x96353517,
            0x20e29858, 0xecc04cb9, 0x0074a2ca, 0x58a0f1ba, 0x6ed4e71f, 0x063fec8e, 0xc5bc30c2, 0x77af6d46,
            0x078a6a93, 0x8c8da7a2, 0x1d02b1cc, 0x96b659f9, 0x8d8b4fbd, 0x521b2964, 0x990235f7, 0x55c63419,
            0x1ad869a5, 0x51987dbd, 0x99e7a3ff, 0xf584d99a, 0xc11c3506, 0xb1adca80, 0x55007e41, 0x09efa72b,
        },
    },
    // Level 3
    {
        UINT64_C(0xae82fd43), UINT64_C(0x4358e7ef21), { UINT64_C(0), UINT64_C(0) }, // dummy
        {
            0x9e6c8a0f, 0x9107b963, 0xdc39a0eb, 0x9fb2328d, 0xd4f03812, 0xce7ff238, 0x99710f09, 0x90b5a0ba,
            0x53cb9654, 0xdca51386, 0x5a03c91d, 0x542e4280, 0x92d368ff, 0x6769cd0b, 0xacad27d0, 0x3947f94b,
            0xf33a3265, 0x2f298054, 0x5094d047, 0x962591a6, 0x89c1de39, 0x0ef43de4, 0xe87f5576, 0xb342b1dc,
            0xffb893e3, 0x08a96d7d, 0xe1023f0d, 0x054ac7ea, 0xeb0a8934, 0xe1558e68, 0xce76025c, 0x47c0a61f,
            0x9d476622, 0xee83acc6, 0x5fb7a3fd, 0xa1798b06, 0x97cfbc96, 0x341dc4f8, 0x079d4d68, 0x85811d0d,
            0xe81cd930, 0x83f55707, 0x7cd3da51, 0xe504fcf6, 0x5afed439, 0x35677002, 0x40d755aa, 0xcea876c6,
            0x1c8a9953, 0x9a7d47c1, 0x9343c019, 0x60ffafe4, 0x7c12e1c5, 0xa64b2499, 0x9e13587f, 0x6e690d98,
            0x24a0dcfe, 0xfc4c35a6, 0x66eca52a, 0xe9e0315f, 0xa208fe48, 0x16d7bd81, 0xd5c9b0fb, 0xe7337bf9,
            0x2d3ad9dc, 0x6924c3f3, 0x8e7174f8, 0x01f7e499, 0x2e3edfb8, 0x8dfe2b6a, 0x40f43c09, 0xcf51dafc,
            0xafe98c70, 0x31b3d859, 0x07f28e34, 0x6527d100, 0x5274484e, 0x92fa82fe, 0xf059d18a, 0x55e4c67c,
            0x51e5d061, 0xaa4408e9, 0xbd7463cc, 0xb587505f, 0xfc88d42e, 0x70b3e921, 0xeabb6770, 0xfb3a060b,
            0xd675527a, 0xb8d6153f, 0xbd1763ad, 0x6f1a2573, 0xf96490be, 0xce99095f, 0x966d1090, 0x65e2a371,
            0x3a81e7f8, 0x769315db, 0xaa973861, 0x8d6d798c, 0xa935a7ae, 0x194de67a, 0x402f5da2, 0x58a7f932,
            0xa1eb519c, 0x65125c5b, 0x961b4b6c, 0x518c8dab, 0x47233e7f, 0x1b19109b, 0x46a1b3c1, 0x5dc3dd6c,
            0x709b63af, 0x3e43e71c, 0x7b997703, 0xa2259145, 0x81f87a1c, 0xa6c8a082, 0xa12ef053, 0x412e7f0e,
            0x29bef6e8, 0xcc8fca68, 0xf521167a, 0x203c0e84, 0xe92d5cd7, 0x9589c2d1, 0x208e2f28, 0x906bd537,
        },
    },
    // Level 4
    {
        UINT64_C(0xc3b9656e), UINT64_C(0x3f969c7ed3), { UINT64_C(0), UINT64_C(0) }, // dummy
        {
            0x60731d8f, 0x2e17b1b7, 0xb808f3c7, 0xf20f223c, 0xb964bc3c, 0xaa61a231, 0x3d84cd54, 0x94f006d6,
            0x684e8f60, 0xb64adf58, 0x7033ff6c, 0x01ea1b40, 0xbcaf2776, 0x70250562, 0x342ec517, 0x1e280438,
            0xaeaa96ba, 0x802391c2, 0x35a7f213, 0x8d0f57aa, 0xf8a1153b, 0x917a692a, 0xbac0385c, 0x6dc2f7dd,
            0xc573a21b, 0x0469558c, 0xf206c551, 0xfe683c17, 0x54d0c3bc, 0x80734381, 0xc4eef75c, 0x22648b9e,
            0xede23e78, 0x8823f123, 0xd687c6a7, 0x85b6752b, 0xb8cf5160, 0x8109a1c8, 0x1b4c7ceb, 0xaa8b17a6,
            0xeda3fcbf, 0xb6d65214, 0xe6171214, 0x98f4ee28, 0xc1ac9d91, 0x0810d22e, 0x1ccec281, 0xd1911b8a,
            0x272b7696, 0x860fc01d, 0x903c0029, 0xf3308e35, 0x8c2021ef, 0x52ebae93, 0x6ece3f90, 0x2d01f59f,
            0x15cf87c9, 0x79c113fd, 0xcee953e9, 0x6152456a, 0x82d25ea1, 0x743316c4, 0x351f50d1, 0x06e3708f,
            0x45060a80, 0x4c13c59a, 0x0a737387, 0x3eaa3672, 0xe5176942, 0x8431098a, 0x0cd55f05, 0x9d5c2eda,
            0x6df6d514, 0x41a412ea, 0x67606dd0, 0xdec02567, 0xaebddaad, 0xf48d85d8, 0x7f41af4b, 0xbb8b03b7,
            0x29bb612f, 0xc96546c9, 0xb04dfcc9, 0x2ee6c830, 0xafb0bc9e, 0x08e0ef18, 0xea81d1fc, 0xa58be897,
            0xee996482, 0xb7ee4493, 0x0c561cd5, 0x7695207b, 0x763a34f3, 0x7093196a, 0xecf527bd, 0xb3037632,
            0x40fdbc46, 0x72a3f33d, 0xb09e2e73, 0x1b41ab32, 0x32c280f4, 0x865d6444, 0xa998ef38, 0xe1f097de,
            0x5f6c5d4f, 0xfebdf03d, 0xc569ef53, 0xec6decf1, 0x03de6003, 0x0e3063d7, 0x8dd9c0a0, 0x062c97a4,
            0xa45c835e, 0xd167187d, 0xfe55e66e, 0x6b24b6df, 0x572c5189, 0x30c18b20, 0x3c0346f8, 0x5982a13e,
            0xbf491b0f, 0x248df32c, 0x6f572546, 0x51296aff, 0x1a8c0702, 0x94a21284, 0x371e69c8, 0x2298720e,
        },
    },
    // Level 5
    {
        UINT64_C(0xe3c9939c), UINT64_C(0x3d848fecbb), { UINT64_C(0), UINT64_C(0) }, // dummy
        {
            0x78bb7f84, 0xc6a18ac7, 0xeb321f90, 0x35d4f871, 0x61a5f4a7, 0x6d591ba2, 0x7f93ad57, 0x96841919,
            0xea7890a9, 0x0fa2f69c, 0x1866af58, 0x7f257346, 0xdcc51cd9, 0x92e78656, 0xc4628292, 0x42e01b49,
            0x40541662, 0x37af7888, 0x4faa39af, 0xa3207d98, 0x63750fda, 0x2767c143, 0xf11a2916, 0x618ceb9b,
            0x9d684ce0, 0x69088033, 0x1ab5a1c7, 0x0f0a4f86, 0x4e49f893, 0x0ca32464, 0x90a7c38e, 0x5a0aded0,
            0x2dae1926, 0x0d935a0e, 0xde592a69, 0x085299b2, 0x4977a3a0, 0x7e82d9bc, 0x399e6a95, 0xdb9f1b90,
            0xe1dfe431, 0xbac5a72d, 0x168fe9ef, 0x9727301e, 0x76cd1ddb, 0x2bcd89e0, 0x45b7de13, 0xf239f2ad,
            0xae66187d, 0xb92a6f32, 0xf0fb1c7f, 0xb77384f2, 0x6e405312, 0x6616a82e, 0x9bdca728, 0x1b5e6782,
            0xdd243a3f, 0xf148d161, 0xfe0e7b47, 0x0fdadcf7, 0x9f21d59d, 0x5057328f, 0x22f944b9, 0x7e68d807,
            0x46de914d, 0x2d351dad, 0x6b0f3436, 0x6d6a8943, 0xcd18923c, 0x2e8fa891, 0x33f1ed84, 0x30e3a20a,
            0xa15f52a0, 0x3162fa56, 0xa60d4a72, 0x3e9fab64, 0x0a584673, 0x99d08542, 0x5ce99b5a, 0xcf1be8b0,
            0xe83225e3, 0xad522e70, 0xb17e0c87, 0x5b081b14, 0xc4c71a48, 0xb430a70b, 0xf38673cd, 0x1aad3b26,
            0x0e50ca70, 0xa1aeb568, 0x4140ea0c, 0xdabeee2d, 0x2779c11b, 0x5e06c86e, 0x12803b8f, 0xa46fd322,
            0x7de67db9, 0x7d1ee355, 0xbea94742, 0xf529e572, 0x5374fffc, 0xf9037c7a, 0x1010523f, 0xb1a96f9c,
            0x89b49bfc, 0xf2469dc2, 0x1692f9e1, 0x95ec9a68, 0x09426ab7, 0x0bc30953, 0x8628bd58, 0xa28375f2,
            0xd9d4c2bf, 0xaae40027, 0x2b56df1b, 0x9d9fbc50, 0x14bf937d, 0xe7b0fb0a, 0xa5e40995, 0xfae90145,
            0x1ea68371, 0x671f2f40, 0xc654778c, 0x477cf3fd, 0x6aa5cbda, 0x8f9960c8, 0xc08542ef, 0x88bbddc8,
        },
    },
    // Level 6
    {
        UINT64_C(0xf33fe2d4), UINT64_C(0x3be3330adb), { UINT64_C(0), UINT64_C(0) }, // dummy
        {
            0x413faa9b, 0x1a3a2814, 0x957ff066, 0xfc5c55ec, 0x7898f40d, 0x30d71b62, 0xab1f1b9a, 0x5c93c31a,
            0x27e1bf84, 0x277fd4f4, 0xc8de8b61, 0x619ec0a3, 0xcc3106c9, 0x7e07e8c7, 0xadbbff04, 0x986f8050,
            0x26cd3f0a, 0xe7dcfd5a, 0xed3be524, 0x4a1e0f2b, 0xe0888023, 0x24d0c5eb, 0x476e89ae, 0x1a222b82,
            0xb3d0cd98, 0x8856e275, 0x95ac5c19, 0xbbf334b5, 0x1a346ac4, 0x9f9ed27d, 0xe64567c6, 0xfc52f176,
            0x98c8223c, 0xc09233fb, 0x078e98a4, 0xa36a369a, 0x89dfd3f0, 0x10a40ad1, 0xd14f4f1f, 0xe8ec2908,
            0xb9af0bd3, 0x4d55c288, 0xc235e430, 0x77564268, 0x42c4877e, 0x00baab49, 0xd79bda2b, 0x490fcfc2,
            0x225bfa4b, 0x216af042, 0xac221547, 0x6d8d84e0, 0x17dc383c, 0x49dcb049, 0x46d29882, 0x6661b4ed,
            0x77b0becd, 0xf7a52591, 0x70c7256d, 0x0872d1fd, 0x2940fad9, 0x2c857e39, 0x358bf808, 0x0081180c,
            0x01ec2a40, 0x3b7e716d, 0x2e0da024, 0xb77c9d9f, 0x725b6a35, 0x42d22b0c, 0x30fe2079, 0x8b72db40,
            0xba80de6a, 0x03fb3689, 0x0557ad42, 0x7237cc5d, 0x792b74ae, 0x3bd5a870, 0x136749ef, 0x81c9ddf5,
            0x95b80aa7, 0x7e885861, 0xc797839c, 0x667083b5, 0xe8e9b2d7, 0x9b282b8e, 0x8e7a7db0, 0x79d39fea,
            0x1f9cea00, 0xf7c5c4f1, 0x9e669399, 0x136a5889, 0x680d40a6, 0xea6ba4fa, 0xf7660f4b, 0xfd9af075,
            0xf242ad0c, 0xcf89799a, 0x1173b431, 0x8b3b0aa0, 0xd8e862ff, 0x6ee0e93e, 0x482772e0, 0x6f382985,
            0x995506f1, 0x5f1c3b7f, 0xc54d0f78, 0x5ba663aa, 0x91e7cc43, 0x07295028, 0xe1f9640d, 0x5e0d49cb,
            0xd1d6d96a, 0x7e602d59, 0xc8a376ac, 0x15ddcff4, 0x90481328, 0x543e0eb7, 0x07d297e4, 0xddfb2d18,
            0x94a578aa, 0x9a39368e, 0x6aab286e, 0x0a39debd, 0x8ee5e818, 0x5c30655e, 0x661772e5, 0x527b25c1,
        },
    },
    // Level 7
    {
        UINT64_C(0x6d983dad), UINT64_C(0x3e435b56e5), { UINT64_C(0), UINT64_C(0) }, // dummy
        {
            0x4014ee95, 0xfdbe07f6, 0x27a2c5d7, 0x497ae9f0, 0x18a372d5, 0x375c55ae, 0x4aab4110, 0x2d554d43,
            0x9504cbcd, 0xfbaedcce, 0x758c4326, 0xfafbba66, 0x9bda2b02, 0x1d955954, 0xe4bb3e12, 0xd558ed02,
            0x770c3bec, 0x6fcf284d, 0x7142cbb0, 0xefe84369, 0x9516d833, 0x097022c9, 0x8572785a, 0xcc866071,
            0x11084cac, 0x15707ce6, 0xc8a05f69, 0xf15c7b38, 0x3607b067, 0xa8f646b2, 0x62949620, 0x0e013130,
            0xe73a8f37, 0x853e3bd2, 0x4ad40839, 0x961fff58, 0x5b9a291e, 0x4df678ae, 0x9e49ab57, 0x12c0823b,
            0x804a15b9, 0xedbe4a7f, 0x3f65fe91, 0x0aca6940, 0xa14a7dc6, 0xd9a78895, 0x4c90b7fa, 0x90443c6a,
            0xc1325ada, 0x48876a7b, 0x091df649, 0x7ae46bc8, 0xdcfdc695, 0xc398dd91, 0xe6a24f20, 0x333f496b,
            0xe08413da, 0xbd197fa0, 0x55abc5e6, 0xa1abe124, 0x1cfdeee2, 0x48732fff, 0xdb2f1a4a, 0x192de0ae,
            0x87a288b7, 0x406f0062, 0xc4358b22, 0x19ccdeba, 0xa30cd0c5, 0x848d1e9a, 0x2fd31932, 0x7b78238e,
            0x9e9a208e, 0x517f5394, 0x8b689859, 0xe2202a00, 0x7d82aa8d, 0x736d2f4c, 0x8a5c630a, 0xaf1857bf,
            0xd56d5b1f, 0x3416feea, 0x6b16d737, 0xf61f0747, 0x359f0963, 0x6044d7c6, 0xedcdcafd, 0xa53ff8c5,
            0x09c7732a, 0x7f1b4137, 0x9d63e5c0, 0x776c5120, 0x0b0d231e, 0x57e54da1, 0x3b5e1e5e, 0x63069af7,
            0xa44a600c, 0x3d5a02fb, 0x2387039e, 0xf32214b4, 0x95707014, 0x65ae19ab, 0xa906bfd3, 0x41083458,
            0x106bdfd4, 0x41a3efe8, 0xb58bee3f, 0xaa70953c, 0x01cf2485, 0x40e5bdb9, 0xc94b2765, 0xc79cd151,
            0xad2d9daa, 0x62b40b60, 0x02800b32, 0x97d69686, 0xa9f0efdb, 0x24952809, 0x48694c4f, 0x630104fe,
            0x24f26b53, 0xc94d2a0f, 0x8635b8db, 0xb6822421, 0xe53c26dd, 0x9286330f, 0xf5a431ec, 0xacbb86b4,
        },
    },
};
// STATIC_ASSERT(PMPML_32_LEVELS <= 8, "Only 8 levels of data currently exist");

//-------------------------------------------------------------
// 64-bit constants

// Theoretically-settable constants (first 2 change the hash outputs!)
#define PMPML_64_CHUNK_SIZE_LOG2 7
#define PMPML_64_WORD_SIZE_BYTES_LOG2 3
#define PMPML_64_LEVELS 8
// Derived constants
static const uint32_t PMPML_64_CHUNK_SIZE            = (1 << PMPML_64_CHUNK_SIZE_LOG2     );
static const uint32_t PMPML_64_WORD_SIZE_BYTES       = (1 << PMPML_64_WORD_SIZE_BYTES_LOG2);
static const uint32_t PMPML_64_CHUNK_SIZE_BYTES      = PMPML_64_CHUNK_SIZE * PMPML_64_WORD_SIZE_BYTES;
static const uint32_t PMPML_64_CHUNK_SIZE_BYTES_LOG2 = PMPML_64_CHUNK_SIZE_LOG2 + PMPML_64_WORD_SIZE_BYTES_LOG2;

// container for coefficients
typedef struct alignas( 32 ) _random_data_for_PMPML_64 {
    uint64_t const_term;
    uint64_t cachedSumLow;
    uint64_t cachedSumHigh;
    uint64_t dummy;
    uint64_t random_coeff[1 << PMPML_64_CHUNK_SIZE_LOG2];
} random_data_for_PMPML_64;

static thread_local random_data_for_PMPML_64 rd_for_PMPML_64[PMPML_64_LEVELS] = {
    // Level 0
    {
        UINT64_C(0x4a29bfabe82f3abe), UINT64_C(0x2ccb0e578cfa99b), UINT64_C(0x000000041), 0, // sum of coeff and dummy
        {
            UINT64_C(0x2f129e0f017dff36), UINT64_C(0xb42c52ed219ac8ce), UINT64_C(0xd3324e2b5efdfa21), UINT64_C(0xc830746c5019f1de),
            UINT64_C(0x57b1306026904f72), UINT64_C(0x0ec3ffd84539cf3d), UINT64_C(0x95664d4564b54986), UINT64_C(0xe0ee74349c002680),
            UINT64_C(0x5a365b98971ff939), UINT64_C(0xf6bcac95513c540e), UINT64_C(0x49567d345ab6b3cf), UINT64_C(0x526ab3f6dee0def3),
            UINT64_C(0x1d6fb9cf7dc2f089), UINT64_C(0xaeff1dbeb93f0749), UINT64_C(0xd4e05404a7eecac8), UINT64_C(0x5175e11e90cf1a69),
            UINT64_C(0x29aac3810d90cf44), UINT64_C(0xe9930a671d8aab37), UINT64_C(0x00eded5ac8eeb924), UINT64_C(0xdb4820639e005b34),
            UINT64_C(0x12debc35a3054ea7), UINT64_C(0x5a9dccd55b94986f), UINT64_C(0x666773be4be48027), UINT64_C(0xf9a45b94c9c5ce42),
            UINT64_C(0xf3f018ccd958cf92), UINT64_C(0x473c23beeb584939), UINT64_C(0xc5e4f821ec00cd5b), UINT64_C(0x1d61cf5079c28b1c),
            UINT64_C(0xf46643c7b0c9427b), UINT64_C(0x34d7177b30a2a078), UINT64_C(0x5279d153b2ab790a), UINT64_C(0xeaf18c48a1791f4c),
            UINT64_C(0x90a13cb0c7ccb5b1), UINT64_C(0x2900f5242f23c3e6), UINT64_C(0x0975f1f8a1f6800f), UINT64_C(0xa53f1a9605cce7f2),
            UINT64_C(0x0b396087cda51e60), UINT64_C(0x842e287b1fc29d36), UINT64_C(0x4556b0258878e52d), UINT64_C(0x546c60312887a3f0),
            UINT64_C(0xdc13b1bb35399672), UINT64_C(0x32f18c1aa7a4697c), UINT64_C(0xc9223ebe2ebe5810), UINT64_C(0xeb845691d3f028e8),
            UINT64_C(0xa21337280cc34732), UINT64_C(0x94d78e46776a29e2), UINT64_C(0x6cba9535a7c4c9a8), UINT64_C(0x9758fe18e1fb3d08),
            UINT64_C(0x92478227db728e63), UINT64_C(0xa782477118744c90), UINT64_C(0xb1e0b74044f53769), UINT64_C(0x7b3a58b416f2474f),
            UINT64_C(0xea041c911fc2991f), UINT64_C(0x4515562dfb118051), UINT64_C(0x36133ab6715ff0bd), UINT64_C(0xb0d107f4c74bcfc7),
            UINT64_C(0xef47885bb62db5b8), UINT64_C(0xb2060330e33f5951), UINT64_C(0x96758e992ce56ba6), UINT64_C(0xe6ca7568b7f6a8ec),
            UINT64_C(0xd6fd9b1a7b29fb71), UINT64_C(0x2e95d6aaa1593907), UINT64_C(0xf1abe303bdda6758), UINT64_C(0x1eb12f0ed0f91332),
            UINT64_C(0xf593589b9ff39cbb), UINT64_C(0x110e67013362cf26), UINT64_C(0x671ca6801c7f9d57), UINT64_C(0x0aa55c338ed83b64),
            UINT64_C(0x627d00690f3f465d), UINT64_C(0xff97bfbba48e8524), UINT64_C(0x9c3f5a0387919b50), UINT64_C(0x25f1e1efb7f91c48),
            UINT64_C(0x7114cada956a53ae), UINT64_C(0x626a4e2ff89c39af), UINT64_C(0x86540186b2e391cc), UINT64_C(0x82d5f935e9a90bcd),
            UINT64_C(0xe2d4d3059b6f5dc1), UINT64_C(0xbb3cc83e6478dd2e), UINT64_C(0x59b9b400b166ed62), UINT64_C(0xf04b9b209bb113b1),
            UINT64_C(0xb27be3c3397ac130), UINT64_C(0xf619002cc54ac417), UINT64_C(0x46a8c23f12907210), UINT64_C(0x54fc42e7d99aa54f),
            UINT64_C(0x2b264e8ea68323e7), UINT64_C(0x0e0b0f627257dfb9), UINT64_C(0xadc098de597949e8), UINT64_C(0xe2ba17b10bd5401a),
            UINT64_C(0x7fa49be97f34ca1a), UINT64_C(0x8817b0a7e7d981cf), UINT64_C(0x3bede65042860a1f), UINT64_C(0xae569b2aafd241eb),
            UINT64_C(0x5f1cc5a3059aa744), UINT64_C(0x762409219323dae9), UINT64_C(0x64d5aac875461b4e), UINT64_C(0x62147c9101655025),
            UINT64_C(0xbde2c420826c8ddd), UINT64_C(0xde6d7e2be12d0797), UINT64_C(0x8338ac734c823357), UINT64_C(0x419b2aa58f1b985a),
            UINT64_C(0x39ed88775355ae2d), UINT64_C(0x7a2e8cc72c7f3bce), UINT64_C(0x97935746814fa944), UINT64_C(0x828331abf2018ef4),
            UINT64_C(0xd6b9060cd1d0ba56), UINT64_C(0x5548e64ac7626ff2), UINT64_C(0xe4635461f9175d23), UINT64_C(0x566d5d69d40cd206),
            UINT64_C(0x65ffaf0c83ae838f), UINT64_C(0x5a585c800a52de9e), UINT64_C(0x64a121bc55d0b7a2), UINT64_C(0x661ef9d5b90d6e53),
            UINT64_C(0xb298bfcff8afba20), UINT64_C(0x2a60665850d1a5e8), UINT64_C(0x61aba7a90d9ae6eb), UINT64_C(0x083667e22ffdf423),
            UINT64_C(0xd5efe61f9bd9a79c), UINT64_C(0x582a3cf851cafad0), UINT64_C(0x1989365a301ef819), UINT64_C(0xe2778e8aee7b917e),
            UINT64_C(0x4bd139ea2fc74066), UINT64_C(0x2716bfaa4b18912a), UINT64_C(0x1a477a7687dbbe34), UINT64_C(0x90127b1d8835c6e1),
            UINT64_C(0x44651dc23bfac77d), UINT64_C(0xb030740966562609), UINT64_C(0xb295d4733127a190), UINT64_C(0xf022c66dc7b74382),
        },
    },
// Level 1
    {
        UINT64_C(0x39cd7650ff4f752a), UINT64_C(0xe9b49347770073e9), UINT64_C(0x00000003f), 0, // sum of coeff and dummy
        {
            UINT64_C(0x6a22166c40f87e99), UINT64_C(0xff7e13387c337404), UINT64_C(0xd15f0f4dd5de05be), UINT64_C(0x825bb897d6ad1ef4),
            UINT64_C(0x77b045691a63a8ec), UINT64_C(0x0a49df4370eb4048), UINT64_C(0xf6c80d9827e7043b), UINT64_C(0x1628979784f8c50d),
            UINT64_C(0xd1a3e1f52402e01b), UINT64_C(0x6cfa2849efd5bc7f), UINT64_C(0xc6416ba240b063ec), UINT64_C(0x772d9ac4e43b2707),
            UINT64_C(0x8cc9c4735bea20c5), UINT64_C(0xede4a423d10791b3), UINT64_C(0xc75eb6c16dbb96eb), UINT64_C(0x2df99f5f3ac91794),
            UINT64_C(0x31be65ba10763ed5), UINT64_C(0xe89ce26b47440bc2), UINT64_C(0xe537526e59ddafdf), UINT64_C(0x16ae378ed0ef349c),
            UINT64_C(0x747c11f0403b290e), UINT64_C(0xc1ada5226937ff10), UINT64_C(0x91886c173226bd6f), UINT64_C(0x7e0002e3c3aaeee3),
            UINT64_C(0x65c329b5ce3ffac3), UINT64_C(0xd01f1343a37cc2f7), UINT64_C(0x366e7896927020e8), UINT64_C(0x84327c9993246a19),
            UINT64_C(0x2c08dcf57f5487d1), UINT64_C(0x9981f7143c3f09bf), UINT64_C(0xe413c704e8ac8b14), UINT64_C(0x6c1354b6a416b3fb),
            UINT64_C(0xaf14a970a5db32a3), UINT64_C(0x37428eb1cbdf20a8), UINT64_C(0x9b3a2f48a45999fc), UINT64_C(0x894d39e47aad1efa),
            UINT64_C(0x662abdc6b0bb17e8), UINT64_C(0xd449820255e4bc4a), UINT64_C(0x5fc5d5a18389fa01), UINT64_C(0xf76102aa2484326e),
            UINT64_C(0x08c4308c96b8ef43), UINT64_C(0x5c3a562402cee74c), UINT64_C(0xcf896705837e6c8c), UINT64_C(0xe069655ea3c1a067),
            UINT64_C(0x3478c1c88ef76c15), UINT64_C(0x8f97330dff9ff33b), UINT64_C(0xba8c150f3fa32e41), UINT64_C(0x1f9be6e624480693),
            UINT64_C(0x65d39bd613016d2c), UINT64_C(0x8d4504cb5be46d10), UINT64_C(0xf8b9f2f1685ce679), UINT64_C(0x023c59373ff7edc6),
            UINT64_C(0x86283f83c707e5fa), UINT64_C(0xd7c3eebedd1a109b), UINT64_C(0x942b2786ea139167), UINT64_C(0xf54a2b229a268134),
            UINT64_C(0x85d175f335d21fa1), UINT64_C(0xce39abb9d7e787e0), UINT64_C(0x3290b3797c71b62d), UINT64_C(0x954aebd35bc2d445),
            UINT64_C(0xfb24c9a40287bbea), UINT64_C(0x7c50d2bef8066d38), UINT64_C(0xf8614d3fa751b1d1), UINT64_C(0x0ed6bd1b203b43b9),
            UINT64_C(0x7444a688119fc803), UINT64_C(0xaafc0cf7a8f588a3), UINT64_C(0x86790f357d28efc6), UINT64_C(0xbc6d006ea2a48c65),
            UINT64_C(0x192cd81c89e62897), UINT64_C(0x144a15fa87c09aa8), UINT64_C(0xc9466727de209085), UINT64_C(0xeaf453256eda97d1),
            UINT64_C(0x2f0baafb5017bc8e), UINT64_C(0x1871e4808c0438bd), UINT64_C(0x1e78e125290b3e64), UINT64_C(0xb85bef6ba39ebc7d),
            UINT64_C(0xc4487e3cabd4bf9e), UINT64_C(0x2ec0963510ce4901), UINT64_C(0x3b760a55c2ffc8aa), UINT64_C(0x0538bff351c74590),
            UINT64_C(0xa2720fb707bf396d), UINT64_C(0xbca7ae2418758cc9), UINT64_C(0x6080c33057e68c8d), UINT64_C(0x0ce8e54cf677833c),
            UINT64_C(0xc08644e5a40fa1ec), UINT64_C(0x143ce206cebb6352), UINT64_C(0x9842eb597773bb9a), UINT64_C(0xf9a01484a87d6b12),
            UINT64_C(0x734da10581a35732), UINT64_C(0x1c5817613ea17f8d), UINT64_C(0xfbeb5bf815f12eb3), UINT64_C(0x0879175b1d28ed23),
            UINT64_C(0xc470ffc0a1ce0cfd), UINT64_C(0x0b4b4e44b3d0b5d8), UINT64_C(0x2cd5a8501f56ac9a), UINT64_C(0xf2dfcf44a1689892),
            UINT64_C(0x3bf38a66c6b001a2), UINT64_C(0xabfe0c1ce71d4829), UINT64_C(0xde1916f0d7565ad1), UINT64_C(0x97d66cfacf3df802),
            UINT64_C(0x0e28348769858002), UINT64_C(0xefed65d521df30e9), UINT64_C(0x33abb8c0116b7721), UINT64_C(0xb21b1751d4a13405),
            UINT64_C(0x3c445b844cb809e8), UINT64_C(0x48fe0d52ba18de8c), UINT64_C(0x88206dc4b93a7829), UINT64_C(0x2543fca442fe076b),
            UINT64_C(0x4c6b6b567a3571d3), UINT64_C(0x47d9c2f551c39ba7), UINT64_C(0x2c6e0a4ebba24ac4), UINT64_C(0xb0a1c2f16942e728),
            UINT64_C(0x536ca9a81adc2f15), UINT64_C(0xd84840af846d8115), UINT64_C(0x6a85aa0fa3159219), UINT64_C(0x4c167b95be156d20),
            UINT64_C(0xcd3f7f07382d52cb), UINT64_C(0x000020e3a8604961), UINT64_C(0x0889912d52e797ba), UINT64_C(0x19eca83144939b12),
            UINT64_C(0xb746c4bc57d2b80d), UINT64_C(0x5f19680e72e9ae82), UINT64_C(0xc8d7c655d341f90e), UINT64_C(0xd5d17f24f8e76882),
            UINT64_C(0x111bc49d022a5575), UINT64_C(0xd6c434f7739424b9), UINT64_C(0x5d56d36b4ded16fe), UINT64_C(0x910276b4a008443f),
        },
    },
// Level 2
    {
        UINT64_C(0x8d88b6de8694f9bd), UINT64_C(0xab3746b512cf0a0e), UINT64_C(0x00000003d), 0, // sum of coeff and dummy
        {
            UINT64_C(0x8c35afea7008c707), UINT64_C(0x41ead554cfccdc94), UINT64_C(0x2efb2ec168e3bffc), UINT64_C(0xe7c3a0bbddc63920),
            UINT64_C(0x4dce9e2b34302387), UINT64_C(0xfaf035fd5624990c), UINT64_C(0xccd919a786ba8213), UINT64_C(0x9a18857bdb2be4c1),
            UINT64_C(0x001d03ba509647b6), UINT64_C(0x7e331694b4f66982), UINT64_C(0xb478c5a41317d762), UINT64_C(0xe717e226317c1144),
            UINT64_C(0x022ffa0a2f15f66e), UINT64_C(0x6519929c261c063c), UINT64_C(0xff2060eae017d4e0), UINT64_C(0xefff6af725b87556),
            UINT64_C(0x5d4d573a24be5312), UINT64_C(0xc07e9f4f495eb740), UINT64_C(0x5257032ed4c0e657), UINT64_C(0x2841f8526903c4ce),
            UINT64_C(0xa5deee0ffb84873b), UINT64_C(0x45ce5d741491bbb2), UINT64_C(0x9c2b70601078ed64), UINT64_C(0x43837fdef168a0b0),
            UINT64_C(0xf2ac139bf0bef9e8), UINT64_C(0x31f63ea0f89c8f29), UINT64_C(0x566268e5d7e2b1a7), UINT64_C(0x90a1dcf90070c039),
            UINT64_C(0xb656b46da32098f3), UINT64_C(0x932e618f2bf02ff5), UINT64_C(0x6567346814e558c3), UINT64_C(0x6fee0aa9bbcd1aab),
            UINT64_C(0x55a497a53ecf775d), UINT64_C(0xcce903fab3ead90d), UINT64_C(0x7fe3e530e9d3eaa0), UINT64_C(0x4dde47c8e75c1597),
            UINT64_C(0x9d487b4725819ca5), UINT64_C(0x5893db2002678a18), UINT64_C(0x75f4da89918d8bff), UINT64_C(0x46736d07b2f80ed6),
            UINT64_C(0x2b6e79c066e45341), UINT64_C(0xce708ef399b937cb), UINT64_C(0xa63749ae5d4f1767), UINT64_C(0x635d830a136e0563),
            UINT64_C(0x55eea54f48f48df6), UINT64_C(0x68a076896b939688), UINT64_C(0x6e980d43ce7b11e9), UINT64_C(0x199065b551f0a7da),
            UINT64_C(0x5d42faee0cb91d94), UINT64_C(0xa1770f53043c2107), UINT64_C(0x35c1ac46c4e4a748), UINT64_C(0xff43f86b0cd6ab3b),
            UINT64_C(0x279dbad410c06a67), UINT64_C(0x40017b35ed84446a), UINT64_C(0xa73172134f9c5e8f), UINT64_C(0xfcff1de2975b0043),
            UINT64_C(0xae0dd9ae2cfa364f), UINT64_C(0x52129c7818987b00), UINT64_C(0xaa0e91dae1a89606), UINT64_C(0x91dc4cbfdbb14973),
            UINT64_C(0xb0ab9a3a7281965c), UINT64_C(0x9a8e2941fc1696a4), UINT64_C(0x6c76a89ed0a78b2c), UINT64_C(0xaa2539208db7d79a),
            UINT64_C(0xcd5a73ca1b8ad462), UINT64_C(0xd2844afcfff68b7a), UINT64_C(0x808b81ab58a3c11e), UINT64_C(0x2003a1d79ee96e7e),
            UINT64_C(0x87b236e5742b42d7), UINT64_C(0x3a3610e8bad3b373), UINT64_C(0xb481ca092e54fd87), UINT64_C(0xaf8adee08b5326e7),
            UINT64_C(0x3ee2e6130ab53ef6), UINT64_C(0xbf7427af75a7c2d1), UINT64_C(0x4d7a6067dbeed20f), UINT64_C(0xcbdb5568d804ef3f),
            UINT64_C(0x508ff58236e7a6f9), UINT64_C(0xacf7eac3c3037dab), UINT64_C(0x482b277d6928bddc), UINT64_C(0x538974760ddc6f83),
            UINT64_C(0x6c3b990a1194ebe4), UINT64_C(0xeb3dfeda259aae19), UINT64_C(0x1043b1e32e6a609c), UINT64_C(0xe29853f3b731712a),
            UINT64_C(0x725474cd1469a035), UINT64_C(0x08cc37d08547e287), UINT64_C(0x0de8c6d9ae66fe36), UINT64_C(0xaaef7eb47eb75f52),
            UINT64_C(0xa29a69722b3bf66b), UINT64_C(0xd44d96ca50981b64), UINT64_C(0x0952a0827ec5b006), UINT64_C(0xaeced6c30c1fff4a),
            UINT64_C(0xcf8551b4584c0c46), UINT64_C(0x2611b04aafedc71c), UINT64_C(0xd927dc8e6de6164f), UINT64_C(0x1fd5e2029d572551),
            UINT64_C(0x45ad5bcd4bf72122), UINT64_C(0x54a3c4b12c343b21), UINT64_C(0x96156949c3f32a47), UINT64_C(0xa81023ef8e94e51b),
            UINT64_C(0x26d335efc1d4efde), UINT64_C(0x669c4846e9284067), UINT64_C(0xcabd41a53335f6e1), UINT64_C(0x4f517812e06a917f),
            UINT64_C(0xcdd989ce6aa55626), UINT64_C(0x5ca882c756fe4999), UINT64_C(0x639d8b99c6477c42), UINT64_C(0x2716a772911dca49),
            UINT64_C(0x4374400157dc3d13), UINT64_C(0x1d0a512182a280f5), UINT64_C(0xd822a4f87a0ad77c), UINT64_C(0x0a0ab212f142db2b),
            UINT64_C(0xe80fb8a935595883), UINT64_C(0x7568eec35a490b83), UINT64_C(0x09abdb9e114df5fc), UINT64_C(0x55137c447d1bca41),
            UINT64_C(0x0de593a7acafcc85), UINT64_C(0xb975febcee3ca728), UINT64_C(0x63bef68e44fea1d5), UINT64_C(0xb013be7092b2a894),
            UINT64_C(0xeba8c75d166e19d9), UINT64_C(0x224ad7936de628b9), UINT64_C(0x42b55663e6da91c0), UINT64_C(0x68f73c834d3b02a8),
            UINT64_C(0x0bd2a1b0f697dc42), UINT64_C(0x89fc577d065f571a), UINT64_C(0xdc714c2c16925d8d), UINT64_C(0x5f94692fe9a6b2eb),
        },
    },
// Level 3
    {
        UINT64_C(0x8370e3dd2dd7e740), UINT64_C(0x4ac7a23650afaa5d), UINT64_C(0x00000003c), 0, // sum of coeff and dummy
        {
            UINT64_C(0x141a416e635e3008), UINT64_C(0xe59e5696300fc54e), UINT64_C(0x3ac6afaf368cd3a6), UINT64_C(0x1c4d7641d7192768),
            UINT64_C(0xaae556230b19cb19), UINT64_C(0x09fe3e074ade9f7e), UINT64_C(0xcc11adbd55ed21af), UINT64_C(0x862d3632edce6066),
            UINT64_C(0x83200725a18ecf18), UINT64_C(0xef8a88f410ebfffa), UINT64_C(0x8f32ade56cc5cd11), UINT64_C(0x68601c8acb3b697b),
            UINT64_C(0x3f7bc460e435c5be), UINT64_C(0xead87aaff097bf77), UINT64_C(0x5d35b160f1047863), UINT64_C(0x3c7c707d1decebe3),
            UINT64_C(0xffab7fcb4b288977), UINT64_C(0xbb30bf67ea8078d4), UINT64_C(0x08c14f33079c0375), UINT64_C(0xc34be6df85f4e084),
            UINT64_C(0xc5d61545239490a8), UINT64_C(0xc206111b5df05780), UINT64_C(0xb40b9d277b5eb1a6), UINT64_C(0x61f772ed20991bd7),
            UINT64_C(0xa423cf9ee644f9b9), UINT64_C(0x63a281c7fb30afbe), UINT64_C(0x33dd3deb21ee47f3), UINT64_C(0x3d882a465f6520e0),
            UINT64_C(0xd8f44673c67ff2c6), UINT64_C(0x159cafea157a4f90), UINT64_C(0x38a18e681a48e2a0), UINT64_C(0xb9ebf2a06fe035b4),
            UINT64_C(0xdd504b49fd3e67bb), UINT64_C(0xae67fb542747c488), UINT64_C(0x7416c312f3387e02), UINT64_C(0xa5bebc6a0bc34dd0),
            UINT64_C(0x89a98f212c21c94a), UINT64_C(0xd377d8c55c6c78c8), UINT64_C(0x23f194d2e59b81d0), UINT64_C(0xc0efd26a5d0ed051),
            UINT64_C(0x0112146515113ef8), UINT64_C(0x2031a3cd82ce8702), UINT64_C(0x7ec8e3c87ce50a07), UINT64_C(0x47a142fc6fcd89c7),
            UINT64_C(0x2bcb63e57f0cae2f), UINT64_C(0x8664c6f962a87b24), UINT64_C(0xe6d174ff007b2c34), UINT64_C(0x87e09c902d073b32),
            UINT64_C(0xb543d64ed7dfb009), UINT64_C(0x7c31c340b3dae313), UINT64_C(0x562ba6cf0b4713cc), UINT64_C(0x957f23822221316e),
            UINT64_C(0x9612164e43a7d75e), UINT64_C(0x66088836498298a7), UINT64_C(0x2277a69befc583cd), UINT64_C(0xc6a74c6baecd220d),
            UINT64_C(0xc3df4a454eaf882f), UINT64_C(0x4c70af7cee8f0bbc), UINT64_C(0x2ba3590fd97517d4), UINT64_C(0xbb00a28e752d346c),
            UINT64_C(0xebfa174a39681974), UINT64_C(0x033d8678eca2890b), UINT64_C(0xede2c5142f49827c), UINT64_C(0x614d56f55dde9f8b),
            UINT64_C(0x72e2e9d5582a0a08), UINT64_C(0x9d1f6238ddac882b), UINT64_C(0xfcd3682c3bd70286), UINT64_C(0x8958816740699ee2),
            UINT64_C(0xa5c7a3559d07b917), UINT64_C(0x4d8e82254c5a70e4), UINT64_C(0x291f69d4c89e5c45), UINT64_C(0x9c94a14902c4b249),
            UINT64_C(0xd9bcf68e0f055258), UINT64_C(0x3a0cc6dcfffd05b7), UINT64_C(0xf0a22a2d6b06d03a), UINT64_C(0xeb9a2918852926aa),
            UINT64_C(0x37915f797a6675f7), UINT64_C(0x98cdbb4e1686b742), UINT64_C(0x7007270bff4fcbe1), UINT64_C(0xc458d4068dc6c70f),
            UINT64_C(0x073bbe0965ce93f3), UINT64_C(0xe7f2df0297e091e6), UINT64_C(0x3bf1a925fb9e6d1c), UINT64_C(0x48af31eef7b34f4b),
            UINT64_C(0x00e92e127962fa5e), UINT64_C(0x0f8fc920466f3cd3), UINT64_C(0x25a21a02222a64b5), UINT64_C(0xb9853aa495decb46),
            UINT64_C(0x262dc131bb0c35bb), UINT64_C(0xaf519c96fb0e9f68), UINT64_C(0x755849eedbb94ff2), UINT64_C(0x13a3d660e45f77b0),
            UINT64_C(0x9f5d4268c5d69a64), UINT64_C(0x8c8a5e806938377c), UINT64_C(0x5bd34bfb54b64524), UINT64_C(0x6b5f1db574ecfaa9),
            UINT64_C(0x37f725e56c1e9dc3), UINT64_C(0xc7fe10ac9904f90f), UINT64_C(0x879ae4eff04c0ab8), UINT64_C(0x76aea0675622e495),
            UINT64_C(0xe29e3a0ebbe40dba), UINT64_C(0x157ffad6ff36b56f), UINT64_C(0x5466d89bca624434), UINT64_C(0x5449470d65bc5b35),
            UINT64_C(0x7f6c99db52e6348a), UINT64_C(0x776d4dff2abd85c7), UINT64_C(0xb010a7f1beffcc1a), UINT64_C(0xad74603f4c6d9ab6),
            UINT64_C(0x0599c30e3b018f16), UINT64_C(0x127a45fdeef28abd), UINT64_C(0x4cf790e8928575a0), UINT64_C(0x58fa1edd4caa9a51),
            UINT64_C(0x5f3e8dd37e04eb51), UINT64_C(0xac131e1aea11807f), UINT64_C(0xf46fd7f990fb8cca), UINT64_C(0x73963b93ad4b9bb2),
            UINT64_C(0x004c15e2478e8c36), UINT64_C(0xc79d966848c52c68), UINT64_C(0x827091c5d5309f35), UINT64_C(0x8e6290b4ecb7be34),
            UINT64_C(0x4a2a701831915090), UINT64_C(0xb9ed682c26ae8721), UINT64_C(0x06c94a32c3f063b5), UINT64_C(0x11946415f289d8b4),
            UINT64_C(0x4e6d4a3b505cd181), UINT64_C(0x7ad8e06beddabbeb), UINT64_C(0x272e050758ccfa94), UINT64_C(0x1a38a7703463de87),
        },
    },
// Level 4
    {
        UINT64_C(0x7c024d493240fd81), UINT64_C(0xcbedce790be4d6b), UINT64_C(0x000000041), 0, // sum of coeff and dummy
        {
            UINT64_C(0xc385e890cdafa370), UINT64_C(0x72af2ae52cda3c0c), UINT64_C(0x377cc48ad117edce), UINT64_C(0xf3724d905f5cdc46),
            UINT64_C(0xf51e0db646e04641), UINT64_C(0xb3ef041173b95e50), UINT64_C(0x483d8f190412d741), UINT64_C(0x9565fe70636fe7d1),
            UINT64_C(0x7b5497f93bca30f2), UINT64_C(0xf7aa697c1f31e835), UINT64_C(0x26b9b332c5097919), UINT64_C(0x609c027c0e94be94),
            UINT64_C(0xa4a77bf651dff968), UINT64_C(0xd3e952f9477aa964), UINT64_C(0xb6eb6ba84eafa8c3), UINT64_C(0xecc3cb66b4f9e264),
            UINT64_C(0x6f7de149b48c42d2), UINT64_C(0xef38e08b77c94c8b), UINT64_C(0xd6a178affe73a087), UINT64_C(0xba01cfe6a8b0bfaf),
            UINT64_C(0x771821ab27b1d361), UINT64_C(0x7b5e6b3e68a80c08), UINT64_C(0xd53c33bab8faf82f), UINT64_C(0x81e128821c9b5835),
            UINT64_C(0x6968851cd767ecb8), UINT64_C(0x539510f090361d02), UINT64_C(0xee243a481fed197e), UINT64_C(0x57a7a6f5c2d4a423),
            UINT64_C(0x7afc981eebfd0da8), UINT64_C(0xca100d08037f88e1), UINT64_C(0x7caf7e30e051e2f3), UINT64_C(0x09c6f692bb7e0c5e),
            UINT64_C(0xff97c9f9213491a7), UINT64_C(0x3c7f06f4da8b68a8), UINT64_C(0xcc22969e12b0c521), UINT64_C(0xd3c246d637dc486c),
            UINT64_C(0x645c098f230c482c), UINT64_C(0x7be14df33d02c990), UINT64_C(0xea99f1bc32cc189f), UINT64_C(0x8b776c2437b66a29),
            UINT64_C(0xb6975830b26d1bcb), UINT64_C(0x3c24c07fb12dedfb), UINT64_C(0x939403d4624cb460), UINT64_C(0x0b4f454217f1f947),
            UINT64_C(0x1ba0c284e2ac36c2), UINT64_C(0x25cfdc661fa02193), UINT64_C(0x661dc556bc51ede9), UINT64_C(0x8e4e8f1996c5b04f),
            UINT64_C(0x6196e065ebbfc052), UINT64_C(0xbc1f2b573fcaf323), UINT64_C(0x74b0be15966126bc), UINT64_C(0xb61922dc3648b491),
            UINT64_C(0x7528e5507af25415), UINT64_C(0xa03fee7cecbf5a92), UINT64_C(0x28f080a17abcdbf4), UINT64_C(0xf558e58265b50247),
            UINT64_C(0x48946bc6b781b231), UINT64_C(0x1d3f9268ece51d01), UINT64_C(0x64cfd592583cd6d1), UINT64_C(0x33227252dde03dcc),
            UINT64_C(0xfe487eba451edd0e), UINT64_C(0x1554136d4e0da4f8), UINT64_C(0x5446eb38aa369ed4), UINT64_C(0x5b46c4ce910d2ab6),
            UINT64_C(0x5ca4f4ee4346e6f3), UINT64_C(0xb8a0111cf306801f), UINT64_C(0x4f96aae6581da78e), UINT64_C(0x6245d9523980b137),
            UINT64_C(0x5e6efad77dd317ba), UINT64_C(0x7eb8de8eb617c7f4), UINT64_C(0x84e4d9ed06dce648), UINT64_C(0x24ed663bd6ce99fd),
            UINT64_C(0xdf0ba8713d3bd076), UINT64_C(0xc11063b88172e67a), UINT64_C(0xb173e8e756868535), UINT64_C(0x6f9b72467e93008f),
            UINT64_C(0x0c7ab90fa88aa8b2), UINT64_C(0x3deb22d963a56bcf), UINT64_C(0xa56348ee35314bb8), UINT64_C(0x9881a7a2129cebdb),
            UINT64_C(0xc160ec1b18ecaeb6), UINT64_C(0x358f2bd362310528), UINT64_C(0xa92ccae5ed750d12), UINT64_C(0xdce6d5d94a23845d),
            UINT64_C(0xf50e3e4e30ac79f4), UINT64_C(0x308e35ff0a5c199f), UINT64_C(0x9843f1db5c0f0066), UINT64_C(0x21e31f7ea490ff33),
            UINT64_C(0x180b0bd32ae3dc81), UINT64_C(0x64067fc5626d1cd9), UINT64_C(0x10803e502f4b4eef), UINT64_C(0x64f3d35137338ceb),
            UINT64_C(0x12f3445e0c9d7641), UINT64_C(0x7be6720939744b5c), UINT64_C(0xe85e4cc174c166e2), UINT64_C(0x9468eb4ab9946aed),
            UINT64_C(0xa8bb2b2d4df63a32), UINT64_C(0xb2f95c382e934037), UINT64_C(0x3e902ed369fbbb44), UINT64_C(0x185a9eade1869dd0),
            UINT64_C(0xd240a5734d051bf1), UINT64_C(0x92faec8652bea745), UINT64_C(0x8996ab0aec688aba), UINT64_C(0xbcac5f2824c8daef),
            UINT64_C(0x5881daacfc329969), UINT64_C(0x55364eaf990b3b21), UINT64_C(0xe5de0bd0d06f1120), UINT64_C(0xd6a6fb94a44fbf1a),
            UINT64_C(0x4e10e2dcf9e9aa49), UINT64_C(0xfe401a3e5cdb41ae), UINT64_C(0x81a4db50e11a295f), UINT64_C(0xfcc87dd6a04da032),
            UINT64_C(0x6c5f6fa90c36ccb6), UINT64_C(0xf7fa702ef53bd5bd), UINT64_C(0x37345651f635ded5), UINT64_C(0x9650ac0acc8b0f11),
            UINT64_C(0xfb1fc5e6a46f6c48), UINT64_C(0x75fbd67a4f588024), UINT64_C(0xbcf48525891fbf4e), UINT64_C(0x076fdfe68cb57efc),
            UINT64_C(0x9ff4fdeb562abe4d), UINT64_C(0x363686dcec66ee6f), UINT64_C(0x3ed3c65e6660e857), UINT64_C(0x555629fb07677f9c),
            UINT64_C(0x0b9e59e5e2dc63f0), UINT64_C(0x3dd204d3c272f8e8), UINT64_C(0x0a5e2bc12753cc6f), UINT64_C(0x261571527dae8627),
        },
    },
// Level 5
    {
        UINT64_C(0x742b91e91dcfb0a6), UINT64_C(0xcfeca6a967921914), UINT64_C(0x00000003c), 0, // sum of coeff and dummy
        {
            UINT64_C(0x6edee5be930ba5a3), UINT64_C(0x7da756c8a9d5865f), UINT64_C(0x979d7286e9ec6a3a), UINT64_C(0xb5f53e73c1075910),
            UINT64_C(0xac17c48f4a6369d1), UINT64_C(0xe59c869b50f242b8), UINT64_C(0xd82f2c4debbd7a92), UINT64_C(0x2f480ab7fcef8c2a),
            UINT64_C(0x5455617627c7967c), UINT64_C(0x391f4653479cd148), UINT64_C(0x93816a1fe3fe659f), UINT64_C(0x750610cc458f0e83),
            UINT64_C(0xaea9ec84538ba181), UINT64_C(0x07f69ef23331d201), UINT64_C(0x1154b8671a7e21a6), UINT64_C(0x44f2b2a5e705dccd),
            UINT64_C(0xf4137114642bd756), UINT64_C(0x0d9fdd5c26862aa0), UINT64_C(0x24252072220e87e6), UINT64_C(0x40c56b66c01c20f4),
            UINT64_C(0x3d1246932d66f5fb), UINT64_C(0x549be143f5ad841a), UINT64_C(0xf5a694fd849975f9), UINT64_C(0xab3a75807839e2ae),
            UINT64_C(0xdbc151ec40a63d29), UINT64_C(0x252d86d9b6ff7885), UINT64_C(0xd848fb1e2a170064), UINT64_C(0x8dbfbaa7e285d213),
            UINT64_C(0x48c5c1a431e6a390), UINT64_C(0x4ea411a44607dc21), UINT64_C(0xbb8535f2c692910e), UINT64_C(0x6d8c5388d2aed8b2),
            UINT64_C(0x2fddc57f1a7b1cc8), UINT64_C(0x3a2c8bd7ea3f25ab), UINT64_C(0x87708e34be0fb414), UINT64_C(0x8543e5d4e9f7c34e),
            UINT64_C(0x2c349130b9d62f31), UINT64_C(0x8589d21285426c0c), UINT64_C(0x5b2a39baebaad52f), UINT64_C(0x03f8700c91cd5413),
            UINT64_C(0xcc00c06be9d784fb), UINT64_C(0x70a78056b4c5b930), UINT64_C(0x4a2aa9811bbd47a3), UINT64_C(0x4a878b1e922c6304),
            UINT64_C(0x2443f15ef107a70f), UINT64_C(0xf64b29a8f4069376), UINT64_C(0xfc309fa9086da268), UINT64_C(0xffeedab78f765ff4),
            UINT64_C(0xa99a216b423fac77), UINT64_C(0x3b9c309929d6991e), UINT64_C(0x113fe1aa6ba4c211), UINT64_C(0x2f214dea6f758f36),
            UINT64_C(0x519806a4ba5b5ca8), UINT64_C(0xef203bc2948dda9e), UINT64_C(0xaa83a59110f3a193), UINT64_C(0xebdef286170eb7ef),
            UINT64_C(0x9bd44760cd090ead), UINT64_C(0x234b9dde9fd14ab3), UINT64_C(0xee6e9c107305b2f4), UINT64_C(0x5eae7639d8a2b0ab),
            UINT64_C(0x63d30ff6c83a7320), UINT64_C(0x3ded1e0f42fa1cb2), UINT64_C(0xd386b3b3b19d708e), UINT64_C(0x34d5016669fe449a),
            UINT64_C(0xb9f91d66682b7278), UINT64_C(0x817659853e4e435e), UINT64_C(0xfc2e6483c3048759), UINT64_C(0xb261e03ffbd9519e),
            UINT64_C(0xb49de284f5cf5d02), UINT64_C(0x02387c87bbbf7445), UINT64_C(0x6d937def7be53a83), UINT64_C(0x08526f8ae49dbd0f),
            UINT64_C(0x615ef3f5af7fd5ab), UINT64_C(0x54cb4d9e528c1d79), UINT64_C(0x3cb713ba05a67835), UINT64_C(0xf592fb2d4d2af2db),
            UINT64_C(0x86ec6601e42b2456), UINT64_C(0x0e857a59e7439d0d), UINT64_C(0x8326414cd1f6874f), UINT64_C(0xa92dad5f5d9a106a),
            UINT64_C(0x58793e150f7ff874), UINT64_C(0x519bc1ed4913c3c5), UINT64_C(0x4f3b0da10be83d82), UINT64_C(0xd82c561b6f18a264),
            UINT64_C(0xa47f8878009a1815), UINT64_C(0x0673feb8c6083dd6), UINT64_C(0x343ac4c37efb4d08), UINT64_C(0x4847b3364092fa4a),
            UINT64_C(0x1a30098e32c503a0), UINT64_C(0x7f242c4cb083e69b), UINT64_C(0x08e69e6c3b1070ec), UINT64_C(0x0711fa2b404a9684),
            UINT64_C(0xfc24e0a982ae39fa), UINT64_C(0x02ff5ca0bd974db5), UINT64_C(0x2777845db37d0e98), UINT64_C(0x5555b5942327e543),
            UINT64_C(0x7717c93942df84b7), UINT64_C(0x2a661b86ad2dcdde), UINT64_C(0x61c93d7746664b20), UINT64_C(0x514090cc1a87d06b),
            UINT64_C(0x7aa2f5f8bcf987ad), UINT64_C(0x2898047ec7fa8778), UINT64_C(0xe5cf2d9a08d8927c), UINT64_C(0xecde6d34e5c3fe5a),
            UINT64_C(0x5589c848adaebaf8), UINT64_C(0xedac4b9343975aa2), UINT64_C(0x48503cf321ad26b2), UINT64_C(0x4e7f1530c16f8941),
            UINT64_C(0x6a9fe4e56715fa4e), UINT64_C(0xefa9aec821c89e4b), UINT64_C(0xc23b542018927c97), UINT64_C(0xeedb11ae93481c6f),
            UINT64_C(0x35f45dab8618f030), UINT64_C(0x2a5eb24e550fcb99), UINT64_C(0x5c6d2d61242cf3a8), UINT64_C(0x96058fee3f9becb0),
            UINT64_C(0x811ed70d6e6cd756), UINT64_C(0x93642e8381c4a6a0), UINT64_C(0xc81e05bef85ad62b), UINT64_C(0xd12ce5cee02edeae),
            UINT64_C(0x0a00b676c5f25868), UINT64_C(0xc5c91383914e9732), UINT64_C(0xd9e4fbd6c7a78695), UINT64_C(0x24741bcd3aab63f3),
            UINT64_C(0xa86f85bc7932add8), UINT64_C(0xd851daaea4ade651), UINT64_C(0xc1b2a4b765bd4ee2), UINT64_C(0xd648f4971ef524f7),
        },
    },
// Level 6
    {
        UINT64_C(0xaf62ce594afbb378), UINT64_C(0x248e65d01cba3e0b), UINT64_C(0x00000003f), 0, // sum of coeff and dummy
        {
            UINT64_C(0x6ce36b80768d6e7f), UINT64_C(0xa397920aa6626e5a), UINT64_C(0x04de32bd5633745d), UINT64_C(0xe699be0bb8411b1f),
            UINT64_C(0xd06b3da1042ffeff), UINT64_C(0xc8c12f5678dbc1fe), UINT64_C(0x5f1c5df4786ec543), UINT64_C(0xc64eed21fe2dab71),
            UINT64_C(0x43083efd3ab83bc9), UINT64_C(0xfbd27f38b364bb80), UINT64_C(0x948701fc4ed5f457), UINT64_C(0xb26d9d8304db31a5),
            UINT64_C(0x18ec7952e4e525a9), UINT64_C(0x0a81dbd330204a9d), UINT64_C(0x033c520def3d2101), UINT64_C(0x73a6c045c701aadd),
            UINT64_C(0xd7d19f80a027afec), UINT64_C(0x8bf3f0c57c2fe429), UINT64_C(0xb8344463c59719e3), UINT64_C(0xf76ffe54b2fd1d64),
            UINT64_C(0xf3358f8c810dda81), UINT64_C(0x8049af80eb93f21f), UINT64_C(0x5ff59a51e9dafd79), UINT64_C(0xb3f6e7835814a5e9),
            UINT64_C(0xbd127322c2e4b16c), UINT64_C(0x7bc601b6ef92afa3), UINT64_C(0x00b5e1e97c28a598), UINT64_C(0x38d94a15139b608e),
            UINT64_C(0x39737d09f0035403), UINT64_C(0x65337848d976c3a2), UINT64_C(0x91c04f2a6a9ec21f), UINT64_C(0x02548b83235c115f),
            UINT64_C(0x430e4ec854acc042), UINT64_C(0x0b0d27ee05bcd498), UINT64_C(0xf669534441242d11), UINT64_C(0x02cbaa107829c390),
            UINT64_C(0x35b4d683817b903c), UINT64_C(0x31834f7142d5cfa0), UINT64_C(0x77fd19567cb1ffea), UINT64_C(0x0911558876310281),
            UINT64_C(0xeaaef1c301d92167), UINT64_C(0xf1c746401671b4d3), UINT64_C(0x7d1888c23b2447e9), UINT64_C(0x72c44c19bde5d380),
            UINT64_C(0x7a6156a99377bf58), UINT64_C(0xeafd8cb3722b6aa4), UINT64_C(0xa4b21df76c4ae4a6), UINT64_C(0xa612df347cb132bf),
            UINT64_C(0x2f8331da53e4651f), UINT64_C(0x498baa43072061aa), UINT64_C(0x669cd34bdf522223), UINT64_C(0x611a32f117b489e3),
            UINT64_C(0xb1d08c016e277a67), UINT64_C(0xb1d4d0937395b21f), UINT64_C(0x9d3e7447db71fd3d), UINT64_C(0x8d61714b54616249),
            UINT64_C(0x91cfe6cad3939afb), UINT64_C(0x785efcfc1fbed3f8), UINT64_C(0xc7270e86e752b71a), UINT64_C(0xe91bc93a14e678c4),
            UINT64_C(0x9bf095b9662cf95d), UINT64_C(0xa82d8d1309df2256), UINT64_C(0x41abc3fa674c6a06), UINT64_C(0x0e38a88b0398547e),
            UINT64_C(0x6fe82427e8c24696), UINT64_C(0x0f20ed4a9e8e02c2), UINT64_C(0x5df70b3c4784b7e1), UINT64_C(0x000b2deddde9963c),
            UINT64_C(0xc8929e6367803b53), UINT64_C(0xb28033a4c174c86d), UINT64_C(0x3a666b4c18406801), UINT64_C(0xbd8b5791ba056136),
            UINT64_C(0x715ed0ae7c79e816), UINT64_C(0x577c1b256c64436a), UINT64_C(0x54a4f8d1b535e02d), UINT64_C(0xc8d7f16769d38240),
            UINT64_C(0xb707839b15b0d3fc), UINT64_C(0x255def6be6755b91), UINT64_C(0x9bb54bbffd57d21f), UINT64_C(0xd882bcc3caa155e7),
            UINT64_C(0x32706a042f57ab60), UINT64_C(0xf2f38aa7f8c31e8b), UINT64_C(0xa1e84cfff8dc3cae), UINT64_C(0xa703b9fc24c2e1db),
            UINT64_C(0x8c3bd99cdd77d160), UINT64_C(0x4d4692d129444836), UINT64_C(0xef4b1c7cd501fd7d), UINT64_C(0xde07e34df48421ab),
            UINT64_C(0xae4083dd864c910d), UINT64_C(0xfa4ba5e1a2d58460), UINT64_C(0x6f0068aa4e75a5ec), UINT64_C(0x0a9e07133b5a2abe),
            UINT64_C(0x337739bfa36cecc8), UINT64_C(0xe3591f5cc97b787c), UINT64_C(0xf2bbe16b3ec41399), UINT64_C(0xf3dcc6246a758716),
            UINT64_C(0xc73351933e7e2417), UINT64_C(0x0e1f947d867b0bdd), UINT64_C(0xe48bf8efb1f572a0), UINT64_C(0xd5b209d89f09fa2a),
            UINT64_C(0x27478ae42843f9f1), UINT64_C(0x01b30ed80db664a5), UINT64_C(0x0181e5ed5e84cd8b), UINT64_C(0xf6318c19349acefb),
            UINT64_C(0x69c8492982778f4b), UINT64_C(0x4af6702966bca750), UINT64_C(0xa8b4d353631e2482), UINT64_C(0x5ce04a70f584d238),
            UINT64_C(0xfbf5b2cdc0394772), UINT64_C(0x104d44c77b80b6ae), UINT64_C(0xbe8e5a49d6ee3335), UINT64_C(0x5bf8f3f9a05f36f9),
            UINT64_C(0x4be7aeb57af4a56a), UINT64_C(0xa09e9cd11d6ef9a7), UINT64_C(0x091ecc28674a929a), UINT64_C(0xad2c90bc1f89d87f),
            UINT64_C(0xbf25df5f95456364), UINT64_C(0x7b104f2289b28c07), UINT64_C(0x902272c148ddc16d), UINT64_C(0x3285c7b614a096f3),
            UINT64_C(0x6491973c285a2f0f), UINT64_C(0x31f84ba2ce5e3755), UINT64_C(0x3300c615947fd40c), UINT64_C(0x3c4747adf437f115),
            UINT64_C(0x04fa56d556527742), UINT64_C(0xd7b45d6644b42059), UINT64_C(0x4cdea756d6091a28), UINT64_C(0x2431ed986745785b),
        },
    },
// Level 7
    {
        UINT64_C(0x1249b1f513689151), UINT64_C(0xc658fcfbfabe77d5), UINT64_C(0x000000042), 0, // sum of coeff and dummy
        {
            UINT64_C(0xabaaefde77273dcd), UINT64_C(0xe737f9d4fba6ee5b), UINT64_C(0xc2c8521e524e50e7), UINT64_C(0xb6347dd4ecff2e08),
            UINT64_C(0x81cc14e56b826c78), UINT64_C(0x7e96733438db219f), UINT64_C(0x93f66e8959ad9a5d), UINT64_C(0xad77e6ffafdfa01b),
            UINT64_C(0x79842c77afd94c9a), UINT64_C(0xb2fe351094030a32), UINT64_C(0x04f00838dc236276), UINT64_C(0x1064827c937cd78b),
            UINT64_C(0xa914296fc9de0469), UINT64_C(0x4a87b2d1971b2b6e), UINT64_C(0x1ef28858c6e99de6), UINT64_C(0x23429a77bea42f46),
            UINT64_C(0xf771817be7a38b16), UINT64_C(0xcc348f7a13deb19a), UINT64_C(0x0a91d46fb1ae97e8), UINT64_C(0x753cdb5468c83c10),
            UINT64_C(0x65cc613edbcd3f84), UINT64_C(0xcb157fac042d9ab2), UINT64_C(0x18e6a31aed525487), UINT64_C(0x5924230b1281b56d),
            UINT64_C(0xb828c042782945ba), UINT64_C(0x2decd50526005abe), UINT64_C(0x05caa6f761c5857a), UINT64_C(0x4c93892d66de5320),
            UINT64_C(0xac796b30f48a75b3), UINT64_C(0xe11728c76eab1822), UINT64_C(0xa59ec090b0f3ed2e), UINT64_C(0xada9c2e74edc137b),
            UINT64_C(0x4ca60d77ed9f8e0d), UINT64_C(0x6304a44de4bc4219), UINT64_C(0x361436da34a05f49), UINT64_C(0x097fcaec609fd08f),
            UINT64_C(0xf9f9ae511316dcce), UINT64_C(0xa62ca6c22fa94122), UINT64_C(0xb32ebc94594cf9c8), UINT64_C(0x1b673219068f53f7),
            UINT64_C(0x28a8f7de358ea82b), UINT64_C(0x7d3e002bee6f572f), UINT64_C(0xbe24c789f9ddb580), UINT64_C(0x0257b24167d83acd),
            UINT64_C(0x5651f9ac1cfa5113), UINT64_C(0x225aaaa55c5d72d4), UINT64_C(0x1bb9759abf1d08b0), UINT64_C(0x7c36896386d4f50c),
            UINT64_C(0xdd4ceaf465f970eb), UINT64_C(0xf349d378bfd4beb9), UINT64_C(0xf2d9ea03c79109d8), UINT64_C(0xe915c84fab4efd66),
            UINT64_C(0xe401bb6a403813b6), UINT64_C(0x2171265710c01426), UINT64_C(0x6542b43cba6a4d08), UINT64_C(0x58591c6e1250104f),
            UINT64_C(0x77bc044ed6c4a7a0), UINT64_C(0x73b1a5f682fd2d52), UINT64_C(0x6c2b7083b26b9976), UINT64_C(0xf9e3b1347ceaaaca),
            UINT64_C(0xa709263b9c304a96), UINT64_C(0x6c6fedc1e78481dc), UINT64_C(0xbec268cc818190e0), UINT64_C(0xbafa9271d75b733b),
            UINT64_C(0xeace12cbb37fc677), UINT64_C(0x1176816b69b51d98), UINT64_C(0x62d28bbf94c2762d), UINT64_C(0x142b7d89bcc06043),
            UINT64_C(0x8e166c13e205cc00), UINT64_C(0xac3dcf9c75177f8e), UINT64_C(0xc75695f82b7f6c46), UINT64_C(0xdff44c46fe5e7b6d),
            UINT64_C(0x932846955828d471), UINT64_C(0x7593c5e733dca4d6), UINT64_C(0xf1efc8ad9718ca14), UINT64_C(0x93a618cb5b6aff34),
            UINT64_C(0x1d89f5253c2f819f), UINT64_C(0x419744eb9c63d0b2), UINT64_C(0x2b07ff7747ed7c29), UINT64_C(0x617be6e4454749a0),
            UINT64_C(0xaa24d8e4142c5bf4), UINT64_C(0xe25d6c2fe999691d), UINT64_C(0xf78965d974e8e076), UINT64_C(0x8e6203aa0037ae8e),
            UINT64_C(0x732c3a3a561c6d79), UINT64_C(0xd61a9622b0da5c93), UINT64_C(0xfc1c73c6152a141b), UINT64_C(0x03a4694838529e5b),
            UINT64_C(0x686cb297afba7101), UINT64_C(0xbee9f55d5260fbe2), UINT64_C(0xd53a374387aa4f2a), UINT64_C(0xc6b2494c1a96d781),
            UINT64_C(0xbe8aa945ac411c10), UINT64_C(0xbfc814fa4da90048), UINT64_C(0xb46847e8ecaca5f4), UINT64_C(0x83466ccfb2037365),
            UINT64_C(0x39bfd895a4917200), UINT64_C(0xfd6106ab889f9c14), UINT64_C(0x87d80fcd94875b38), UINT64_C(0xd05a5e75bdd29067),
            UINT64_C(0xc8fbbb4d3e850e9d), UINT64_C(0xef2dc9eb5228f1ae), UINT64_C(0xc3775c3e9ac4da44), UINT64_C(0x12004ef1609624ed),
            UINT64_C(0x43ec24f8c096ee25), UINT64_C(0xeb207061723522ad), UINT64_C(0xbd3767314ad773e4), UINT64_C(0x4b2059a2964d28f4),
            UINT64_C(0xcd4522a02ed66868), UINT64_C(0x74c6b45b4b5b5657), UINT64_C(0x48bcc161232e14b1), UINT64_C(0x958c3b741a54bd75),
            UINT64_C(0x2f64940639fedc7d), UINT64_C(0xc1321efa1c279cc3), UINT64_C(0x0680b3866e485f15), UINT64_C(0x5633b30c0c7c4a96),
            UINT64_C(0xb5c9b8539fa9ea3c), UINT64_C(0x1fd67c7175c87172), UINT64_C(0xe03ed40e88bcdf23), UINT64_C(0x81a69e0147fbb776),
            UINT64_C(0x244e2bf676590e87), UINT64_C(0x8a86357137c0d611), UINT64_C(0x4fcaad51eba3720f), UINT64_C(0x2b8b7b933f76e019),
            UINT64_C(0xecff900b265d06f4), UINT64_C(0xbc3b359d2e438bbc), UINT64_C(0x086c671b288776d9), UINT64_C(0x652c4a2d18d847ba),
        },
    },
};
// STATIC_ASSERT(PMPML_64_LEVELS <= 8, "Only 8 levels of data currently exist");

//-------------------------------------------------------------
// Common math routines

static inline uint32_t fmix32_short( uint32_t h ) {
    h ^= h >> 13;
    h *= 0xab3be54f;
    h ^= h >> 16;

    return h;
}

static inline uint64_t fmix64_short( uint64_t k ) {
    k ^= k >> 33;
    k *= UINT64_C(0xc4ceb9fe1a85ec53);
    k ^= k >> 33;

    return k;
}

#define UInt32x32To64(a, b) ((uint64_t)(((uint64_t)((uint32_t)(a))) * ((uint32_t)(b))))

//-------------------------------------------------------------
// 32-bit hash

static inline
void multiply32x32to64( uint32_t & rhi, uint32_t & rlo, uint32_t a, uint32_t b ) {
    MathMult::mult32_64(rlo, rhi, a, b);
}

static inline
void add64( uint32_t & loWord, uint32_t & hiWord, uint32_t & hhWord, uint32_t & loAdd, uint32_t & hiAdd, uint32_t & hhAdd ) {
    MathMult::add96(loWord, hiWord, hhWord, loAdd, hiAdd, hhAdd);
}

static FORCE_INLINE
void mul32x32to64addto96( uint32_t & loWord, uint32_t & hiWord, uint32_t & hhWord, uint32_t a, uint32_t b ) {
    MathMult::fma32_96(loWord, hiWord, hhWord, a, b);
}

#define PMPML_CHUNK_LOOP_INTRO_L0 \
	uint32_t ctr;             \
	ctr = 0;                  \
	ULARGE_INTEGER__XX mul;

// Input data is read in 32-bit chunks.
#define PMPML_CHUNK_LOOP_BODY_ULI_T1( i )                                                 \
    /*multiply32x32to64(mul.HighPart, mul.LowPart, x[i], coeff[ i ]);                     \
    add64(constTerm.LowPart, constTerm.HighPart, ctr, mul.LowPart, mul.HighPart, zero);*/ \
  mul32x32to64addto96(constTerm.LowPart, constTerm.HighPart, ctr, GET_U32<bswap>((const uint8_t*)x, (i)*sizeof(x[0])), coeff[ i ]);

// Hash data from previous blocks is read in 64-bit chunks, and always
// in native endian format.
#define PMPML_CHUNK_LOOP_BODY_ULI_T1_64( i )                                              \
    /*multiply32x32to64(mul.HighPart, mul.LowPart, x[i], coeff[ i ]);                     \
    add64(constTerm.LowPart, constTerm.HighPart, ctr, mul.LowPart, mul.HighPart, zero);*/ \
  mul32x32to64addto96(constTerm.LowPart, constTerm.HighPart, ctr, GET_U64<false>((const uint8_t*)x, (i)*sizeof(x[0])), coeff[ i ]);

#define PMPML_CHUNK_LOOP_BODY_ULI_T1_LAST                                                  \
    /*multiply32x32to64(mul.HighPart, mul.LowPart, xLast, coeff[ size ]);                  \
	add64(constTerm.LowPart, constTerm.HighPart, ctr, mul.LowPart, mul.HighPart);*/        \
    mul32x32to64addto96(constTerm.LowPart, constTerm.HighPart, ctr, xLast, coeff[ size ]); \

#define PMPML_CHUNK_LOOP_PRE_REDUCE_L0

/*
 #define PMPML_MOD_2_32_PLUS_15( x, y ) \
 *  x = (uint32_t)x + UINT64_C(0xF000000E1) - (( (uint64_t)x >> 32 ) << 4) + ( x >> 32 ); \
 *  y = (uint32_t)x; \
 *  y -= ((uint32_t)(x >> 32 )) * 15; \
 *  if ( y < 0 ) y += PMPML_MAIN_PRIME; // y += PMPML_MAIN_PRIME * ( y < 0 );
 */

#define PMPML_CHUNK_REDUCE_96_TO_64

#define PMPML_CHUNK_REDUCE_64_TO_32                       \
{                                                         \
	uint32_t lo, hi;                                      \
	multiply32x32to64(hi, lo, constTerm.HighPart, 15);    \
	uint32_t part = ctr * 225 + (hi << 4) - hi + 15;      \
	constTerm.LowPart += part;                            \
	constTerm.HighPart = 1 + (constTerm.LowPart < part);  \
	constTerm.HighPart -= (constTerm.LowPart < lo);       \
	constTerm.LowPart -= lo;                              \
	if ( likely( constTerm.LowPart >= 30) ) {             \
        constTerm.LowPart -= constTerm.HighPart * 15;     \
        constTerm.HighPart = 0;                           \
    } else {                                              \
		if ( constTerm.HighPart )  {                      \
			constTerm.LowPart -= constTerm.HighPart * 15; \
			constTerm.HighPart = 1;                       \
			if ( likely( constTerm.LowPart >= 15)) {      \
                constTerm.LowPart -= 15;                  \
                constTerm.HighPart = 0;                   \
            } else {                                      \
				constTerm.LowPart -= 15;                  \
				constTerm.HighPart = 0;                   \
			}                                             \
		}                                                 \
	}                                                     \
}

#define PMPML_FULL_REDUCE_MOD_2_32_PLUS_15_AND_RETURN \
	PMPML_CHUNK_REDUCE_96_TO_64                       \
	PMPML_CHUNK_REDUCE_64_TO_32                       \
	return constTerm.QuadPart;

#define PMPML_FULL_REDUCE_MOD_2_32_PLUS_15_AND_RETURN_RETURN_32x32_ONLY                              \
    {                                                                                                \
	constTerm.QuadPart = constTerm.LowPart + PMPML_MAIN_PRIME - constTerm.HighPart * UINT64_C( 15 ); \
	if ( likely( constTerm.LowPart >= 30) ) {                                                        \
        constTerm.LowPart -= (constTerm.HighPart << 4) - constTerm.HighPart;                         \
        return fmix32_short( constTerm.LowPart );                                                    \
    } else {                                                                                         \
		constTerm.LowPart -= constTerm.HighPart * 15;                                                \
		if ( constTerm.LowPart < 30 ) {                                                              \
            return fmix32_short( constTerm.LowPart );                                                \
        } else  {                                                                                    \
			constTerm.LowPart += 15;                                                                 \
			return fmix32_short( constTerm.LowPart );                                                \
		}                                                                                            \
	}                                                                                                \
}

#define PMPML_FULL_REDUCE_MOD_2_32_PLUS_15_AND_RETURN_RETURN                                            \
{                                                                                                       \
	uint32_t lo, hi;                                                                                    \
	multiply32x32to64(hi, lo, constTerm.HighPart, 15);                                                  \
	uint32_t part = ctr * 225 + (hi << 4) - hi + 15;                                                    \
	constTerm.LowPart += part;                                                                          \
	constTerm.HighPart = 1 + (constTerm.LowPart < part);                                                \
	constTerm.HighPart -= (constTerm.LowPart < lo);                                                     \
	constTerm.LowPart -= lo;                                                                            \
	if ( likely( constTerm.LowPart >= 30) ) {                                                           \
        constTerm.LowPart -= (constTerm.HighPart << 4) - constTerm.HighPart/*constTerm.HighPart * 15*/; \
        return fmix32_short( constTerm.LowPart );                                                       \
	} else  {                                                                                           \
		if ( constTerm.HighPart ) {                                                                     \
			constTerm.LowPart -= constTerm.HighPart * 15 - 15;                                          \
			constTerm.HighPart = 1;                                                                     \
			if ( likely( constTerm.LowPart >= 15)) {                                                    \
                constTerm.LowPart -= 15;                                                                \
                return fmix32_short( constTerm.LowPart );                                               \
            } else  {                                                                                   \
				return constTerm.LowPart;                                                               \
			}                                                                                           \
        } else {                                                                                        \
			return fmix32_short( constTerm.LowPart );                                                   \
        }                                                                                               \
	}                                                                                                   \
}

class PMP_Multilinear_Hasher_32 {
  private:
    random_data_for_PMPML_32 * curr_rd;
    uint64_t  coeff0;

    // calls to be done from LEVEL=0
    template <bool bswap>
    FORCE_INLINE uint64_t hash_of_string_chunk_compact( const uint32_t * coeff,
            ULARGE_INTEGER__XX constTerm, const uint32_t * x ) const {
        PMPML_CHUNK_LOOP_INTRO_L0

#if defined(HAVE_AVX2) && (PMPML_32_CHUNK_SIZE_LOG2 >= 3)
        __m256i ctr0, ctr1, mask_low;
        __m256i  a, data, product, temp;
        uint64_t temp_fin;
        int      i;

        ctr0     = _mm256_setzero_si256(); // Sets the 128-bit value to zero.
        ctr1     = _mm256_setzero_si256();
        mask_low = _mm256_set_epi32(0, -1, 0, -1, 0, -1, 0, -1);

        uint32_t * x1, * x2, * x3, * c1, * c2, * c3;

  #if (PMPML_32_CHUNK_SIZE_LOG2 >= 6)
        for (i = 0; i < PMPML_32_CHUNK_SIZE; i += 64)
  #elif (PMPML_32_CHUNK_SIZE_LOG2 == 5)
        for (i = 0; i < PMPML_32_CHUNK_SIZE; i += 32)
  #elif (PMPML_32_CHUNK_SIZE_LOG2 == 4)
        for (i = 0; i < PMPML_32_CHUNK_SIZE; i += 16)
  #else
        for (i = 0; i < PMPML_32_CHUNK_SIZE; i += 8)
  #endif
        {
            a       = _mm256_load_si256((__m256i * )(coeff + i)); // Loads 256-bit value. Address p must be 32-byte
                                                                  // aligned.
            data    = _mm256_loadu_si256((__m256i *)(x     + i)); // Loads 256-bit value. Address p does not need be
                                                                  // 32-byte aligned.
            product = _mm256_mul_epu32(data, a);                  // A 256-bit value that contains four 64-bit unsigned
                                                                  // integers. The result can be expressed by the
                                                                  // following equations. r0 := a0 * b0; r1 := a2 * b2;
                                                                  // ...
            temp    = _mm256_srli_epi64(product, 32);             // Shifts the 4 signed or unsigned 64-bit integers in
                                                                  // a right by count bits while shifting in zeros.
            ctr1    = _mm256_add_epi64(ctr1, temp   );
            // temp = _mm256_and_si256 ( mask_low, product );
            ctr0    = _mm256_add_epi64(ctr0, product); // ctr0 = _mm256_add_epi64 ( ctr0, temp );

            a       = _mm256_shuffle_epi32(a   , 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            data    = _mm256_shuffle_epi32(data, 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            product = _mm256_mul_epu32(data, a);
            temp    = _mm256_srli_epi64(product, 32);
            ctr1    = _mm256_add_epi64(ctr1, temp   );
            // temp = _mm256_and_si256 ( mask_low, product );
            ctr0    = _mm256_add_epi64(ctr0, product); // ctr0 = _mm256_add_epi64 ( ctr0, temp );

  #if (PMPML_32_CHUNK_SIZE_LOG2 > 3)

            a       = _mm256_load_si256((__m256i * )(coeff + i + 8));
            data    = _mm256_loadu_si256((__m256i *)(x     + i + 8));
            product = _mm256_mul_epu32(data, a);
            temp    = _mm256_srli_epi64(product, 32);
            ctr1    = _mm256_add_epi64(ctr1, temp   );
            // temp = _mm256_and_si256 ( mask_low, product );
            ctr0    = _mm256_add_epi64(ctr0, product); // ctr0 = _mm256_add_epi64 ( ctr0, temp );

            a       = _mm256_shuffle_epi32(a   , 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            data    = _mm256_shuffle_epi32(data, 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            product = _mm256_mul_epu32(data, a);
            temp    = _mm256_srli_epi64(product, 32);
            ctr1    = _mm256_add_epi64(ctr1, temp   );
            // temp = _mm256_and_si256 ( mask_low, product );
            ctr0    = _mm256_add_epi64(ctr0, product); // ctr0 = _mm256_add_epi64 ( ctr0, temp );

  #endif
  #if (PMPML_32_CHUNK_SIZE_LOG2 > 4)

            a       = _mm256_load_si256((__m256i * )(coeff + i + 16));
            data    = _mm256_loadu_si256((__m256i *)(x     + i + 16));
            product = _mm256_mul_epu32(data, a);
            temp    = _mm256_srli_epi64(product, 32);
            ctr1    = _mm256_add_epi64(ctr1, temp   );
            // temp = _mm256_and_si256 ( mask_low, product );
            ctr0    = _mm256_add_epi64(ctr0, product); // ctr0 = _mm256_add_epi64 ( ctr0, temp );

            a       = _mm256_shuffle_epi32(a   , 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            data    = _mm256_shuffle_epi32(data, 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            product = _mm256_mul_epu32(data, a);
            temp    = _mm256_srli_epi64(product, 32);
            ctr1    = _mm256_add_epi64(ctr1, temp   );
            // temp = _mm256_and_si256 ( mask_low, product );
            ctr0    = _mm256_add_epi64(ctr0, product); // ctr0 = _mm256_add_epi64 ( ctr0, temp );

            a       = _mm256_load_si256((__m256i * )(coeff + i + 24));
            data    = _mm256_loadu_si256((__m256i *)(x     + i + 24));
            product = _mm256_mul_epu32(data, a);
            temp    = _mm256_srli_epi64(product, 32);
            ctr1    = _mm256_add_epi64(ctr1, temp   );
            // temp = _mm256_and_si256 ( mask_low, product );
            ctr0    = _mm256_add_epi64(ctr0, product); // ctr0 = _mm256_add_epi64 ( ctr0, temp );

            a       = _mm256_shuffle_epi32(a   , 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            data    = _mm256_shuffle_epi32(data, 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            product = _mm256_mul_epu32(data, a);
            temp    = _mm256_srli_epi64(product, 32);
            ctr1    = _mm256_add_epi64(ctr1, temp   );
            // temp = _mm256_and_si256 ( mask_low, product );
            ctr0    = _mm256_add_epi64(ctr0, product); // ctr0 = _mm256_add_epi64 ( ctr0, temp );

  #endif
  #if (PMPML_32_CHUNK_SIZE_LOG2 > 5)

            a       = _mm256_load_si256((__m256i * )(coeff + i + 32));
            data    = _mm256_loadu_si256((__m256i *)(x     + i + 32));
            product = _mm256_mul_epu32(data, a);
            temp    = _mm256_srli_epi64(product, 32);
            ctr1    = _mm256_add_epi64(ctr1, temp   );
            // temp = _mm256_and_si256 ( mask_low, product );
            ctr0    = _mm256_add_epi64(ctr0, product); // ctr0 = _mm256_add_epi64 ( ctr0, temp );

            a       = _mm256_shuffle_epi32(a   , 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            data    = _mm256_shuffle_epi32(data, 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            product = _mm256_mul_epu32(data, a);
            temp    = _mm256_srli_epi64(product, 32);
            ctr1    = _mm256_add_epi64(ctr1, temp   );
            // temp = _mm256_and_si256 ( mask_low, product );
            ctr0    = _mm256_add_epi64(ctr0, product); // ctr0 = _mm256_add_epi64 ( ctr0, temp );

            a       = _mm256_load_si256((__m256i * )(coeff + i + 40));
            data    = _mm256_loadu_si256((__m256i *)(x     + i + 40));
            product = _mm256_mul_epu32(data, a);
            temp    = _mm256_srli_epi64(product, 32);
            ctr1    = _mm256_add_epi64(ctr1, temp   );
            // temp = _mm256_and_si256 ( mask_low, product );
            ctr0    = _mm256_add_epi64(ctr0, product); // ctr0 = _mm256_add_epi64 ( ctr0, temp );

            a       = _mm256_shuffle_epi32(a   , 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            data    = _mm256_shuffle_epi32(data, 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            product = _mm256_mul_epu32(data, a);
            temp    = _mm256_srli_epi64(product, 32);
            ctr1    = _mm256_add_epi64(ctr1, temp   );
            // temp = _mm256_and_si256 ( mask_low, product );
            ctr0    = _mm256_add_epi64(ctr0, product); // ctr0 = _mm256_add_epi64 ( ctr0, temp );

            a       = _mm256_load_si256((__m256i * )(coeff + i + 48));
            data    = _mm256_loadu_si256((__m256i *)(x     + i + 48));
            product = _mm256_mul_epu32(data, a);
            temp    = _mm256_srli_epi64(product, 32);
            ctr1    = _mm256_add_epi64(ctr1, temp   );
            // temp = _mm256_and_si256 ( mask_low, product );
            ctr0    = _mm256_add_epi64(ctr0, product); // ctr0 = _mm256_add_epi64 ( ctr0, temp );

            a       = _mm256_shuffle_epi32(a   , 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            data    = _mm256_shuffle_epi32(data, 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            product = _mm256_mul_epu32(data, a);
            temp    = _mm256_srli_epi64(product, 32);
            ctr1    = _mm256_add_epi64(ctr1, temp   );
            // temp = _mm256_and_si256 ( mask_low, product );
            ctr0    = _mm256_add_epi64(ctr0, product); // ctr0 = _mm256_add_epi64 ( ctr0, temp );

            a       = _mm256_load_si256((__m256i * )(coeff + i + 56));
            data    = _mm256_loadu_si256((__m256i *)(x     + i + 56));
            product = _mm256_mul_epu32(data, a);
            temp    = _mm256_srli_epi64(product, 32);
            ctr1    = _mm256_add_epi64(ctr1, temp   );
            // temp = _mm256_and_si256 ( mask_low, product );
            ctr0    = _mm256_add_epi64(ctr0, product); // ctr0 = _mm256_add_epi64 ( ctr0, temp );

            a       = _mm256_shuffle_epi32(a   , 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            data    = _mm256_shuffle_epi32(data, 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            product = _mm256_mul_epu32(data, a);
            temp    = _mm256_srli_epi64(product, 32);
            ctr1    = _mm256_add_epi64(ctr1, temp   );
            // temp = _mm256_and_si256 ( mask_low, product );
            ctr0    = _mm256_add_epi64(ctr0, product); // ctr0 = _mm256_add_epi64 ( ctr0, temp );
  #endif
        }

        temp = _mm256_unpackhi_epi64(ctr0, ctr1); // Interleaves the upper signed or unsigned 64-bit integer in a with
                                                  // the upper signed or unsigned 64-bit integer in b. r0 := a1 ; r1 :=
                                                  // b1 ; ...
        data = _mm256_unpacklo_epi64(ctr0, ctr1); // Interleaves the lower signed or unsigned 64-bit integer in a with
                                                  // the lower signed or unsigned 64-bit integer in b. r0 := a0 ; r1 :=
                                                  // b0 ; ...
        ctr1 = _mm256_add_epi64(data, temp);

        uint64_t lo   = *(uint64_t *)(&ctr1) + ((uint64_t *)(&ctr1))[2];
        uint64_t hi   = ((uint64_t *)(&ctr1))[1] + ((uint64_t *)(&ctr1))[3];
        uint32_t lohi = lo >> 32;
        uint32_t hilo = hi;
        uint32_t diff = lohi - hilo;
        hi  += diff;
        lo   = (uint32_t)lo + (((uint64_t)(uint32_t)hi) << 32);
        constTerm.QuadPart += lo;
        ctr += constTerm.QuadPart < lo;
        ctr += hi >> 32;

#elif defined(HAVE_SSE_2) && (PMPML_32_CHUNK_SIZE_LOG2 >= 2)

        __m128i ctr0, ctr1, mask_low;
        __m128i  a, data, product, temp;
        uint64_t temp_fin;
        int      i;

        ctr0     = _mm_setzero_si128(); // Sets the 128-bit value to zero.
        ctr1     = _mm_setzero_si128();
        mask_low = _mm_set_epi32(0, -1, 0, -1);

        uint32_t * x1, * x2, * x3, * c1, * c2, * c3;

  #if (PMPML_32_CHUNK_SIZE_LOG2 >= 6)
        for (i = 0; i < PMPML_32_CHUNK_SIZE; i += 64)
  #elif (PMPML_32_CHUNK_SIZE_LOG2 == 5)
        for (i = 0; i < PMPML_32_CHUNK_SIZE; i += 32)
  #elif (PMPML_32_CHUNK_SIZE_LOG2 == 4)
        for (i = 0; i < PMPML_32_CHUNK_SIZE; i += 16)
  #elif (PMPML_32_CHUNK_SIZE_LOG2 == 3)
        for (i = 0; i < PMPML_32_CHUNK_SIZE; i += 8)
  #else
        for (i = 0; i < PMPML_32_CHUNK_SIZE; i += 4)
  #endif
        {
            a       = _mm_load_si128((__m128i * )(coeff + i)); // Loads 128-bit value. Address p must be 16-byte
                                                               // aligned.
            data    = _mm_loadu_si128((__m128i *)(x     + i)); // Loads 128-bit value. Address p does not need be
                                                               // 16-byte aligned.
            product = _mm_mul_epu32(data, a);                  // A 128-bit value that contains two 64-bit unsigned
                                                               // integers. The result can be expressed by the following
                                                               // equations. r0 := a0 * b0; r1 := a2 * b2
            temp    = _mm_srli_epi64(product, 32);             // Shifts the 2 signed or unsigned 64-bit integers in a
                                                               // right by count bits while shifting in zeros.
            ctr1    = _mm_add_epi64(ctr1, temp   );
            // temp = _mm_and_si128 ( mask_low, product );
            ctr0    = _mm_add_epi64(ctr0, product); // ctr0 = _mm_add_epi64 ( ctr0, temp );

            a       = _mm_shuffle_epi32(a   , 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            data    = _mm_shuffle_epi32(data, 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            product = _mm_mul_epu32(data, a);
            temp    = _mm_srli_epi64(product, 32);
            ctr1    = _mm_add_epi64(ctr1, temp   );
            // temp = _mm_and_si128 ( mask_low, product );
            ctr0    = _mm_add_epi64(ctr0, product); // ctr0 = _mm_add_epi64 ( ctr0, temp );

  #if (PMPML_32_CHUNK_SIZE_LOG2 > 2)

            a       = _mm_load_si128((__m128i * )(coeff + i + 4));
            data    = _mm_loadu_si128((__m128i *)(x     + i + 4));
            product = _mm_mul_epu32(data, a);
            temp    = _mm_srli_epi64(product, 32);
            ctr1    = _mm_add_epi64(ctr1, temp   );
            // temp = _mm_and_si128 ( mask_low, product );
            ctr0    = _mm_add_epi64(ctr0, product); // ctr0 = _mm_add_epi64 ( ctr0, temp );

            a       = _mm_shuffle_epi32(a   , 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            data    = _mm_shuffle_epi32(data, 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            product = _mm_mul_epu32(data, a);
            temp    = _mm_srli_epi64(product, 32);
            ctr1    = _mm_add_epi64(ctr1, temp   );
            // temp = _mm_and_si128 ( mask_low, product );
            ctr0    = _mm_add_epi64(ctr0, product); // ctr0 = _mm_add_epi64 ( ctr0, temp );

  #endif
  #if (PMPML_32_CHUNK_SIZE_LOG2 > 3)

            a       = _mm_load_si128((__m128i * )(coeff + i + 8));
            data    = _mm_loadu_si128((__m128i *)(x     + i + 8));
            product = _mm_mul_epu32(data, a);
            temp    = _mm_srli_epi64(product, 32);
            ctr1    = _mm_add_epi64(ctr1, temp   );
            // temp = _mm_and_si128 ( mask_low, product );
            ctr0    = _mm_add_epi64(ctr0, product); // ctr0 = _mm_add_epi64 ( ctr0, temp );

            a       = _mm_shuffle_epi32(a   , 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            data    = _mm_shuffle_epi32(data, 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            product = _mm_mul_epu32(data, a);
            temp    = _mm_srli_epi64(product, 32);
            ctr1    = _mm_add_epi64(ctr1, temp   );
            // temp = _mm_and_si128 ( mask_low, product );
            ctr0    = _mm_add_epi64(ctr0, product); // ctr0 = _mm_add_epi64 ( ctr0, temp );

            a       = _mm_load_si128((__m128i * )(coeff + i + 12));
            data    = _mm_loadu_si128((__m128i *)(x     + i + 12));
            product = _mm_mul_epu32(data, a);
            temp    = _mm_srli_epi64(product, 32);
            ctr1    = _mm_add_epi64(ctr1, temp   );
            // temp = _mm_and_si128 ( mask_low, product );
            ctr0    = _mm_add_epi64(ctr0, product); // ctr0 = _mm_add_epi64 ( ctr0, temp );

            a       = _mm_shuffle_epi32(a   , 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            data    = _mm_shuffle_epi32(data, 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            product = _mm_mul_epu32(data, a);
            temp    = _mm_srli_epi64(product, 32);
            ctr1    = _mm_add_epi64(ctr1, temp   );
            // temp = _mm_and_si128 ( mask_low, product );
            ctr0    = _mm_add_epi64(ctr0, product); // ctr0 = _mm_add_epi64 ( ctr0, temp );

  #endif
  #if (PMPML_32_CHUNK_SIZE_LOG2 > 4)

            a       = _mm_load_si128((__m128i * )(coeff + i + 16));
            data    = _mm_loadu_si128((__m128i *)(x     + i + 16));
            product = _mm_mul_epu32(data, a);
            temp    = _mm_srli_epi64(product, 32);
            ctr1    = _mm_add_epi64(ctr1, temp   );
            // temp = _mm_and_si128 ( mask_low, product );
            ctr0    = _mm_add_epi64(ctr0, product); // ctr0 = _mm_add_epi64 ( ctr0, temp );

            a       = _mm_shuffle_epi32(a   , 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            data    = _mm_shuffle_epi32(data, 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            product = _mm_mul_epu32(data, a);
            temp    = _mm_srli_epi64(product, 32);
            ctr1    = _mm_add_epi64(ctr1, temp   );
            // temp = _mm_and_si128 ( mask_low, product );
            ctr0    = _mm_add_epi64(ctr0, product); // ctr0 = _mm_add_epi64 ( ctr0, temp );

            a       = _mm_load_si128((__m128i * )(coeff + i + 20));
            data    = _mm_loadu_si128((__m128i *)(x     + i + 20));
            product = _mm_mul_epu32(data, a);
            temp    = _mm_srli_epi64(product, 32);
            ctr1    = _mm_add_epi64(ctr1, temp   );
            // temp = _mm_and_si128 ( mask_low, product );
            ctr0    = _mm_add_epi64(ctr0, product); // ctr0 = _mm_add_epi64 ( ctr0, temp );

            a       = _mm_shuffle_epi32(a   , 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            data    = _mm_shuffle_epi32(data, 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            product = _mm_mul_epu32(data, a);
            temp    = _mm_srli_epi64(product, 32);
            ctr1    = _mm_add_epi64(ctr1, temp   );
            // temp = _mm_and_si128 ( mask_low, product );
            ctr0    = _mm_add_epi64(ctr0, product); // ctr0 = _mm_add_epi64 ( ctr0, temp );

            a       = _mm_load_si128((__m128i * )(coeff + i + 24));
            data    = _mm_loadu_si128((__m128i *)(x     + i + 24));
            product = _mm_mul_epu32(data, a);
            temp    = _mm_srli_epi64(product, 32);
            ctr1    = _mm_add_epi64(ctr1, temp   );
            // temp = _mm_and_si128 ( mask_low, product );
            ctr0    = _mm_add_epi64(ctr0, product); // ctr0 = _mm_add_epi64 ( ctr0, temp );

            a       = _mm_shuffle_epi32(a   , 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            data    = _mm_shuffle_epi32(data, 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            product = _mm_mul_epu32(data, a);
            temp    = _mm_srli_epi64(product, 32);
            ctr1    = _mm_add_epi64(ctr1, temp   );
            // temp = _mm_and_si128 ( mask_low, product );
            ctr0    = _mm_add_epi64(ctr0, product); // ctr0 = _mm_add_epi64 ( ctr0, temp );

            a       = _mm_load_si128((__m128i * )(coeff + i + 28));
            data    = _mm_loadu_si128((__m128i *)(x     + i + 28));
            product = _mm_mul_epu32(data, a);
            temp    = _mm_srli_epi64(product, 32);
            ctr1    = _mm_add_epi64(ctr1, temp   );
            // temp = _mm_and_si128 ( mask_low, product );
            ctr0    = _mm_add_epi64(ctr0, product); // ctr0 = _mm_add_epi64 ( ctr0, temp );

            a       = _mm_shuffle_epi32(a   , 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            data    = _mm_shuffle_epi32(data, 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            product = _mm_mul_epu32(data, a);
            temp    = _mm_srli_epi64(product, 32);
            ctr1    = _mm_add_epi64(ctr1, temp   );
            // temp = _mm_and_si128 ( mask_low, product );
            ctr0    = _mm_add_epi64(ctr0, product); // ctr0 = _mm_add_epi64 ( ctr0, temp );

  #endif
  #if (PMPML_32_CHUNK_SIZE_LOG2 > 5)

            x1      = const_cast<uint32_t *>(x     + i + 36);
            x2      = const_cast<uint32_t *>(x     + i + 40);
            x3      = const_cast<uint32_t *>(x     + i + 44);
            c1      = const_cast<uint32_t *>(coeff + i + 36);
            c2      = const_cast<uint32_t *>(coeff + i + 40);
            c3      = const_cast<uint32_t *>(coeff + i + 44);
            a       = _mm_load_si128((__m128i * )(coeff + i + 32));
            data    = _mm_loadu_si128((__m128i *)(x     + i + 32));
            product = _mm_mul_epu32(data, a);
            temp    = _mm_srli_epi64(product, 32);
            ctr1    = _mm_add_epi64(ctr1, temp   );
            // temp = _mm_and_si128 ( mask_low, product );
            ctr0    = _mm_add_epi64(ctr0, product); // ctr0 = _mm_add_epi64 ( ctr0, temp );

            a       = _mm_shuffle_epi32(a   , 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            data    = _mm_shuffle_epi32(data, 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            product = _mm_mul_epu32(data, a);
            temp    = _mm_srli_epi64(product, 32);
            ctr1    = _mm_add_epi64(ctr1, temp   );
            // temp = _mm_and_si128 ( mask_low, product );
            ctr0    = _mm_add_epi64(ctr0, product); // ctr0 = _mm_add_epi64 ( ctr0, temp );

            a       = _mm_load_si128((__m128i * )(c1));
            data    = _mm_loadu_si128((__m128i *)(x1));
            product = _mm_mul_epu32(data, a);
            temp    = _mm_srli_epi64(product, 32);
            ctr1    = _mm_add_epi64(ctr1, temp   );
            // temp = _mm_and_si128 ( mask_low, product );
            ctr0    = _mm_add_epi64(ctr0, product); // ctr0 = _mm_add_epi64 ( ctr0, temp );

            a       = _mm_shuffle_epi32(a   , 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            data    = _mm_shuffle_epi32(data, 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            product = _mm_mul_epu32(data, a);
            temp    = _mm_srli_epi64(product, 32);
            ctr1    = _mm_add_epi64(ctr1, temp   );
            // temp = _mm_and_si128 ( mask_low, product );
            ctr0    = _mm_add_epi64(ctr0, product); // ctr0 = _mm_add_epi64 ( ctr0, temp );

            a       = _mm_load_si128((__m128i * )(c2));
            data    = _mm_loadu_si128((__m128i *)(x2));
            product = _mm_mul_epu32(data, a);
            temp    = _mm_srli_epi64(product, 32);
            ctr1    = _mm_add_epi64(ctr1, temp   );
            // temp = _mm_and_si128 ( mask_low, product );
            ctr0    = _mm_add_epi64(ctr0, product); // ctr0 = _mm_add_epi64 ( ctr0, temp );

            a       = _mm_shuffle_epi32(a   , 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            data    = _mm_shuffle_epi32(data, 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            product = _mm_mul_epu32(data, a);
            temp    = _mm_srli_epi64(product, 32);
            ctr1    = _mm_add_epi64(ctr1, temp   );
            // temp = _mm_and_si128 ( mask_low, product );
            ctr0    = _mm_add_epi64(ctr0, product); // ctr0 = _mm_add_epi64 ( ctr0, temp );

            a       = _mm_load_si128((__m128i * )(c3));
            data    = _mm_loadu_si128((__m128i *)(x3));
            product = _mm_mul_epu32(data, a);
            temp    = _mm_srli_epi64(product, 32);
            ctr1    = _mm_add_epi64(ctr1, temp   );
            // temp = _mm_and_si128 ( mask_low, product );
            ctr0    = _mm_add_epi64(ctr0, product); // ctr0 = _mm_add_epi64 ( ctr0, temp );

            a       = _mm_shuffle_epi32(a   , 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            data    = _mm_shuffle_epi32(data, 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            product = _mm_mul_epu32(data, a);
            temp    = _mm_srli_epi64(product, 32);
            ctr1    = _mm_add_epi64(ctr1, temp   );
            // temp = _mm_and_si128 ( mask_low, product );
            ctr0    = _mm_add_epi64(ctr0, product); // ctr0 = _mm_add_epi64 ( ctr0, temp );

            x1      = const_cast<uint32_t *>(x     + i + 52);
            x2      = const_cast<uint32_t *>(x     + i + 56);
            x3      = const_cast<uint32_t *>(x     + i + 60);
            c1      = const_cast<uint32_t *>(coeff + i + 52);
            c2      = const_cast<uint32_t *>(coeff + i + 56);
            c3      = const_cast<uint32_t *>(coeff + i + 60);
            a       = _mm_load_si128((__m128i * )(coeff + i + 48));
            data    = _mm_loadu_si128((__m128i *)(x     + i + 48));
            product = _mm_mul_epu32(data, a);
            temp    = _mm_srli_epi64(product, 32);
            ctr1    = _mm_add_epi64(ctr1, temp   );
            // temp = _mm_and_si128 ( mask_low, product );
            ctr0    = _mm_add_epi64(ctr0, product); // ctr0 = _mm_add_epi64 ( ctr0, temp );

            a       = _mm_shuffle_epi32(a   , 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            data    = _mm_shuffle_epi32(data, 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            product = _mm_mul_epu32(data, a);
            temp    = _mm_srli_epi64(product, 32);
            ctr1    = _mm_add_epi64(ctr1, temp   );
            // temp = _mm_and_si128 ( mask_low, product );
            ctr0    = _mm_add_epi64(ctr0, product); // ctr0 = _mm_add_epi64 ( ctr0, temp );

            a       = _mm_load_si128((__m128i * )(c1));
            data    = _mm_loadu_si128((__m128i *)(x1));
            product = _mm_mul_epu32(data, a);
            temp    = _mm_srli_epi64(product, 32);
            ctr1    = _mm_add_epi64(ctr1, temp   );
            // temp = _mm_and_si128 ( mask_low, product );
            ctr0    = _mm_add_epi64(ctr0, product); // ctr0 = _mm_add_epi64 ( ctr0, temp );

            a       = _mm_shuffle_epi32(a   , 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            data    = _mm_shuffle_epi32(data, 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            product = _mm_mul_epu32(data, a);
            temp    = _mm_srli_epi64(product, 32);
            ctr1    = _mm_add_epi64(ctr1, temp   );
            // temp = _mm_and_si128 ( mask_low, product );
            ctr0    = _mm_add_epi64(ctr0, product); // ctr0 = _mm_add_epi64 ( ctr0, temp );

            a       = _mm_load_si128((__m128i * )(c2));
            data    = _mm_loadu_si128((__m128i *)(x2));
            product = _mm_mul_epu32(data, a);
            temp    = _mm_srli_epi64(product, 32);
            ctr1    = _mm_add_epi64(ctr1, temp   );
            // temp = _mm_and_si128 ( mask_low, product );
            ctr0    = _mm_add_epi64(ctr0, product); // ctr0 = _mm_add_epi64 ( ctr0, temp );

            a       = _mm_shuffle_epi32(a   , 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            data    = _mm_shuffle_epi32(data, 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            product = _mm_mul_epu32(data, a);
            temp    = _mm_srli_epi64(product, 32);
            ctr1    = _mm_add_epi64(ctr1, temp   );
            // temp = _mm_and_si128 ( mask_low, product );
            ctr0    = _mm_add_epi64(ctr0, product); // ctr0 = _mm_add_epi64 ( ctr0, temp );

            a       = _mm_load_si128((__m128i * )(c3));
            data    = _mm_loadu_si128((__m128i *)(x3));
            product = _mm_mul_epu32(data, a);
            temp    = _mm_srli_epi64(product, 32);
            ctr1    = _mm_add_epi64(ctr1, temp   );
            // temp = _mm_and_si128 ( mask_low, product );
            ctr0    = _mm_add_epi64(ctr0, product); // ctr0 = _mm_add_epi64 ( ctr0, temp );

            a       = _mm_shuffle_epi32(a   , 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            data    = _mm_shuffle_epi32(data, 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            product = _mm_mul_epu32(data, a);
            temp    = _mm_srli_epi64(product, 32);
            ctr1    = _mm_add_epi64(ctr1, temp   );
            // temp = _mm_and_si128 ( mask_low, product );
            ctr0    = _mm_add_epi64(ctr0, product); // ctr0 = _mm_add_epi64 ( ctr0, temp );
  #endif
        }

        temp = _mm_unpackhi_epi64(ctr0, ctr1); // Interleaves the upper signed or unsigned 64-bit integer in a with the
                                               // upper signed or unsigned 64-bit integer in b. r0 := a1 ; r1 := b1
        data = _mm_unpacklo_epi64(ctr0, ctr1); // Interleaves the lower signed or unsigned 64-bit integer in a with the
                                               // lower signed or unsigned 64-bit integer in b. r0 := a0 ; r1 := b0
        ctr1 = _mm_add_epi64(data, temp);

  #if defined(_MSC_VER)
        constTerm.QuadPart += ctr1.m128i_u32[0]; // Microsoft specific
        ctr.QuadPart       += ctr1.m128i_u64[1] + ctr1.m128i_u32[1];
  #elif defined(HAVE_SSE_4_1)
        constTer.QuadPart  += _mm_extract_epi32(ctr1, 0);
        ctr.QuadPart       += _mm_extract_epi64(ctr1, 0) + _mm_extract_epi32(ctr1, 1);
  #elif (defined __arm__ || defined __aarch64__)
        uint32_t b[4];
        _mm_storeu_si128((__m128i *)b, ctr1);
        constTerm.QuadPart += b[0];
        ctr.QuadPart       += b[1] + b[2] + ((uint64_t)b[3] << 32);
  #else
        uint64_t lo   = ((uint64_t *)(&ctr1))[0];
        uint64_t hi   = ((uint64_t *)(&ctr1))[1];
/*
 *      constTerm.QuadPart += lo;
 *  ctr += constTerm.QuadPart < lo;
 *  constTerm.HighPart += ((uint32_t*)(&ctr1))[2];
 *  ctr += constTerm.HighPart < ((uint32_t*)(&ctr1))[2];
 *  ctr +=  ((uint32_t*)(&ctr1))[3];
 */
        uint32_t lohi = lo >> 32;
        uint32_t hilo = hi;
        uint32_t diff = lohi - hilo;
        hi  += diff;
        lo   = (uint32_t)lo + (((uint64_t)(uint32_t)hi) << 32);
        constTerm.QuadPart += lo;
        ctr += constTerm.QuadPart < lo;
        ctr += hi >> 32;
  #endif

#else // No AVX2 and no SSE
        for (uint32_t i = 0; i < PMPML_32_CHUNK_SIZE; i += 8) {
            PMPML_CHUNK_LOOP_BODY_ULI_T1(0 + i)
            PMPML_CHUNK_LOOP_BODY_ULI_T1(1 + i)
            PMPML_CHUNK_LOOP_BODY_ULI_T1(2 + i)
            PMPML_CHUNK_LOOP_BODY_ULI_T1(3 + i)
  #if (PMPML_32_CHUNK_SIZE_LOG2 > 2)
            PMPML_CHUNK_LOOP_BODY_ULI_T1(4 + i)
            PMPML_CHUNK_LOOP_BODY_ULI_T1(5 + i)
            PMPML_CHUNK_LOOP_BODY_ULI_T1(6 + i)
            PMPML_CHUNK_LOOP_BODY_ULI_T1(7 + i)
  #endif
        }
#endif // PMPML_USE_SSE

        PMPML_CHUNK_LOOP_PRE_REDUCE_L0

                PMPML_FULL_REDUCE_MOD_2_32_PLUS_15_AND_RETURN
    }

    template <bool bswap>
    FORCE_INLINE uint64_t hash_of_beginning_of_string_chunk_type2( const uint32_t * coeff, ULARGE_INTEGER__XX constTerm,
            const unsigned char * tail, unsigned int tail_size  ) const {
        PMPML_CHUNK_LOOP_INTRO_L0
        uint32_t         size = tail_size >> PMPML_32_WORD_SIZE_BYTES_LOG2;
        const uint32_t * x    = (const uint32_t *)tail;

#if defined(HAVE_SSE_2)
        __m128i ctr0, ctr1, a, data, product, temp, mask_low;
        int     i;

        ctr0     = _mm_setzero_si128(); // Sets the 128-bit value to zero.
        ctr1     = _mm_setzero_si128();
        mask_low = _mm_set_epi32(0, -1, 0, -1);

        for (i = 0; i < (size & 0xFFFFFFF8); i += 4) {
            a       = _mm_load_si128((__m128i * )(coeff + i)); // Loads 128-bit value. Address p must be 16-byte
                                                               // aligned.
            data    = _mm_loadu_si128((__m128i *)(x     + i)); // Loads 128-bit value. Address p does not need be
                                                               // 16-byte aligned.
            product = _mm_mul_epu32(data, a);                  // A 128-bit value that contains two 64-bit unsigned
                                                               // integers. The result can be expressed by the following
                                                               // equations. r0 := a0 * b0; r1 := a2 * b2
            temp    = _mm_srli_epi64(product, 32);             // Shifts the 2 signed or unsigned 64-bit integers in a
                                                               // right by count bits while shifting in zeros.
            ctr1    = _mm_add_epi64(ctr1, temp);
            temp    = _mm_and_si128(mask_low, product);
            ctr0    = _mm_add_epi64(ctr0, temp);

//              a = _mm_srli_epi64 ( a, 32 );
//              data = _mm_srli_epi64 ( data, 32 );
            a       = _mm_shuffle_epi32(a   , 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            data    = _mm_shuffle_epi32(data, 1 * 1 + 0 * 4 + 3 * 16 + 2 * 64);
            product = _mm_mul_epu32(data, a);      // A 128-bit value that contains two 64-bit unsigned integers. The
                                                   // result can be expressed by the following equations. r0 := a0 * b0;
                                                   // r1 := a2 * b2
            temp    = _mm_srli_epi64(product, 32); // Shifts the 2 signed or unsigned 64-bit integers in a right by
                                                   // count bits while shifting in zeros.
            ctr1    = _mm_add_epi64(ctr1, temp);
            temp    = _mm_and_si128(mask_low, product);
            ctr0    = _mm_add_epi64(ctr0, temp);
        }

        temp = _mm_unpackhi_epi64(ctr0, ctr1); // Interleaves the upper signed or unsigned 64-bit integer in a with the
                                               // upper signed or unsigned 64-bit integer in b. r0 := a1 ; r1 := b1
        data = _mm_unpacklo_epi64(ctr0, ctr1); // Interleaves the lower signed or unsigned 64-bit integer in a with the
                                               // lower signed or unsigned 64-bit integer in b. r0 := a0 ; r1 := b0
        ctr1 = _mm_add_epi64(data, temp);

  #if defined(_MSC_VER)
        constTerm.QuadPart += ctr1.m128i_u32[0]; // Microsoft specific
        ctr.QuadPart       += ctr1.m128i_u64[1] + ctr1.m128i_u32[1];
  #elif 0 && defined(__SSE4_1__)
        constTerm.QuadPart += _mm_extract_epi32(ctr1, 0);
        ctr.QuadPart       += _mm_extract_epi64(ctr1, 0) + _mm_extract_epi32(ctr1, 1);
  #elif 0 && defined(IDEK)
        uint32_t b[4];
        _mm_storeu_si128((__m128i *)b, ctr1);
        constTerm.QuadPart += b[0];
        ctr.QuadPart       += b[1] + b[2] + ((uint64_t)b[3] << 32);
  #else
        constTerm.QuadPart += *      (uint64_t *)(&ctr1);
        ctr += constTerm.QuadPart < *(uint64_t *)(&ctr1);
        constTerm.HighPart +=       ((uint32_t *)(&ctr1))[2];
        ctr += constTerm.HighPart < ((uint32_t *)(&ctr1))[2];
        ctr += ((uint32_t *)(&ctr1))[3];
  #endif

#else // HAVE_SSE_2

        for (uint32_t i = 0; i < (size & 0xFFFFFFF8); i += 8) {
            PMPML_CHUNK_LOOP_BODY_ULI_T1(0 + i)
            PMPML_CHUNK_LOOP_BODY_ULI_T1(1 + i)
            PMPML_CHUNK_LOOP_BODY_ULI_T1(2 + i)
            PMPML_CHUNK_LOOP_BODY_ULI_T1(3 + i)
  #if (PMPML_32_CHUNK_SIZE_LOG2 > 2)
            PMPML_CHUNK_LOOP_BODY_ULI_T1(4 + i)
            PMPML_CHUNK_LOOP_BODY_ULI_T1(5 + i)
            PMPML_CHUNK_LOOP_BODY_ULI_T1(6 + i)
            PMPML_CHUNK_LOOP_BODY_ULI_T1(7 + i)
  #endif
        }

#endif // HAVE_SSE_2

        uint32_t offset = size & 0xFFFFFFF8;

        switch (size & 0x7) {
        case 0: { break; }
        case 1: {   PMPML_CHUNK_LOOP_BODY_ULI_T1(0 + offset) }
        break;
        case 2: {   PMPML_CHUNK_LOOP_BODY_ULI_T1(0 + offset) PMPML_CHUNK_LOOP_BODY_ULI_T1(1 + offset) }
        break;
        case 3: {   PMPML_CHUNK_LOOP_BODY_ULI_T1(0 + offset) PMPML_CHUNK_LOOP_BODY_ULI_T1(1 + offset)
                    PMPML_CHUNK_LOOP_BODY_ULI_T1(2 + offset) }
                    break;
        case 4: {   PMPML_CHUNK_LOOP_BODY_ULI_T1(0 + offset) PMPML_CHUNK_LOOP_BODY_ULI_T1(1 + offset)
                    PMPML_CHUNK_LOOP_BODY_ULI_T1(2 + offset) PMPML_CHUNK_LOOP_BODY_ULI_T1(3 + offset) }
                    break;
        case 5: {   PMPML_CHUNK_LOOP_BODY_ULI_T1(0 + offset) PMPML_CHUNK_LOOP_BODY_ULI_T1(1 + offset)
                    PMPML_CHUNK_LOOP_BODY_ULI_T1(2 + offset) PMPML_CHUNK_LOOP_BODY_ULI_T1(3 + offset)
                    PMPML_CHUNK_LOOP_BODY_ULI_T1(4 + offset) }
                    break;
        case 6: {   PMPML_CHUNK_LOOP_BODY_ULI_T1(0 + offset) PMPML_CHUNK_LOOP_BODY_ULI_T1(1 + offset)
                    PMPML_CHUNK_LOOP_BODY_ULI_T1(2 + offset) PMPML_CHUNK_LOOP_BODY_ULI_T1(3 + offset)
                    PMPML_CHUNK_LOOP_BODY_ULI_T1(4 + offset) PMPML_CHUNK_LOOP_BODY_ULI_T1(5 + offset) }
                    break;
        case 7: {   PMPML_CHUNK_LOOP_BODY_ULI_T1(0 + offset) PMPML_CHUNK_LOOP_BODY_ULI_T1(1 + offset)
                    PMPML_CHUNK_LOOP_BODY_ULI_T1(2 + offset) PMPML_CHUNK_LOOP_BODY_ULI_T1(3 + offset)
                    PMPML_CHUNK_LOOP_BODY_ULI_T1(4 + offset) PMPML_CHUNK_LOOP_BODY_ULI_T1(5 + offset)
                    PMPML_CHUNK_LOOP_BODY_ULI_T1(6 + offset) }
                    break;
        }

        uint32_t xLast;
        switch (tail_size & (PMPML_32_WORD_SIZE_BYTES - 1)) {
        case 0: { xLast = 0x1; break; }
        case 1: { xLast = 0x100 | tail[tail_size - 1]; break; }
        case 2: { xLast = GET_U16<bswap>(tail + tail_size - 2, 0) | 0x10000; break; }
        case 3: { xLast = tail[tail_size - 1];
                  xLast = (xLast << 16) | GET_U16<bswap>(tail + tail_size - 3, 0) | 0x1000000; break; }
        }

        PMPML_CHUNK_LOOP_BODY_ULI_T1_LAST

        PMPML_CHUNK_LOOP_PRE_REDUCE_L0

                PMPML_FULL_REDUCE_MOD_2_32_PLUS_15_AND_RETURN
    }

    // a call to be done from subsequent levels
    FORCE_INLINE uint64_t hash_of_num_chunk( const uint32_t * coeff, ULARGE_INTEGER__XX constTerm, const uint64_t * x ) const {
        PMPML_CHUNK_LOOP_INTRO_L0

        for (uint32_t i = 0; i < PMPML_32_CHUNK_SIZE; i += 8) {
            PMPML_CHUNK_LOOP_BODY_ULI_T1_64(0 + i)
            PMPML_CHUNK_LOOP_BODY_ULI_T1_64(1 + i)
            PMPML_CHUNK_LOOP_BODY_ULI_T1_64(2 + i)
            PMPML_CHUNK_LOOP_BODY_ULI_T1_64(3 + i)
#if (PMPML_32_CHUNK_SIZE_LOG2 > 2)
            PMPML_CHUNK_LOOP_BODY_ULI_T1_64(4 + i)
            PMPML_CHUNK_LOOP_BODY_ULI_T1_64(5 + i)
            PMPML_CHUNK_LOOP_BODY_ULI_T1_64(6 + i)
            PMPML_CHUNK_LOOP_BODY_ULI_T1_64(7 + i)
#endif
        }

        PMPML_CHUNK_LOOP_PRE_REDUCE_L0

                PMPML_FULL_REDUCE_MOD_2_32_PLUS_15_AND_RETURN
    }

    // a call to be done from subsequent levels
    FORCE_INLINE uint64_t hash_of_num_chunk_incomplete( const uint32_t * coeff, ULARGE_INTEGER__XX constTerm,
            ULARGE_INTEGER__XX prevConstTerm, ULARGE_INTEGER__XX coeffSum, const uint64_t * x, size_t count ) const {
        PMPML_CHUNK_LOOP_INTRO_L0

        ULARGE_INTEGER__XX c_ctr;

        c_ctr.QuadPart = 0;

        uint32_t i;

        if (count < (PMPML_32_CHUNK_SIZE >> 1)) {
            for (i = 0; i < count; i++) {
                PMPML_CHUNK_LOOP_BODY_ULI_T1_64(0 + i)
                c_ctr.QuadPart += coeff[i];
            }
            c_ctr.QuadPart = coeffSum.QuadPart - c_ctr.QuadPart;
        } else {
            for (i = 0; i < count; i++) {
                PMPML_CHUNK_LOOP_BODY_ULI_T1_64(0 + i)
                for (; i < PMPML_32_CHUNK_SIZE; i++) {
                    c_ctr.QuadPart += coeff[i];
                }
            }
        }

        ULARGE_INTEGER__XX lowProduct;
        lowProduct.QuadPart  = UInt32x32To64(c_ctr.LowPart, prevConstTerm.LowPart );
        ULARGE_INTEGER__XX midProduct;
        midProduct.QuadPart  = UInt32x32To64(c_ctr.LowPart, prevConstTerm.HighPart) +
                UInt32x32To64(c_ctr.HighPart, prevConstTerm.LowPart);
        midProduct.QuadPart += lowProduct.HighPart;
        lowProduct.HighPart  = midProduct.LowPart;
        uint32_t hiProduct = c_ctr.HighPart * prevConstTerm.HighPart + midProduct.HighPart;

        constTerm.QuadPart += lowProduct.QuadPart;
        ctr += hiProduct + (constTerm.QuadPart < lowProduct.QuadPart);

/*
 *      for ( uint32_t i=0; i<PMPML_CHUNK_SIZE; i+=8 )
 *  {
 *      PMPML_CHUNK_LOOP_BODY_ULI_T1( 0 + i )
 *      PMPML_CHUNK_LOOP_BODY_ULI_T1( 1 + i )
 *      PMPML_CHUNK_LOOP_BODY_ULI_T1( 2 + i )
 *      PMPML_CHUNK_LOOP_BODY_ULI_T1( 3 + i )
 #if ( PMPML_CHUNK_SIZE > 4 )
 *      PMPML_CHUNK_LOOP_BODY_ULI_T1( 4 + i )
 *      PMPML_CHUNK_LOOP_BODY_ULI_T1( 5 + i )
 *      PMPML_CHUNK_LOOP_BODY_ULI_T1( 6 + i )
 *      PMPML_CHUNK_LOOP_BODY_ULI_T1( 7 + i )
 #endif
 *  }
 */

        PMPML_CHUNK_LOOP_PRE_REDUCE_L0

        PMPML_FULL_REDUCE_MOD_2_32_PLUS_15_AND_RETURN
    }

    template <bool bswap>
    FORCE_INLINE void procesNextValue( int level, uint64_t value, uint64_t * allValues,
            unsigned int * cnts, unsigned int & flag ) const {
        for (int i = level;; i++) {
            // NOTE: it's not necessary to check whether ( i < PMPML_LEVELS ),
            // if it is guaranteed that the string size is less than 1 << USHF_MACHINE_WORD_SIZE_BITS
            allValues[(i << PMPML_32_CHUNK_SIZE_LOG2) + cnts[i]] = value;
            (cnts[i])++;
            if (cnts[i] != PMPML_32_CHUNK_SIZE) {
                break;
            }
            cnts[i] = 0;
            value   = hash_of_num_chunk(curr_rd[i].random_coeff, *(ULARGE_INTEGER__XX *)(&(curr_rd[i].const_term)),
                    allValues + (i << PMPML_32_CHUNK_SIZE_LOG2));
            if ((flag & (1 << i)) == 0) {
                cnts[i + 1] = 0;
                flag       |= 1 << i;
            }
        }
    }

    template <bool bswap>
    FORCE_INLINE uint64_t finalize( int level, uint64_t * allValues, unsigned int * cnts, unsigned int & flag ) const {
        for (int i = level;; i++) {
//              assert ( level != PMPML_LEVELS )
            if (((flag & (1 << i)) == 0) && (cnts[i] == 1)) {
                return allValues[i << PMPML_32_CHUNK_SIZE_LOG2];
            }
            if (cnts[i]) {
/*
 *                      for ( int j=cnts[ i ]; j<PMPML_CHUNK_SIZE; j++ )
 *              ( allValues + ( i << PMPML_CHUNK_SIZE_LOG2 ) )[ j ] = curr_rd[ i - 1 ].const_term;
 */
                if ((flag & (1 << i)) == 0) {
                    cnts[i + 1] = 0;
                    flag       |= 1 << i;
                }
                procesNextValue<bswap>(i + 1,
/*
 *                                                       hash_of_num_chunk( curr_rd[ i ].random_coeff,
 *                                              (ULARGE_INTEGER__XX*)(&(curr_rd[i].const_term)),
 *                                              allValues + ( i << PMPML_CHUNK_SIZE_LOG2 ) ),
 */
                        hash_of_num_chunk_incomplete(curr_rd[i].random_coeff, *(ULARGE_INTEGER__XX *)(&(curr_rd[i].const_term)),
                        *(ULARGE_INTEGER__XX *)(&(curr_rd[i - 1].const_term)), *(ULARGE_INTEGER__XX *)(&(curr_rd[i].cachedSum)),
                        allValues + (i << PMPML_32_CHUNK_SIZE_LOG2), cnts[i]), allValues, cnts, flag);
            }
        }
    }

#if defined(_MSC_VER) && defined(HAVE_32BIT_PLATFORM)

    template <uint32_t N, bool bswap>
    static FORCE_INLINE uint32_t hash_size_SMALL_N( const unsigned char * chars ) const {
        const uint32_t *   coeff     = curr_rd[0].random_coeff;
        ULARGE_INTEGER__XX constTerm = *(ULARGE_INTEGER__XX *)(&(curr_rd[0].const_term));
        uint32_t           xLast;

        switch (N) {
        case 0: break;
        case 1: xLast = 0x100 + chars[0]; break
        case 2: xLast = GET_U16<bswap>(chars, 0) + 0x10000; break;
        case 3: xLast = chars[2]; xLast = (xLast << 16) + GET_U16<bswap>(chars, 0) + 0x1000000; break;
        case 4: xLast = GET_U32<bswap>(chars, 0) + coeff[1]; break;
        }

        if (N != 0) {
            constTerm.QuadPart += UInt32x32To64(coeff[0], xLast);
        } else {
            constTerm.QuadPart += coeff[0];
        }

        PMPML_FULL_REDUCE_MOD_2_32_PLUS_15_AND_RETURN_RETURN_32x32_ONLY;
    }

#define HASH_SIZE_XXX_BEGIN( XXX )                                                 \
  static FORCE_INLINE uint32_t hash_size_##XXX( const unsigned char* chars ) const \
  {                                                                                \
		const uint32_t* coeff = curr_rd[0].random_coeff;                   \
		const uint32_t* x = (const uint32_t*)chars;                        \
		ULARGE_INTEGER__XX constTerm = *(ULARGE_INTEGER__XX*)(&(curr_rd[0].const_term));\
		uint32_t xLast;                                                    \
		PMPML_CHUNK_LOOP_INTRO_L0                                          \
                uint32_t size = XXX >> PMPML_WORD_SIZE_BYTES_LOG2;

#define HASH_SIZE_XXX_END                              \
		PMPML_CHUNK_LOOP_PRE_REDUCE_L0         \
		PMPML_FULL_REDUCE_MOD_2_32_PLUS_15_AND_RETURN_RETURN\
  }

    HASH_SIZE_XXX_BEGIN(28)
    PMPML_CHUNK_LOOP_BODY_ULI_T1(0) PMPML_CHUNK_LOOP_BODY_ULI_T1(1) PMPML_CHUNK_LOOP_BODY_ULI_T1(2) PMPML_CHUNK_LOOP_BODY_ULI_T1(3)
    PMPML_CHUNK_LOOP_BODY_ULI_T1(4) PMPML_CHUNK_LOOP_BODY_ULI_T1(5) PMPML_CHUNK_LOOP_BODY_ULI_T1(6)
    xLast = 0x1;
    PMPML_CHUNK_LOOP_BODY_ULI_T1_LAST_FOR_JUST_1;
    HASH_SIZE_XXX_END

    HASH_SIZE_XXX_BEGIN( 29 )
    PMPML_CHUNK_LOOP_BODY_ULI_T1(0) PMPML_CHUNK_LOOP_BODY_ULI_T1(1) PMPML_CHUNK_LOOP_BODY_ULI_T1(2) PMPML_CHUNK_LOOP_BODY_ULI_T1(3)
    PMPML_CHUNK_LOOP_BODY_ULI_T1(4) PMPML_CHUNK_LOOP_BODY_ULI_T1(5) PMPML_CHUNK_LOOP_BODY_ULI_T1(6)
    xLast = 0x100 + chars[28];
    PMPML_CHUNK_LOOP_BODY_ULI_T1_LAST;
    HASH_SIZE_XXX_END

    HASH_SIZE_XXX_BEGIN( 30 )
    PMPML_CHUNK_LOOP_BODY_ULI_T1(0) PMPML_CHUNK_LOOP_BODY_ULI_T1(1) PMPML_CHUNK_LOOP_BODY_ULI_T1(2) PMPML_CHUNK_LOOP_BODY_ULI_T1(3)
    PMPML_CHUNK_LOOP_BODY_ULI_T1(4) PMPML_CHUNK_LOOP_BODY_ULI_T1(5) PMPML_CHUNK_LOOP_BODY_ULI_T1(6)
    xLast =((const unsigned short *)(chars + 28)) + 0x10000;
    PMPML_CHUNK_LOOP_BODY_ULI_T1_LAST
    HASH_SIZE_XXX_END

    HASH_SIZE_XXX_BEGIN( 31 )
    PMPML_CHUNK_LOOP_BODY_ULI_T1(0) PMPML_CHUNK_LOOP_BODY_ULI_T1(1) PMPML_CHUNK_LOOP_BODY_ULI_T1(2) PMPML_CHUNK_LOOP_BODY_ULI_T1(3)
    PMPML_CHUNK_LOOP_BODY_ULI_T1(4) PMPML_CHUNK_LOOP_BODY_ULI_T1(5) PMPML_CHUNK_LOOP_BODY_ULI_T1(6)
    xLast = chars[30];
    xLast = (xLast << 16) + *((const unsigned short *)(chars + 28)) + 0x1000000;
    PMPML_CHUNK_LOOP_BODY_ULI_T1_LAST;
    HASH_SIZE_XXX_END

#endif // PMPML_MSC_32_WORKAROUND

    template <bool bswap>
    NEVER_INLINE uint32_t _hash_noRecursionNoInline_forLessThanChunk( const unsigned char * chars, unsigned int cnt ) const {
        unsigned int       i;
        ULARGE_INTEGER__XX tmp_hash;

        tmp_hash.QuadPart = hash_of_beginning_of_string_chunk_type2<bswap>(curr_rd[0].random_coeff,
                *(ULARGE_INTEGER__XX *)(&(curr_rd[0].const_term)), chars, cnt);
        if (tmp_hash.HighPart == 0) {     // LIKELY
            return fmix32_short(tmp_hash.LowPart);
        }
        return tmp_hash.LowPart;
    }

    template <bool bswap>
    NEVER_INLINE uint32_t _hash_noRecursionNoInline_type2( const unsigned char * chars, unsigned int cnt ) const {
        uint64_t     allValues[PMPML_32_LEVELS * PMPML_32_CHUNK_SIZE];
        unsigned int cnts[PMPML_32_LEVELS];
        unsigned int flag;

        cnts[1] = 0;
        flag    = 0;

        unsigned int       i;
        ULARGE_INTEGER__XX tmp_hash;

        // process full chunks
        for (i = 0; i < (cnt >> PMPML_32_CHUNK_SIZE_BYTES_LOG2); i++) {
            tmp_hash.QuadPart = hash_of_string_chunk_compact<bswap>(curr_rd[0].random_coeff,
                    *(ULARGE_INTEGER__XX *)(&(curr_rd[0].const_term)),
                    ((const uint32_t *)(chars)) + (i << PMPML_32_CHUNK_SIZE_LOG2));
            procesNextValue<bswap>(1, tmp_hash.QuadPart, allValues, cnts, flag);
        }

        // process remaining incomplete chunk(s)
        // note: if string size is a multiple of chunk size, we create a new chunk (1,0,0,...0),
        // so THIS PROCESSING IS ALWAYS PERFORMED
        unsigned int          tailCnt = cnt & (PMPML_32_CHUNK_SIZE_BYTES - 1);
        const unsigned char * tail    = chars + ((cnt >> PMPML_32_CHUNK_SIZE_BYTES_LOG2) << PMPML_32_CHUNK_SIZE_BYTES_LOG2);

        tmp_hash.QuadPart = hash_of_beginning_of_string_chunk_type2<bswap>(curr_rd[0].random_coeff,
                *(ULARGE_INTEGER__XX *)(&(curr_rd[0].const_term)), tail, tailCnt);
        procesNextValue<bswap>(1, tmp_hash.QuadPart, allValues, cnts, flag);
        ULARGE_INTEGER__XX ret64;
        ret64.QuadPart = finalize<bswap>(1, allValues, cnts, flag);
        if (ret64.HighPart == 0) {     // LIKELY
            return fmix32_short(ret64.LowPart);
        }
        return ret64.LowPart;
    }

  public:

    template <bool bswap>
    FORCE_INLINE uint32_t hash( const unsigned char * chars, unsigned int cnt ) const {
        if (likely(cnt < 32)) {
            const uint32_t *   coeff     = curr_rd[0].random_coeff;
            ULARGE_INTEGER__XX constTerm = *(ULARGE_INTEGER__XX *)(&(curr_rd[0].const_term));
            PMPML_CHUNK_LOOP_INTRO_L0
            uint32_t size = cnt >> PMPML_32_WORD_SIZE_BYTES_LOG2;
            uint32_t xLast;

            const uint32_t * x = (const uint32_t *)chars;

#if defined(_MSC_VER) && defined(HAVE_32BIT_PLATFORM)
// enables MSVC-specific code that appears to be more efficient than a regular one; comment out, if not desired
            switch (cnt) {
/*
 *                              case 0: {                       xLast = 0x1;    constTerm.QuadPart += coeff[ 0 ];       PMPML_FULL_REDUCE_MOD_2_32_PLUS_15_AND_RETURN_RETURN_32x32_ONLY;        }
 *          case 1: {                   xLast = 0x100 + chars[cnt-1];   constTerm.QuadPart += UInt32x32To64( coeff[ 0 ],
 * xLast );             PMPML_FULL_REDUCE_MOD_2_32_PLUS_15_AND_RETURN_RETURN_32x32_ONLY;        }
 *          case 2: {                   xLast = *((const unsigned short*)(chars + cnt - 2 )) + 0x10000; constTerm.QuadPart
 * += UInt32x32To64( coeff[ 0 ], xLast );               PMPML_FULL_REDUCE_MOD_2_32_PLUS_15_AND_RETURN_RETURN_32x32_ONLY;        }
 *          case 3: {                   xLast = chars[ cnt - 1 ]; xLast = ( xLast << 16 ) + *((const unsigned
 * short*)(chars + cnt - 3 )) + 0x1000000;      constTerm.QuadPart += UInt32x32To64( coeff[ 0 ], xLast );               PMPML_FULL_REDUCE_MOD_2_32_PLUS_15_AND_RETURN_RETURN_32x32_ONLY;        }
 *
 *          case 0:     {       xLast = 0x1;    PMPML_CHUNK_LOOP_BODY_ULI_T1_LAST;      break;  }
 *          case 1:     {       xLast = 0x100 + chars[cnt-1];   PMPML_CHUNK_LOOP_BODY_ULI_T1_LAST;      break;  }
 *          case 2:     {       xLast = *((const unsigned short*)(chars + cnt - 2 )) + 0x10000; PMPML_CHUNK_LOOP_BODY_ULI_T1_LAST;      break;  }
 *          case 3:     {       xLast = chars[ cnt - 1 ]; xLast = ( xLast << 16 ) + *((const unsigned short*)(chars +
 * cnt - 3 )) + 0x1000000;      PMPML_CHUNK_LOOP_BODY_ULI_T1_LAST;      break;  }
 */
            case 0 : {   return hash_size_SMALL_N<0, bswap>(chars);    }
            case 1 : {   return hash_size_SMALL_N<1, bswap>(chars);    }
            case 2 : {   return hash_size_SMALL_N<2, bswap>(chars);    }
            case 3 : {   return hash_size_SMALL_N<3, bswap>(chars);    }
            case 4 : {   return hash_size_SMALL_N<4, bswap>(chars);    }
//                      case 4: {       PMPML_CHUNK_LOOP_BODY_ULI_T1( 0 )       xLast = 0x1;    PMPML_CHUNK_LOOP_BODY_ULI_T1_LAST_FOR_JUST_1;   break;  }
            case 5 : {   PMPML_CHUNK_LOOP_BODY_ULI_T1(0)   xLast = 0x100 +
                                 chars[4];   PMPML_CHUNK_LOOP_BODY_ULI_T1_LAST;  break;  }
            case 6 : {   PMPML_CHUNK_LOOP_BODY_ULI_T1(0)   xLast =
                                 GET_U16<bswap>(chars, 4) + 0x10000; PMPML_CHUNK_LOOP_BODY_ULI_T1_LAST;  break;  }
            case 7 : {   PMPML_CHUNK_LOOP_BODY_ULI_T1(0)   xLast = chars[6];
                         xLast = (xLast << 16) + GET_U16<bswap>(chars, 4) + 0x1000000;
                         PMPML_CHUNK_LOOP_BODY_ULI_T1_LAST;  break;  }
            case  8: {   PMPML_CHUNK_LOOP_BODY_ULI_T1(0) PMPML_CHUNK_LOOP_BODY_ULI_T1(1)     xLast =
                                 0x1;    PMPML_CHUNK_LOOP_BODY_ULI_T1_LAST_FOR_JUST_1;   break;  }
            case  9: {   PMPML_CHUNK_LOOP_BODY_ULI_T1(0) PMPML_CHUNK_LOOP_BODY_ULI_T1(1)     xLast =
                                 0x100 + chars[8];   PMPML_CHUNK_LOOP_BODY_ULI_T1_LAST;  break;  }
            case 10: {   PMPML_CHUNK_LOOP_BODY_ULI_T1(0) PMPML_CHUNK_LOOP_BODY_ULI_T1(1)     xLast =
                                 GET_U16<bswap>(chars, 8) + 0x10000; PMPML_CHUNK_LOOP_BODY_ULI_T1_LAST;  break;  }
            case 11: {   PMPML_CHUNK_LOOP_BODY_ULI_T1(0) PMPML_CHUNK_LOOP_BODY_ULI_T1(1)     xLast = chars[10];
                         xLast = (xLast << 16) + GET_U16<bswap>(chars, 8) + 0x1000000;
                         PMPML_CHUNK_LOOP_BODY_ULI_T1_LAST;  break;  }
            case 12: {   PMPML_CHUNK_LOOP_BODY_ULI_T1(0) PMPML_CHUNK_LOOP_BODY_ULI_T1(1) PMPML_CHUNK_LOOP_BODY_ULI_T1(2)   xLast =
                                 0x1;    PMPML_CHUNK_LOOP_BODY_ULI_T1_LAST_FOR_JUST_1;   break;  }
            case 13: {   PMPML_CHUNK_LOOP_BODY_ULI_T1(0) PMPML_CHUNK_LOOP_BODY_ULI_T1(1) PMPML_CHUNK_LOOP_BODY_ULI_T1(2)   xLast =
                                 0x100 + chars[12];  PMPML_CHUNK_LOOP_BODY_ULI_T1_LAST;  break;  }
            case 14: {   PMPML_CHUNK_LOOP_BODY_ULI_T1(0) PMPML_CHUNK_LOOP_BODY_ULI_T1(1) PMPML_CHUNK_LOOP_BODY_ULI_T1(2)   xLast =
                                 GET_U16<bswap>(chars, 12) + 0x10000;    PMPML_CHUNK_LOOP_BODY_ULI_T1_LAST;  break;  }
            case 15: {   PMPML_CHUNK_LOOP_BODY_ULI_T1(0) PMPML_CHUNK_LOOP_BODY_ULI_T1(1) PMPML_CHUNK_LOOP_BODY_ULI_T1(2)   xLast =
                                 chars[14];
                         xLast = (xLast << 16) + GET_U16<bswap>(chars, 12) + 0x1000000;
                         PMPML_CHUNK_LOOP_BODY_ULI_T1_LAST;  break;  }
            case 16: {   PMPML_CHUNK_LOOP_BODY_ULI_T1(0) PMPML_CHUNK_LOOP_BODY_ULI_T1(1) PMPML_CHUNK_LOOP_BODY_ULI_T1(2)
                         PMPML_CHUNK_LOOP_BODY_ULI_T1(3)     xLast = 0x1;    PMPML_CHUNK_LOOP_BODY_ULI_T1_LAST_FOR_JUST_1;
                         break;  }
            case 17: {   PMPML_CHUNK_LOOP_BODY_ULI_T1(0) PMPML_CHUNK_LOOP_BODY_ULI_T1(1) PMPML_CHUNK_LOOP_BODY_ULI_T1(2)
                         PMPML_CHUNK_LOOP_BODY_ULI_T1(3)     xLast = 0x100 + chars[16];
                         PMPML_CHUNK_LOOP_BODY_ULI_T1_LAST;  break;  }
            case 18: {   PMPML_CHUNK_LOOP_BODY_ULI_T1(0) PMPML_CHUNK_LOOP_BODY_ULI_T1(1) PMPML_CHUNK_LOOP_BODY_ULI_T1(2)
                         PMPML_CHUNK_LOOP_BODY_ULI_T1(3)     xLast =
                                 GET_U16<bswap>(chars, 16) + 0x10000;    PMPML_CHUNK_LOOP_BODY_ULI_T1_LAST;  break;  }
            case 19: {   PMPML_CHUNK_LOOP_BODY_ULI_T1(0) PMPML_CHUNK_LOOP_BODY_ULI_T1(1) PMPML_CHUNK_LOOP_BODY_ULI_T1(2)
                         PMPML_CHUNK_LOOP_BODY_ULI_T1(3)     xLast = chars[18]; xLast = (xLast << 16) + GET_U16<bswap>(
                                 chars, 16) + 0x1000000;   PMPML_CHUNK_LOOP_BODY_ULI_T1_LAST;  break;  }
            case 20: {   PMPML_CHUNK_LOOP_BODY_ULI_T1(0) PMPML_CHUNK_LOOP_BODY_ULI_T1(1) PMPML_CHUNK_LOOP_BODY_ULI_T1(2)
                         PMPML_CHUNK_LOOP_BODY_ULI_T1(3) PMPML_CHUNK_LOOP_BODY_ULI_T1(4)   xLast =
                                 0x1;    PMPML_CHUNK_LOOP_BODY_ULI_T1_LAST_FOR_JUST_1;   break;  }
            case 21: {   PMPML_CHUNK_LOOP_BODY_ULI_T1(0) PMPML_CHUNK_LOOP_BODY_ULI_T1(1) PMPML_CHUNK_LOOP_BODY_ULI_T1(2)
                         PMPML_CHUNK_LOOP_BODY_ULI_T1(3) PMPML_CHUNK_LOOP_BODY_ULI_T1(4)   xLast =
                                 0x100 + chars[20];  PMPML_CHUNK_LOOP_BODY_ULI_T1_LAST;  break;  }
            case 22: {   PMPML_CHUNK_LOOP_BODY_ULI_T1(0) PMPML_CHUNK_LOOP_BODY_ULI_T1(1) PMPML_CHUNK_LOOP_BODY_ULI_T1(2)
                         PMPML_CHUNK_LOOP_BODY_ULI_T1(3) PMPML_CHUNK_LOOP_BODY_ULI_T1(4)   xLast =
                                 GET_U16<bswap>(chars, 20) + 0x10000;    PMPML_CHUNK_LOOP_BODY_ULI_T1_LAST;  break;  }
            case 23: {   PMPML_CHUNK_LOOP_BODY_ULI_T1(0) PMPML_CHUNK_LOOP_BODY_ULI_T1(1) PMPML_CHUNK_LOOP_BODY_ULI_T1(2)
                         PMPML_CHUNK_LOOP_BODY_ULI_T1(3) PMPML_CHUNK_LOOP_BODY_ULI_T1(4)   xLast = chars[22];
                         xLast = (xLast << 16) + GET_U16<bswap>(chars, 20) + 0x1000000;
                         PMPML_CHUNK_LOOP_BODY_ULI_T1_LAST;  break;  }
            case 24: {   PMPML_CHUNK_LOOP_BODY_ULI_T1(0) PMPML_CHUNK_LOOP_BODY_ULI_T1(1) PMPML_CHUNK_LOOP_BODY_ULI_T1(2)
                         PMPML_CHUNK_LOOP_BODY_ULI_T1(3) PMPML_CHUNK_LOOP_BODY_ULI_T1(4) PMPML_CHUNK_LOOP_BODY_ULI_T1(5)
                         xLast = 0x1;    PMPML_CHUNK_LOOP_BODY_ULI_T1_LAST_FOR_JUST_1;   break;  }
            case 25: {   PMPML_CHUNK_LOOP_BODY_ULI_T1(0) PMPML_CHUNK_LOOP_BODY_ULI_T1(1) PMPML_CHUNK_LOOP_BODY_ULI_T1(2)
                         PMPML_CHUNK_LOOP_BODY_ULI_T1(3) PMPML_CHUNK_LOOP_BODY_ULI_T1(4) PMPML_CHUNK_LOOP_BODY_ULI_T1(5)
                         xLast = 0x100 + chars[24];  PMPML_CHUNK_LOOP_BODY_ULI_T1_LAST;  break;  }
            case 26: {   PMPML_CHUNK_LOOP_BODY_ULI_T1(0) PMPML_CHUNK_LOOP_BODY_ULI_T1(1) PMPML_CHUNK_LOOP_BODY_ULI_T1(2)
                         PMPML_CHUNK_LOOP_BODY_ULI_T1(3) PMPML_CHUNK_LOOP_BODY_ULI_T1(4) PMPML_CHUNK_LOOP_BODY_ULI_T1(5)
                         xLast = GET_U16<bswap>(chars, 24) + 0x10000;    PMPML_CHUNK_LOOP_BODY_ULI_T1_LAST;  break;  }
            case 27: {   PMPML_CHUNK_LOOP_BODY_ULI_T1(0) PMPML_CHUNK_LOOP_BODY_ULI_T1(1) PMPML_CHUNK_LOOP_BODY_ULI_T1(2)
                         PMPML_CHUNK_LOOP_BODY_ULI_T1(3) PMPML_CHUNK_LOOP_BODY_ULI_T1(4) PMPML_CHUNK_LOOP_BODY_ULI_T1(5)
                         xLast = chars[26];
                         xLast = (xLast << 16) + GET_U16<bswap>(chars, 24) + 0x1000000;
                         PMPML_CHUNK_LOOP_BODY_ULI_T1_LAST;  break;  }

/*
 *                              case 28:        {       PMPML_CHUNK_LOOP_BODY_ULI_T1( 0 ) PMPML_CHUNK_LOOP_BODY_ULI_T1(
 * 1 ) PMPML_CHUNK_LOOP_BODY_ULI_T1( 2 ) PMPML_CHUNK_LOOP_BODY_ULI_T1( 3 ) PMPML_CHUNK_LOOP_BODY_ULI_T1( 4 )
 * PMPML_CHUNK_LOOP_BODY_ULI_T1( 5 ) PMPML_CHUNK_LOOP_BODY_ULI_T1( 6 )  xLast = 0x1;    PMPML_CHUNK_LOOP_BODY_ULI_T1_LAST_FOR_JUST_1;   break;  }
 *          case 29:    {       PMPML_CHUNK_LOOP_BODY_ULI_T1( 0 ) PMPML_CHUNK_LOOP_BODY_ULI_T1( 1 )
 * PMPML_CHUNK_LOOP_BODY_ULI_T1( 2 ) PMPML_CHUNK_LOOP_BODY_ULI_T1( 3 ) PMPML_CHUNK_LOOP_BODY_ULI_T1( 4 )
 * PMPML_CHUNK_LOOP_BODY_ULI_T1( 5 ) PMPML_CHUNK_LOOP_BODY_ULI_T1( 6 )  xLast = 0x100 + chars[28];      PMPML_CHUNK_LOOP_BODY_ULI_T1_LAST;      break;  }
 *          case 30:    {       PMPML_CHUNK_LOOP_BODY_ULI_T1( 0 ) PMPML_CHUNK_LOOP_BODY_ULI_T1( 1 )
 * PMPML_CHUNK_LOOP_BODY_ULI_T1( 2 ) PMPML_CHUNK_LOOP_BODY_ULI_T1( 3 ) PMPML_CHUNK_LOOP_BODY_ULI_T1( 4 )
 * PMPML_CHUNK_LOOP_BODY_ULI_T1( 5 ) PMPML_CHUNK_LOOP_BODY_ULI_T1( 6 )  xLast = *((const unsigned short*)(chars + 28 ))
 * + 0x10000;   PMPML_CHUNK_LOOP_BODY_ULI_T1_LAST;      break;  }
 *          default:    {       PMPML_CHUNK_LOOP_BODY_ULI_T1( 0 ) PMPML_CHUNK_LOOP_BODY_ULI_T1( 1 )
 * PMPML_CHUNK_LOOP_BODY_ULI_T1( 2 ) PMPML_CHUNK_LOOP_BODY_ULI_T1( 3 ) PMPML_CHUNK_LOOP_BODY_ULI_T1( 4 )
 * PMPML_CHUNK_LOOP_BODY_ULI_T1( 5 ) PMPML_CHUNK_LOOP_BODY_ULI_T1( 6 )  xLast = chars[ 30 ]; xLast = ( xLast << 16 ) +
 * *((const unsigned short*)(chars + 28 )) + 0x1000000; PMPML_CHUNK_LOOP_BODY_ULI_T1_LAST;      break;  }
 */
            case 28: {   return hash_size_28(chars);   }
            case 29: {   return hash_size_29(chars);   }
            case 30: {   return hash_size_30(chars);   }
            default: {   return hash_size_31(chars);   }
            }
#else
            switch (size) {
            case 0: { break; }
            case 1: {   PMPML_CHUNK_LOOP_BODY_ULI_T1(0) }
            break;
            case 2: {   PMPML_CHUNK_LOOP_BODY_ULI_T1(0) PMPML_CHUNK_LOOP_BODY_ULI_T1(1) }
            break;
            case 3: {   PMPML_CHUNK_LOOP_BODY_ULI_T1(0) PMPML_CHUNK_LOOP_BODY_ULI_T1(1) PMPML_CHUNK_LOOP_BODY_ULI_T1(2) }
            break;
            case 4: {   PMPML_CHUNK_LOOP_BODY_ULI_T1(0) PMPML_CHUNK_LOOP_BODY_ULI_T1(1) PMPML_CHUNK_LOOP_BODY_ULI_T1(2)
                        PMPML_CHUNK_LOOP_BODY_ULI_T1(3) }
                        break;
            case 5: {   PMPML_CHUNK_LOOP_BODY_ULI_T1(0) PMPML_CHUNK_LOOP_BODY_ULI_T1(1) PMPML_CHUNK_LOOP_BODY_ULI_T1(2)
                        PMPML_CHUNK_LOOP_BODY_ULI_T1(3) PMPML_CHUNK_LOOP_BODY_ULI_T1(4) }
                        break;
            case 6: {   PMPML_CHUNK_LOOP_BODY_ULI_T1(0) PMPML_CHUNK_LOOP_BODY_ULI_T1(1) PMPML_CHUNK_LOOP_BODY_ULI_T1(2)
                        PMPML_CHUNK_LOOP_BODY_ULI_T1(3) PMPML_CHUNK_LOOP_BODY_ULI_T1(4) PMPML_CHUNK_LOOP_BODY_ULI_T1(5) }
                        break;
            default: {   PMPML_CHUNK_LOOP_BODY_ULI_T1(0) PMPML_CHUNK_LOOP_BODY_ULI_T1(1) PMPML_CHUNK_LOOP_BODY_ULI_T1(2)
                         PMPML_CHUNK_LOOP_BODY_ULI_T1(3) PMPML_CHUNK_LOOP_BODY_ULI_T1(4) PMPML_CHUNK_LOOP_BODY_ULI_T1(5)
                         PMPML_CHUNK_LOOP_BODY_ULI_T1(6) }
                         break;
            }

            switch (cnt & (PMPML_32_WORD_SIZE_BYTES - 1)) {
            case 0: { xLast = 0x1; break; }
            case 1: { xLast = 0x100 + chars[cnt - 1]; break; }
            case 2: { xLast = GET_U16<bswap>(chars + cnt - 2, 0) + 0x10000; break; }
            default: { xLast = chars[cnt - 1]; xLast = (xLast << 16) + GET_U16<bswap>(chars + cnt - 3, 0) + 0x1000000; break; }
            }

            PMPML_CHUNK_LOOP_BODY_ULI_T1_LAST
#endif // PMPML_MSC_32_WORKAROUND

            PMPML_CHUNK_LOOP_PRE_REDUCE_L0

            PMPML_FULL_REDUCE_MOD_2_32_PLUS_15_AND_RETURN_RETURN
        } else if (cnt < PMPML_32_CHUNK_SIZE_BYTES) {
            return _hash_noRecursionNoInline_forLessThanChunk<bswap>(chars, cnt);
        } else {
            return _hash_noRecursionNoInline_type2<bswap>(chars, cnt);
        }
    }

    PMP_Multilinear_Hasher_32() {
        curr_rd = (random_data_for_PMPML_32 *)rd_for_PMPML_32;
        coeff0  = curr_rd[0].const_term;
    }

    void seed( uint64_t seed ) {
        curr_rd[0].const_term = coeff0 ^ seed;
    }
}; // class PMP_Multilinear_Hasher_32

//-------------------------------------------------------------
// 64-bit hash

static FORCE_INLINE void MultiplyWordLoHi( uint64_t & rlo, uint64_t & rhi, uint64_t a, uint64_t b ) {
    MathMult::mult64_128(rlo, rhi, a, b);
}

/*
 * Adds the 64-bit value in alo into the 128-bit
 * value spread across rhi:rlo.
 */
static FORCE_INLINE void AccumulateLoHi( uint64_t & rlo, uint64_t & rhi, uint64_t alo ) {
    MathMult::add128(rlo, rhi, alo);
}

/*
 * Adds the 192-bit value spread across ahi:ami:alo into the 192-bit
 * value spread across rhi:rmi:rlo.
 */
static FORCE_INLINE void AccumulateLoMidHi( uint64_t & rlo, uint64_t & rmi,
        uint64_t & rhi, uint64_t alo, uint64_t ami, uint64_t ahi ) {
    MathMult::add192(rlo, rmi, rhi, alo, ami, ahi);
}

/*
 * Does a 64x64->128 multiply on a and b, and adds the result into the
 * 192-bit value spread across rhi:rmi:rlo.
 */
static FORCE_INLINE void MultiplyAccumulateWordLoMidHi( uint64_t & rlo, uint64_t & rmi, uint64_t & rhi, uint64_t a, uint64_t b ) {
    MathMult::fma64_192(rlo, rmi, rhi, a, b);
}

/*
 * Does a 64x64->128 multiply on a and b, and adds the result into the
 * 128-bit value spread across rhi:rlo.
 */
static FORCE_INLINE void MultiplyAccumulateWordLoHi( uint64_t & rlo, uint64_t & rhi, uint64_t a, uint64_t b ) {
    MathMult::fma64_128(rlo, rhi, a, b);
}

#define ADD_SHIFT_ADD_NORMALIZE( lo, hi ) {             \
	uint32_t lohi = lo >> 32;                       \
	uint32_t hilo = hi;                             \
	uint32_t diff = lohi - hilo;                    \
	hi += diff;                                     \
	lo = (uint32_t)lo + (((uint64_t)(uint32_t)hi) << 32 );\
	hi >>= 32;                                      \
}

#define ADD_SHIFT_ADD_NORMALIZE_TO_UPPER( lo, hi ) { \
	uint32_t lohi = lo >> 32;                    \
	uint32_t hilo = hi;                          \
	uint32_t diff = lohi - hilo;                 \
	hi += diff;                                  \
	lo = (uint32_t)lo;                           \
}

#define PMPML_CHUNK_LOOP_INTRO_L0_64                  \
	  ULARGE_INTEGER__XX ctr0, ctr1, ctr2;        \
	  ctr0.QuadPart = constTerm.QuadPart;         \
	  ctr1.QuadPart = 0;                          \
	  ctr2.QuadPart = 0;                          \
	  ULARGE_INTEGER__XX ctr2_0, ctr2_1, ctr2_2, ctr2_3;\
	  ctr2_0.QuadPart = 0;                        \
	  ctr2_1.QuadPart = 0;                        \
	  ctr2_2.QuadPart = 0;                        \
	  ctr2_3.QuadPart = 0;                        \
	  ULARGE_INTEGER__XX mulLow, mulHigh;

#define PMPML_64_CHUNK_LOOP_BODY_ULI_T1_SECOND( i ) {                                         \
    uint64_t xi = GET_U64<bswap>((const uint8_t*)x,(i)*8);                                    \
    MultiplyAccumulateWordLoMidHi(ctr0.QuadPart, ctr1.QuadPart, ctr2.QuadPart, xi, coeff[i]); \
}

#define PMPML_64_CHUNK_LOOP_BODY_ULI_T1_FIRST( ii ) {                                                 \
    uint64_t xii = GET_U64<bswap>((const uint8_t*)x,(ii)*8);                                          \
    MultiplyAccumulateWordLoMidHi(ctr2_0.QuadPart, ctr2_1.QuadPart, ctr2_2.QuadPart, xii, coeff[ii]); \
}

#define PMPML_64_CHUNK_LOOP_BODY_ULI_T1(i) PMPML_64_CHUNK_LOOP_BODY_ULI_T1_SECOND(i)

#define _compensate_ {                                                                                                 \
    AccumulateLoMidHi(ctr0.QuadPart, ctr1.QuadPart, ctr2.QuadPart, ctr2_0.QuadPart, ctr2_1.QuadPart, ctr2_2.QuadPart); \
}

#define PMPML_64_CHUNK_LOOP_BODY_ULI_T1_LAST( size ) {                                              \
    MultiplyAccumulateWordLoMidHi(ctr0.QuadPart, ctr1.QuadPart, ctr2.QuadPart, xLast, coeff[size]); \
}

#define PMPML_64_CHUNK_LOOP_BODY_ULI_T2( i )  {                                                                      \
    if (likely(x[i].HighPart == 0)) {                                                                                \
      MultiplyAccumulateWordLoMidHi(ctr0.QuadPart, ctr1.QuadPart, ctr2.QuadPart, x[i].LowPart, coeff[i]);            \
    } else {                                                                                                         \
      MultiplyWordLoHi(mulLow.QuadPart, mulHigh.QuadPart, x[i].LowPart, coeff[i]);                                   \
      mulHigh.QuadPart += x[i].HighPart * coeff[i];                                                                  \
      MultiplyAccumulateWordLoMidHi(ctr0.QuadPart, ctr1.QuadPart, ctr2.QuadPart, mulLow.QuadPart, mulHigh.QuadPart); \
    }                                                                                                                \
}

#define PMPML_64_CHUNK_LOOP_BODY_ULI_ADD_COEFF( i ) {         \
  AccumulateLoHi(c_ctr0.QuadPart, c_ctr1.QuadPart, coeff[i]); \
}

#define PMPML_CHUNK_LOOP_BODY_ULI_T2_AND_ADD_COEFF_64( i ) {                                                         \
    AccumulateLoHi(c_ctr0.QuadPart, c_ctr1.QuadPart, coeff[i]);                                                      \
    if (likely(x[i].HighPart == 0)) {                                                                                \
      MultiplyAccumulateWordLoMidHi(ctr0.QuadPart, ctr1.QuadPart, ctr2.QuadPart, x[i].LowPart, coeff[i]);            \
    } else {                                                                                                         \
      MultiplyWordLoHi(mulLow.QuadPart, mulHigh.QuadPart, x[i].LowPart, coeff[i]);                                   \
      mulHigh.QuadPart += x[i].HighPart * coeff[i];                                                                  \
      MultiplyAccumulateWordLoMidHi(ctr0.QuadPart, ctr1.QuadPart, ctr2.QuadPart, mulLow.QuadPart, mulHigh.QuadPart); \
    }                                                                                                                \
}

#define PMPML_CHUNK_LOOP_BODY_ULI_T2_AND_ADD_SUM_OF_COEFF_64 {                                                  \
    MultiplyAccumulateWordLoMidHi(ctr0.QuadPart, ctr1.QuadPart, ctr2.QuadPart, c_ctr0.QuadPart, prevConstTerm); \
    MultiplyAccumulateWordLoHi(ctr1.QuadPart, ctr2.QuadPart, c_ctr1.QuadPart, prevConstTerm);                   \
}

#define PMPML_CHUNK_LOOP_PRE_REDUCE_L0_64

#define PMPML_CHUNK_REDUCE_128_TO_64                    \
    {                                                   \
	uint64_t hi, lo;                                    \
	MultiplyWordLoHi(lo, hi, ctr1.QuadPart, 13);        \
	uint64_t part = ctr2.QuadPart * 169 + hi * 13 + 13; \
	ctr0.QuadPart += part;                              \
	ctr1.QuadPart = 1 + (ctr0.QuadPart < part);         \
	ctr1.QuadPart -= (ctr0.QuadPart < lo);              \
	ctr0.QuadPart -= lo;                                \
	if ( likely( ctr0.QuadPart >= 26) ) {               \
        ctr0.QuadPart -= ctr1.QuadPart * 13;            \
        ctr1.QuadPart = 0;                              \
	} else {                                            \
		ctr0.QuadPart -= ctr1.QuadPart * 13;            \
		if ( ctr0.QuadPart < 26 ) {                     \
            ctr1.QuadPart = 0;                          \
		} else {                                        \
			ctr0.QuadPart += 13;                        \
			if ( ctr0.QuadPart < 13 ) {                 \
                ctr1.QuadPart = 1;                      \
			} else {                                    \
                ctr1.QuadPart = 0;                      \
            }                                           \
		}                                               \
	}                                                   \
}

#define PMPML_CHUNK_REDUCE_128_TO_64____                \
{                                                       \
	_compensate_                                        \
    uint64_t hi, lo;                                    \
	MultiplyWordLoHi(lo, hi, ctr1.QuadPart, 13);        \
	uint64_t part = ctr2.QuadPart * 169 + hi * 13 + 13; \
	ctr0.QuadPart += part;                              \
	ctr1.QuadPart = 1 + (ctr0.QuadPart < part);         \
	ctr1.QuadPart -= (ctr0.QuadPart < lo);              \
	ctr0.QuadPart -= lo;                                \
	if ( likely( ctr0.QuadPart >= 26) ) {               \
        ctr0.QuadPart -= ctr1.QuadPart * 13;            \
        ctr1.QuadPart = 0;                              \
	} else {                                            \
		ctr0.QuadPart -= ctr1.QuadPart * 13;            \
		if ( ctr0.QuadPart < 26 ) {                     \
            ctr1.QuadPart = 0;                          \
		} else {                                        \
			ctr0.QuadPart += 13;                        \
			if ( ctr0.QuadPart < 13 ) {                 \
                ctr1.QuadPart = 1;                      \
			} else {                                    \
                ctr1.QuadPart = 0;                      \
            }                                           \
		}                                               \
	}                                                   \
}

#define PMPML_CHUNK_REDUCE_128_TO_64_AND_RETURN         \
{                                                       \
	uint64_t hi, lo;                                    \
	MultiplyWordLoHi(lo, hi, ctr1.QuadPart, 13);        \
	uint64_t part = ctr2.QuadPart * 169 + hi * 13 + 13; \
	ctr0.QuadPart += part;                              \
	ctr1.QuadPart = 1 + (ctr0.QuadPart < part);         \
	ctr1.QuadPart -= (ctr0.QuadPart < lo);              \
	ctr0.QuadPart -= lo;                                \
	if ( likely( ctr0.QuadPart >= 26) ) {               \
        ctr0.QuadPart -= ctr1.QuadPart * 13;            \
        return fmix64_short( ctr0.QuadPart );           \
	} else {                                            \
		ctr0.QuadPart -= ctr1.QuadPart * 13;            \
		if ( ctr0.QuadPart < 26 ) {                     \
            return fmix64_short( ctr0.QuadPart );       \
		} else {                                        \
			ctr0.QuadPart += 13;                        \
			return fmix64_short( ctr0.QuadPart );       \
		}                                               \
	}                                                   \
}

template <bool bswap>
static uint64_t ReadTail( const uint8_t * tail, uint64_t tail_size ) {
    uint64_t xLast;

    switch (tail_size & (PMPML_64_WORD_SIZE_BYTES - 1)) {
    case 0: { xLast = 0x1; break; }
    case 1: { xLast = 0x100 + tail[tail_size - 1]; break; }
    case 2: { xLast = GET_U16<bswap>(tail + tail_size - 2, 0) + 0x10000; break; }
    case 3: { xLast = tail[tail_size - 1]; xLast = (xLast << 16) + GET_U16<bswap>(tail + tail_size - 3, 0) + 0x1000000; break; }
    case 4: { xLast = GET_U32<bswap>(tail + tail_size - 4, 0) + UINT64_C(0x100000000); break; }
    case 5: { xLast = tail[tail_size - 1]; xLast = (xLast << 32) + UINT64_C(0x10000000000) + GET_U32<bswap>(
                tail + tail_size - 5, 0); break; }
    case 6: { xLast = GET_U16<bswap>(tail + tail_size - 2, 0); xLast = (xLast << 32) + UINT64_C(0x1000000000000) + GET_U32<bswap>(
                tail + tail_size - 6, 0); break; }
    default: { xLast  = tail[tail_size - 1]; xLast <<= 48;
               uint64_t xLast1 = GET_U16<bswap>(tail + tail_size - 3, 0);
               xLast += (xLast1 << 32) + UINT64_C(0x100000000000000) + GET_U32<bswap>(tail + tail_size - 7, 0); break; }
    }

    return xLast;
}

class PMP_Multilinear_Hasher_64 {
  private:
    random_data_for_PMPML_64 * curr_rd;
    uint64_t  coeff0;

    // calls to be done from LEVEL=0
    template <bool bswap>
    FORCE_INLINE void hash_of_string_chunk_compact( const uint64_t * coeff, ULARGE_INTEGER__XX constTerm,
            const uint64_t * x, ULARGELARGE_INTEGER__XX & ret ) const {
        PMPML_CHUNK_LOOP_INTRO_L0_64

#if defined(HAVE_AVX2) && (PMPML_64_CHUNK_SIZE_LOG2 >= 3)
        __m256i sse_ctr0_0, sse_ctr0_1, sse_ctr1, sse_ctr2, sse_ctr3_0, sse_ctr3_1,
        a, a_shifted, a_low, data, data_low, product, temp, mask_low;
        sse_ctr0_0 = _mm256_setzero_si256(); // Sets the 128-bit value to zero.
        sse_ctr0_1 = _mm256_setzero_si256(); // Sets the 128-bit value to zero.
        sse_ctr1   = _mm256_setzero_si256();
        sse_ctr2   = _mm256_setzero_si256();
        sse_ctr3_0 = _mm256_setzero_si256();
        sse_ctr3_1 = _mm256_setzero_si256();
        mask_low   = _mm256_set_epi32(0, -1, 0, -1, 0, -1, 0, -1);

  #if (PMPML_64_CHUNK_SIZE_LOG2 >= 4)
        for (uint64_t i = 0; i < (PMPML_64_CHUNK_SIZE); i += 16)
  #else
        for (uint64_t i = 0; i < (PMPML_64_CHUNK_SIZE); i += 8)
  #endif
        {
            a    = _mm256_load_si256((__m256i * )(coeff + i)); // Loads 128-bit value. Address p must be 16-byte
                                                               // aligned.
            data = _mm256_loadu_si256((__m256i *)(x     + i)); // Loads 128-bit value. Address p does not need be
                                                               // 16-byte aligned.

            // lower 32 bits
            a_low      = _mm256_and_si256(mask_low, a   );
            data_low   = _mm256_and_si256(mask_low, data);
            product    = _mm256_mul_epu32(data_low, a_low); // A 128-bit value that contains two 64-bit unsigned
                                                            // integers. The result can be expressed by the following
                                                            // equations. r0 := a0 * b0; r1 := a2 * b2
            sse_ctr0_0 = _mm256_add_epi64(sse_ctr0_0, product); // sse_ctr0 = _mm256_add_epi64 ( sse_ctr0, temp );
            temp       = _mm256_srli_epi64(product, 32);    // Shifts the 2 signed or unsigned 64-bit integers in a
                                                            // right by count bits while shifting in zeros.
            sse_ctr0_1 = _mm256_add_epi64(sse_ctr0_1, temp);
            // temp = _mm256_and_si256 ( mask_low, product );

            PMPML_64_CHUNK_LOOP_BODY_ULI_T1_FIRST(4 + i)

            // first cross
            a_shifted = _mm256_srli_epi64(a, 32);
            product   = _mm256_mul_epu32(data_low, a_shifted); // A 128-bit value that contains two 64-bit unsigned
                                                               // integers. The result can be expressed by the following
                                                               // equations. r0 := a0 * b0; r1 := a2 * b2
            sse_ctr1  = _mm256_add_epi64(sse_ctr1, product); // sse_ctr1 = _mm256_add_epi64 ( sse_ctr1, temp );
            temp      = _mm256_srli_epi64(product, 32);        // Shifts the 2 signed or unsigned 64-bit integers in a
                                                               // right by count bits while shifting in zeros.
            sse_ctr2  = _mm256_add_epi64(sse_ctr2, temp);
            // temp = _mm256_and_si256 ( mask_low, product );

            PMPML_64_CHUNK_LOOP_BODY_ULI_T1_SECOND(5 + i)
            // second cross
            data     = _mm256_srli_epi64(data, 32);
            product  = _mm256_mul_epu32(data, a_low);  // A 128-bit value that contains two 64-bit unsigned integers.
                                                       // The result can be expressed by the following equations. r0 :=
                                                       // a0 * b0; r1 := a2 * b2
            sse_ctr1 = _mm256_add_epi64(sse_ctr1, product); // sse_ctr1 = _mm256_add_epi64 ( sse_ctr1, temp );
            temp     = _mm256_srli_epi64(product, 32); // Shifts the 2 signed or unsigned 64-bit integers in a right by
                                                       // count bits while shifting in zeros.
            sse_ctr2 = _mm256_add_epi64(sse_ctr2, temp);
            // temp = _mm256_and_si256 ( mask_low, product );

            PMPML_64_CHUNK_LOOP_BODY_ULI_T1_FIRST(6 + i)
            // upper 32 bits
            product    = _mm256_mul_epu32(data, a_shifted); // A 128-bit value that contains two 64-bit unsigned
                                                            // integers. The result can be expressed by the following
                                                            // equations. r0 := a0 * b0; r1 := a2 * b2
            sse_ctr3_0 = _mm256_add_epi64(sse_ctr3_0, product); // sse_ctr2 = _mm256_add_epi64 ( sse_ctr2, temp );
            temp       = _mm256_srli_epi64(product, 32);    // Shifts the 2 signed or unsigned 64-bit integers in a
                                                            // right by count bits while shifting in zeros.
            sse_ctr3_1 = _mm256_add_epi64(sse_ctr3_1, temp);
            // temp = _mm256_and_si256 ( mask_low, product );
            PMPML_64_CHUNK_LOOP_BODY_ULI_T1_SECOND(7 + i)

  #if (PMPML_64_CHUNK_SIZE_LOG2 >= 4)
            a    = _mm256_load_si256((__m256i * )(coeff + i + 8)); // Loads 128-bit value. Address p must be 16-byte
                                                                   // aligned.
            data = _mm256_loadu_si256((__m256i *)(x     + i + 8)); // Loads 128-bit value. Address p does not need be
                                                                   // 16-byte aligned.

            // lower 32 bits
            a_low      = _mm256_and_si256(mask_low, a   );
            data_low   = _mm256_and_si256(mask_low, data);
            product    = _mm256_mul_epu32(data_low, a_low); // A 128-bit value that contains two 64-bit unsigned
                                                            // integers. The result can be expressed by the following
                                                            // equations. r0 := a0 * b0; r1 := a2 * b2
            sse_ctr0_0 = _mm256_add_epi64(sse_ctr0_0, product); // sse_ctr0 = _mm256_add_epi64 ( sse_ctr0, temp );
            temp       = _mm256_srli_epi64(product, 32);    // Shifts the 2 signed or unsigned 64-bit integers in a
                                                            // right by count bits while shifting in zeros.
            sse_ctr0_1 = _mm256_add_epi64(sse_ctr0_1, temp);
            // temp = _mm256_and_si256 ( mask_low, product );

            PMPML_64_CHUNK_LOOP_BODY_ULI_T1_FIRST(12 + i)

            // first cross
            a_shifted = _mm256_srli_epi64(a, 32);
            product   = _mm256_mul_epu32(data_low, a_shifted); // A 128-bit value that contains two 64-bit unsigned
                                                               // integers. The result can be expressed by the following
                                                               // equations. r0 := a0 * b0; r1 := a2 * b2
            sse_ctr1  = _mm256_add_epi64(sse_ctr1, product); // sse_ctr1 = _mm256_add_epi64 ( sse_ctr1, temp );
            temp      = _mm256_srli_epi64(product, 32);        // Shifts the 2 signed or unsigned 64-bit integers in a
                                                               // right by count bits while shifting in zeros.
            sse_ctr2  = _mm256_add_epi64(sse_ctr2, temp);
            // temp = _mm256_and_si256 ( mask_low, product );

            PMPML_64_CHUNK_LOOP_BODY_ULI_T1_SECOND(13 + i)

            // second cross
            data     = _mm256_srli_epi64(data, 32);
            product  = _mm256_mul_epu32(data, a_low);  // A 128-bit value that contains two 64-bit unsigned integers.
                                                       // The result can be expressed by the following equations. r0 :=
                                                       // a0 * b0; r1 := a2 * b2
            sse_ctr1 = _mm256_add_epi64(sse_ctr1, product); // sse_ctr1 = _mm256_add_epi64 ( sse_ctr1, temp );
            temp     = _mm256_srli_epi64(product, 32); // Shifts the 2 signed or unsigned 64-bit integers in a right by
                                                       // count bits while shifting in zeros.
            sse_ctr2 = _mm256_add_epi64(sse_ctr2, temp);
            // temp = _mm256_and_si256 ( mask_low, product );

            PMPML_64_CHUNK_LOOP_BODY_ULI_T1_FIRST(14 + i)
            // upper 32 bits
            product    = _mm256_mul_epu32(data, a_shifted); // A 128-bit value that contains two 64-bit unsigned
                                                            // integers. The result can be expressed by the following
                                                            // equations. r0 := a0 * b0; r1 := a2 * b2
            sse_ctr3_0 = _mm256_add_epi64(sse_ctr3_0, product); // sse_ctr2 = _mm256_add_epi64 ( sse_ctr2, temp );
            temp       = _mm256_srli_epi64(product, 32);    // Shifts the 2 signed or unsigned 64-bit integers in a
                                                            // right by count bits while shifting in zeros.
            sse_ctr3_1 = _mm256_add_epi64(sse_ctr3_1, temp);
            // temp = _mm256_and_si256 ( mask_low, product );
            PMPML_64_CHUNK_LOOP_BODY_ULI_T1_SECOND(15 + i)
  #endif
        }

        uint64_t t0_0, t0_1, t1, t2, t3_0, t3_1;
        t0_0 = ((uint64_t *)(&sse_ctr0_0))[0] + ((uint64_t *)(&sse_ctr0_0))[1] +
                ((uint64_t *)(&sse_ctr0_0))[2] + ((uint64_t *)(&sse_ctr0_0))[3];
        t0_1 = ((uint64_t *)(&sse_ctr0_1))[0] + ((uint64_t *)(&sse_ctr0_1))[1] +
                ((uint64_t *)(&sse_ctr0_1))[2] + ((uint64_t *)(&sse_ctr0_1))[3];
        t1   = ((uint64_t *)(&sse_ctr1  ))[0] + ((uint64_t *)(&sse_ctr1  ))[1] +
                ((uint64_t *)(&sse_ctr1  ))[2] + ((uint64_t *)(&sse_ctr1  ))[3];
        t2   = ((uint64_t *)(&sse_ctr2  ))[0] + ((uint64_t *)(&sse_ctr2  ))[1] +
                ((uint64_t *)(&sse_ctr2  ))[2] + ((uint64_t *)(&sse_ctr2  ))[3];
        t3_0 = ((uint64_t *)(&sse_ctr3_0))[0] + ((uint64_t *)(&sse_ctr3_0))[1] +
                ((uint64_t *)(&sse_ctr3_0))[2] + ((uint64_t *)(&sse_ctr3_0))[3];
        t3_1 = ((uint64_t *)(&sse_ctr3_1))[0] + ((uint64_t *)(&sse_ctr3_1))[1] +
                ((uint64_t *)(&sse_ctr3_1))[2] + ((uint64_t *)(&sse_ctr3_1))[3];

        ADD_SHIFT_ADD_NORMALIZE_TO_UPPER(t0_0, t0_1)
        ADD_SHIFT_ADD_NORMALIZE_TO_UPPER(t1  , t2  )
        ADD_SHIFT_ADD_NORMALIZE_TO_UPPER(t3_0, t3_1)

        uint64_t add_sse1, add_sse2;

        t1            += t0_1;
        add_sse1       = t0_0         + (((uint64_t)(uint32_t)t1  ) << 32);
        ctr0.QuadPart += add_sse1;
        add_sse2       = ctr0.QuadPart < add_sse1;

        t2            += t3_0         + (t1 >> 32);
        t3_1          += t2 >> 32;

        add_sse2      += (uint32_t)t2 + (((uint64_t)(uint32_t)t3_1) << 32);
        ctr1.QuadPart += add_sse2;

        ctr2.QuadPart += (t3_1 >> 32) + (ctr1.QuadPart < add_sse2);

/*
 *      ctr0.LowPart = (uint32_t)t0_0;
 *  uint64_t upper64 = t0_1 + (t0_0>>32) + (uint64_t)(uint32_t)t1;
 *  ctr0.HighPart = (uint32_t)upper64;
 *
 *  upper64 = (upper64>>32) + (t1>>32) + t2 + (uint32_t)t3_0;
 *  ctr1.LowPart = (uint32_t)upper64;
 *
 *  upper64 = (upper64>>32) + (t3_0>>32) + (uint32_t)t3_1;
 *  ctr1.HighPart += (uint32_t)upper64;
 *
 *  ctr2.QuadPart = (upper64>>32) + (t3_1>>32);
 */

#else // defined(HAVE_AVX2) && (PMPML_64_CHUNK_SIZE_LOG2 >= 3)

        for (uint64_t i = 0; i < (PMPML_64_CHUNK_SIZE); i += 32) {
            PMPML_64_CHUNK_LOOP_BODY_ULI_T1_FIRST(0 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T1_SECOND(1 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T1_FIRST(2 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T1_SECOND(3 + i)
  #if (PMPML_64_CHUNK_SIZE_LOG2 > 2)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T1_FIRST(4 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T1_SECOND(5 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T1_FIRST(6 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T1_SECOND(7 + i)
  #endif
  #if (PMPML_64_CHUNK_SIZE_LOG2 > 3)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T1_FIRST(8 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T1_SECOND(9 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T1_FIRST(10 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T1_SECOND(11 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T1_FIRST(12 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T1_SECOND(13 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T1_FIRST(14 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T1_SECOND(15 + i)
  #endif
  #if (PMPML_64_CHUNK_SIZE_LOG2 > 4)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T1_FIRST(16 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T1_SECOND(17 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T1_FIRST(18 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T1_SECOND(19 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T1_FIRST(20 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T1_SECOND(21 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T1_FIRST(22 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T1_SECOND(23 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T1_FIRST(24 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T1_SECOND(25 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T1_FIRST(26 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T1_SECOND(27 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T1_FIRST(28 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T1_SECOND(29 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T1_FIRST(30 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T1_SECOND(31 + i)
  #endif
        }
#endif  // defined(HAVE_AVX2) && (PMPML_64_CHUNK_SIZE_LOG2 >= 3)

        PMPML_CHUNK_LOOP_PRE_REDUCE_L0_64

        PMPML_CHUNK_REDUCE_128_TO_64____
        ret.LowPart = ctr0.QuadPart;
        ret.HighPart = ctr1.QuadPart;
    }

    template <bool bswap>
    FORCE_INLINE void hash_of_beginning_of_string_chunk_short_type2( const uint64_t * coeff, ULARGE_INTEGER__XX constTerm,
            const uint8_t * tail, std::size_t tail_size, ULARGELARGE_INTEGER__XX & ret ) const {
        PMPML_CHUNK_LOOP_INTRO_L0_64
        std::size_t      size = tail_size >> PMPML_64_WORD_SIZE_BYTES_LOG2;
        const uint64_t * x    = (const uint64_t *)tail;

        switch (size) {
        case 1: { PMPML_64_CHUNK_LOOP_BODY_ULI_T1(0) }
        break;
        case 2: { PMPML_64_CHUNK_LOOP_BODY_ULI_T1(0) PMPML_64_CHUNK_LOOP_BODY_ULI_T1(1) }
        break;
        case 3: { PMPML_64_CHUNK_LOOP_BODY_ULI_T1(0) PMPML_64_CHUNK_LOOP_BODY_ULI_T1(1)
                  PMPML_64_CHUNK_LOOP_BODY_ULI_T1(2) }
                  break;
        case 4: { PMPML_64_CHUNK_LOOP_BODY_ULI_T1(0) PMPML_64_CHUNK_LOOP_BODY_ULI_T1(1)
                  PMPML_64_CHUNK_LOOP_BODY_ULI_T1(2) PMPML_64_CHUNK_LOOP_BODY_ULI_T1(3) }
                  break;
        case 5: { PMPML_64_CHUNK_LOOP_BODY_ULI_T1(0) PMPML_64_CHUNK_LOOP_BODY_ULI_T1(1)
                  PMPML_64_CHUNK_LOOP_BODY_ULI_T1(2) PMPML_64_CHUNK_LOOP_BODY_ULI_T1(3)
                  PMPML_64_CHUNK_LOOP_BODY_ULI_T1(4) }
                  break;
        case 6: { PMPML_64_CHUNK_LOOP_BODY_ULI_T1(0) PMPML_64_CHUNK_LOOP_BODY_ULI_T1(1)
                  PMPML_64_CHUNK_LOOP_BODY_ULI_T1(2) PMPML_64_CHUNK_LOOP_BODY_ULI_T1(3)
                  PMPML_64_CHUNK_LOOP_BODY_ULI_T1(4) PMPML_64_CHUNK_LOOP_BODY_ULI_T1(5) }
                  break;
        case 7: { PMPML_64_CHUNK_LOOP_BODY_ULI_T1(0) PMPML_64_CHUNK_LOOP_BODY_ULI_T1(1)
                  PMPML_64_CHUNK_LOOP_BODY_ULI_T1(2) PMPML_64_CHUNK_LOOP_BODY_ULI_T1(3)
                  PMPML_64_CHUNK_LOOP_BODY_ULI_T1(4) PMPML_64_CHUNK_LOOP_BODY_ULI_T1(5)
                  PMPML_64_CHUNK_LOOP_BODY_ULI_T1(6) }
                  break;
        }

        uint64_t xLast = ReadTail<bswap>(tail, tail_size);

        PMPML_64_CHUNK_LOOP_BODY_ULI_T1_LAST(size)

        PMPML_CHUNK_LOOP_PRE_REDUCE_L0_64
        PMPML_CHUNK_REDUCE_128_TO_64
        ret.LowPart  = ctr0.QuadPart;
        ret.HighPart = ctr1.QuadPart;
    }

    template <bool bswap>
    FORCE_INLINE void hash_of_beginning_of_string_chunk_type2( const uint64_t * coeff, ULARGE_INTEGER__XX constTerm,
            const uint8_t * tail, std::size_t tail_size, ULARGELARGE_INTEGER__XX & ret ) const {
        PMPML_CHUNK_LOOP_INTRO_L0_64
        std::size_t      size = tail_size >> PMPML_64_WORD_SIZE_BYTES_LOG2;
        const uint64_t * x    = (const uint64_t *)tail;

        for (uint32_t i = 0; i < (size >> 3); i++) {
            PMPML_64_CHUNK_LOOP_BODY_ULI_T1(0 + (i << 3))
            PMPML_64_CHUNK_LOOP_BODY_ULI_T1(1 + (i << 3))
            PMPML_64_CHUNK_LOOP_BODY_ULI_T1(2 + (i << 3))
            PMPML_64_CHUNK_LOOP_BODY_ULI_T1(3 + (i << 3))
#if (PMPML_64_CHUNK_SIZE_LOG2 > 2)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T1(4 + (i << 3))
            PMPML_64_CHUNK_LOOP_BODY_ULI_T1(5 + (i << 3))
            PMPML_64_CHUNK_LOOP_BODY_ULI_T1(6 + (i << 3))
            PMPML_64_CHUNK_LOOP_BODY_ULI_T1(7 + (i << 3))
#endif
        }

        uint64_t offset = size & 0xFFFFFFF8;

        switch (size & 0x7) {
        case 0: { break; }
        case 1: { PMPML_64_CHUNK_LOOP_BODY_ULI_T1(0 + offset) }
        break;
        case 2: { PMPML_64_CHUNK_LOOP_BODY_ULI_T1(0 + offset) PMPML_64_CHUNK_LOOP_BODY_ULI_T1(1 + offset) }
        break;
        case 3: { PMPML_64_CHUNK_LOOP_BODY_ULI_T1(0 + offset) PMPML_64_CHUNK_LOOP_BODY_ULI_T1(1 + offset)
                  PMPML_64_CHUNK_LOOP_BODY_ULI_T1(2 + offset) }
                  break;
        case 4: { PMPML_64_CHUNK_LOOP_BODY_ULI_T1(0 + offset) PMPML_64_CHUNK_LOOP_BODY_ULI_T1(1 + offset)
                  PMPML_64_CHUNK_LOOP_BODY_ULI_T1(2 + offset) PMPML_64_CHUNK_LOOP_BODY_ULI_T1(3 + offset) }
                  break;
        case 5: { PMPML_64_CHUNK_LOOP_BODY_ULI_T1(0 + offset) PMPML_64_CHUNK_LOOP_BODY_ULI_T1(1 + offset)
                  PMPML_64_CHUNK_LOOP_BODY_ULI_T1(2 + offset) PMPML_64_CHUNK_LOOP_BODY_ULI_T1(3 + offset)
                  PMPML_64_CHUNK_LOOP_BODY_ULI_T1(4 + offset) }
                  break;
        case 6: { PMPML_64_CHUNK_LOOP_BODY_ULI_T1(0 + offset) PMPML_64_CHUNK_LOOP_BODY_ULI_T1(1 + offset)
                  PMPML_64_CHUNK_LOOP_BODY_ULI_T1(2 + offset) PMPML_64_CHUNK_LOOP_BODY_ULI_T1(3 + offset)
                  PMPML_64_CHUNK_LOOP_BODY_ULI_T1(4 + offset) PMPML_64_CHUNK_LOOP_BODY_ULI_T1(5 + offset) }
                  break;
        case 7: { PMPML_64_CHUNK_LOOP_BODY_ULI_T1(0 + offset) PMPML_64_CHUNK_LOOP_BODY_ULI_T1(1 + offset)
                  PMPML_64_CHUNK_LOOP_BODY_ULI_T1(2 + offset) PMPML_64_CHUNK_LOOP_BODY_ULI_T1(3 + offset)
                  PMPML_64_CHUNK_LOOP_BODY_ULI_T1(4 + offset) PMPML_64_CHUNK_LOOP_BODY_ULI_T1(5 + offset)
                  PMPML_64_CHUNK_LOOP_BODY_ULI_T1(6 + offset) }
                  break;
        }

        uint64_t xLast = ReadTail<bswap>(tail, tail_size);

        PMPML_64_CHUNK_LOOP_BODY_ULI_T1_LAST(size)

        PMPML_CHUNK_LOOP_PRE_REDUCE_L0_64
        PMPML_CHUNK_REDUCE_128_TO_64
        ret.LowPart  = ctr0.QuadPart;
        ret.HighPart = ctr1.QuadPart;
    }

    // a call to be done from subsequent levels
    FORCE_INLINE void hash_of_num_chunk( const uint64_t * coeff, ULARGE_INTEGER__XX constTerm,
            const ULARGELARGE_INTEGER__XX * x, ULARGELARGE_INTEGER__XX & ret ) const {
        ULARGE_INTEGER__XX ctr0, ctr1, ctr2;

        ctr0.QuadPart = constTerm.QuadPart;
        ctr1.QuadPart = 0;
        ctr2.QuadPart = 0;
        ULARGE_INTEGER__XX mulLow, mulHigh;

        for (uint64_t i = 0; i < (PMPML_64_CHUNK_SIZE); i += 32) {
            PMPML_64_CHUNK_LOOP_BODY_ULI_T2( 0 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T2( 1 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T2( 2 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T2( 3 + i)
#if (PMPML_64_CHUNK_SIZE_LOG2 > 2)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T2( 4 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T2( 5 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T2( 6 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T2( 7 + i)
#endif
#if (PMPML_64_CHUNK_SIZE_LOG2 > 3)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T2( 8 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T2( 9 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T2(10 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T2(11 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T2(12 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T2(13 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T2(14 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T2(15 + i)
#endif
#if (PMPML_64_CHUNK_SIZE_LOG2 > 4)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T2(16 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T2(17 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T2(18 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T2(19 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T2(20 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T2(21 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T2(22 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T2(23 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T2(24 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T2(25 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T2(26 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T2(27 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T2(28 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T2(29 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T2(30 + i)
            PMPML_64_CHUNK_LOOP_BODY_ULI_T2(31 + i)
#endif
        }

        PMPML_CHUNK_REDUCE_128_TO_64

        ret.LowPart = ctr0.QuadPart;
        ret.HighPart = ctr1.QuadPart;
    }

    // a call to be done from subsequent levels
    FORCE_INLINE void hash_of_num_chunk_incomplete( const uint64_t * coeff, uint64_t constTerm,
            uint64_t prevConstTerm, uint64_t coeffSumLow, uint64_t coeffSumHigh, const ULARGELARGE_INTEGER__XX * x,
            size_t count, ULARGELARGE_INTEGER__XX & ret ) const {
        ULARGE_INTEGER__XX ctr0, ctr1, ctr2;

        ctr0.QuadPart   = constTerm;
        ctr1.QuadPart   = 0;
        ctr2.QuadPart   = 0;
        ULARGE_INTEGER__XX c_ctr0, c_ctr1;
        c_ctr0.QuadPart = 0;
        c_ctr1.QuadPart = 0;
        ULARGE_INTEGER__XX mulLow, mulHigh;
        uint64_t           i;
        if (count < (PMPML_64_CHUNK_SIZE >> 1)) {
            for (i = 0; i < count; i++) {
                PMPML_CHUNK_LOOP_BODY_ULI_T2_AND_ADD_COEFF_64(i);
            }
            if (c_ctr0.QuadPart > coeffSumLow) {
                c_ctr1.QuadPart = coeffSumHigh - c_ctr1.QuadPart - 1;
            } else {
                c_ctr1.QuadPart = coeffSumHigh - c_ctr1.QuadPart;
            }
            c_ctr0.QuadPart = coeffSumLow - c_ctr0.QuadPart;
        } else {
            for (i = 0; i < count; i++) {
                PMPML_64_CHUNK_LOOP_BODY_ULI_T2(i)
            }
            for (; i < PMPML_64_CHUNK_SIZE; i++) {
                PMPML_64_CHUNK_LOOP_BODY_ULI_ADD_COEFF(i)
            }
        }
        PMPML_CHUNK_LOOP_BODY_ULI_T2_AND_ADD_SUM_OF_COEFF_64

        PMPML_CHUNK_REDUCE_128_TO_64

        ret.LowPart = ctr0.QuadPart;
        ret.HighPart = ctr1.QuadPart;
    }

    FORCE_INLINE void procesNextValue( int level, _ULARGELARGE_INTEGER__XX & value, _ULARGELARGE_INTEGER__XX * allValues,
            std::size_t * cnts, std::size_t & flag ) const {
        for (int i = level;; i++) {
            // NOTE: it's not necessary to check whether ( i < PMPML_64_LEVELS ),
            // if it is guaranteed that the string size is less than 1 << USHF_MACHINE_WORD_SIZE_BITS
            allValues[(i << PMPML_64_CHUNK_SIZE_LOG2) + cnts[i]] = value;
            (cnts[i])++;
            if (cnts[i] != PMPML_64_CHUNK_SIZE) {
                break;
            }
            cnts[i] = 0;
            hash_of_num_chunk(curr_rd[i].random_coeff, *(ULARGE_INTEGER__XX *)(&(curr_rd[i].const_term)),
                    allValues + (i << PMPML_64_CHUNK_SIZE_LOG2), value);
            if ((flag & (1 << i)) == 0) {
                cnts[i + 1] = 0;
                flag       |= 1 << i;
            }
        }
    }

    FORCE_INLINE _ULARGELARGE_INTEGER__XX & finalize( int level, _ULARGELARGE_INTEGER__XX * allValues,
            std::size_t * cnts, std::size_t & flag ) const {
        ULARGELARGE_INTEGER__XX value;

        for (int i = level;; i++) {
//              ASSERT ( level != PMPML_LEVELS )
            if (((flag & (1 << i)) == 0) && (cnts[i] == 1)) {
                return allValues[i << PMPML_64_CHUNK_SIZE_LOG2];
            }
            if (cnts[i]) {
                if ((flag & (1 << i)) == 0) {
                    cnts[i + 1] = 0;
                    flag       |= 1 << i;
                }
                hash_of_num_chunk_incomplete(curr_rd[i].random_coeff, curr_rd[i].const_term, curr_rd[i].const_term,
                        curr_rd[i].cachedSumLow, curr_rd[i].cachedSumHigh, allValues + (i << PMPML_64_CHUNK_SIZE_LOG2),
                        cnts[i], value);
                procesNextValue(i + 1, value, allValues, cnts, flag);
            }
        }
    }

    template <bool bswap>
    NEVER_INLINE uint64_t _hash_noRecursionNoInline_SingleChunk( const uint8_t * chars, std::size_t cnt ) const {
        _ULARGELARGE_INTEGER__XX tmp_hash;

        hash_of_beginning_of_string_chunk_type2<bswap>(curr_rd[0].random_coeff, *(ULARGE_INTEGER__XX *)(&(curr_rd[0].const_term)),
                chars, cnt, tmp_hash);
        if (tmp_hash.HighPart == 0) {
            return fmix64_short(tmp_hash.LowPart);
        }
        return tmp_hash.LowPart;
    }

    template <bool bswap>
    NEVER_INLINE uint64_t _hash_noRecursionNoInline_type2( const uint8_t * chars, std::size_t cnt ) const {
        _ULARGELARGE_INTEGER__XX allValues[PMPML_64_LEVELS * PMPML_64_CHUNK_SIZE];
        std::size_t cnts[PMPML_64_LEVELS];
        std::size_t flag;

        cnts[1] = 0;
        flag    = 0;

        std::size_t i;
        _ULARGELARGE_INTEGER__XX tmp_hash;
        // process full chunks
        for (i = 0; i < (cnt >> PMPML_64_CHUNK_SIZE_BYTES_LOG2); i++) {
            hash_of_string_chunk_compact<bswap>(curr_rd[0].random_coeff, *(ULARGE_INTEGER__XX *)(&(curr_rd[0].const_term)),
                    ((const uint64_t *)(chars)) + (i << PMPML_64_CHUNK_SIZE_LOG2), tmp_hash);
            procesNextValue(1, tmp_hash, allValues, cnts, flag);
        }
        // process remaining incomplete chunk(s)
        // note: if string size is a multiple of chunk size, we create a new chunk (1,0,0,...0),
        // so THIS PROCESSING IS ALWAYS PERFORMED
        std::size_t     tailCnt = cnt & (PMPML_64_CHUNK_SIZE_BYTES - 1);
        const uint8_t * tail    = chars + ((cnt >> PMPML_64_CHUNK_SIZE_BYTES_LOG2) << PMPML_64_CHUNK_SIZE_BYTES_LOG2);
        hash_of_beginning_of_string_chunk_type2<bswap>(curr_rd[0].random_coeff, *(ULARGE_INTEGER__XX *)(&(curr_rd[0].const_term)),
                tail, tailCnt, tmp_hash);
        procesNextValue(1, tmp_hash, allValues, cnts, flag);
        _ULARGELARGE_INTEGER__XX finRet = finalize(1, allValues, cnts, flag);
        if (finRet.HighPart == 0) { // LIKELY
            return fmix64_short(finRet.LowPart);
        }
        return finRet.LowPart;
    }

  public:

    template <bool bswap>
    FORCE_INLINE uint64_t hash( const uint8_t * chars, std::size_t cnt ) const {
        if (likely(cnt < 64)) {
            const uint64_t *   coeff     = curr_rd[0].random_coeff;
            ULARGE_INTEGER__XX constTerm = *(ULARGE_INTEGER__XX *)(&(curr_rd[0].const_term));
            PMPML_CHUNK_LOOP_INTRO_L0_64
            std::size_t      size        = cnt >> PMPML_64_WORD_SIZE_BYTES_LOG2;
            const uint64_t * x = (const uint64_t *)chars;

            switch (size) {
            case 1: { PMPML_64_CHUNK_LOOP_BODY_ULI_T1(0) }
            break;
            case 2: { PMPML_64_CHUNK_LOOP_BODY_ULI_T1(0) PMPML_64_CHUNK_LOOP_BODY_ULI_T1(1) }
            break;
            case 3: { PMPML_64_CHUNK_LOOP_BODY_ULI_T1(0) PMPML_64_CHUNK_LOOP_BODY_ULI_T1(1)
                      PMPML_64_CHUNK_LOOP_BODY_ULI_T1(2) }
                      break;
            case 4: { PMPML_64_CHUNK_LOOP_BODY_ULI_T1(0) PMPML_64_CHUNK_LOOP_BODY_ULI_T1(1)
                      PMPML_64_CHUNK_LOOP_BODY_ULI_T1(2) PMPML_64_CHUNK_LOOP_BODY_ULI_T1(3) }
                      break;
            case 5: { PMPML_64_CHUNK_LOOP_BODY_ULI_T1(0) PMPML_64_CHUNK_LOOP_BODY_ULI_T1(1)
                      PMPML_64_CHUNK_LOOP_BODY_ULI_T1(2) PMPML_64_CHUNK_LOOP_BODY_ULI_T1(3)
                      PMPML_64_CHUNK_LOOP_BODY_ULI_T1(4) }
                      break;
            case 6: { PMPML_64_CHUNK_LOOP_BODY_ULI_T1(0) PMPML_64_CHUNK_LOOP_BODY_ULI_T1(1)
                      PMPML_64_CHUNK_LOOP_BODY_ULI_T1(2) PMPML_64_CHUNK_LOOP_BODY_ULI_T1(3)
                      PMPML_64_CHUNK_LOOP_BODY_ULI_T1(4) PMPML_64_CHUNK_LOOP_BODY_ULI_T1(5) }
                      break;
            case 7: { PMPML_64_CHUNK_LOOP_BODY_ULI_T1(0) PMPML_64_CHUNK_LOOP_BODY_ULI_T1(1)
                      PMPML_64_CHUNK_LOOP_BODY_ULI_T1(2) PMPML_64_CHUNK_LOOP_BODY_ULI_T1(3)
                      PMPML_64_CHUNK_LOOP_BODY_ULI_T1(4) PMPML_64_CHUNK_LOOP_BODY_ULI_T1(5)
                      PMPML_64_CHUNK_LOOP_BODY_ULI_T1(6) }
                      break;
            }

            uint64_t xLast = ReadTail<bswap>(chars, cnt);

            PMPML_64_CHUNK_LOOP_BODY_ULI_T1_LAST(size);

            PMPML_CHUNK_LOOP_PRE_REDUCE_L0_64;
            PMPML_CHUNK_REDUCE_128_TO_64_AND_RETURN;
        } else if (cnt < PMPML_64_CHUNK_SIZE) {
            return _hash_noRecursionNoInline_SingleChunk<bswap>(chars, cnt);
        } else {
            return _hash_noRecursionNoInline_type2<bswap>(chars, cnt);
        }
    }

  public:

    PMP_Multilinear_Hasher_64() {
        curr_rd = (random_data_for_PMPML_64 *)rd_for_PMPML_64;
        coeff0  = curr_rd[0].random_coeff[0];
    }

    void seed( uint64_t seed ) {
        curr_rd[0].random_coeff[0] = coeff0 ^ seed;
    }
}; // class PMP_Multilinear_Hasher_64

//-------------------------------------------------------------
// SMHasher3 API functions

static thread_local PMP_Multilinear_Hasher_32 pmpml_hasher_32;
static thread_local PMP_Multilinear_Hasher_64 pmpml_hasher_64;

static uintptr_t PMPML_32_seed( const seed_t seed ) {
    pmpml_hasher_32.seed((uint64_t)seed);
    return (uintptr_t)(&pmpml_hasher_32);
}

static uintptr_t PMPML_64_seed( const seed_t seed ) {
    pmpml_hasher_64.seed((uint64_t)seed);
    return (uintptr_t)(&pmpml_hasher_64);
}

template <bool bswap>
static void PMPML_32( const void * in, const size_t len, const seed_t seed, void * out ) {
    PMP_Multilinear_Hasher_32 * p = (PMP_Multilinear_Hasher_32 *)(uintptr_t)seed;
    uint32_t h = p->hash<bswap>((const uint8_t *)in, len);

    PUT_U32<bswap>(h, (uint8_t *)out, 0);
}

template <bool bswap>
static void PMPML_64( const void * in, const size_t len, const seed_t seed, void * out ) {
    PMP_Multilinear_Hasher_64 * p = (PMP_Multilinear_Hasher_64 *)(uintptr_t)seed;
    uint64_t h = p->hash<bswap>((const uint8_t *)in, len);

    PUT_U64<bswap>(h, (uint8_t *)out, 0);
}

REGISTER_FAMILY(PMP_mutilinear,
   $.src_url    = "https://github.com/lemire/StronglyUniversalStringHashing",
   $.src_status = HashFamilyInfo::SRC_FROZEN
 );

REGISTER_HASH(PMP_Multilinear_32,
   $.desc       = "PMP_Multilinear 32-bit",
   $.hash_flags =
         FLAG_HASH_LOOKUP_TABLE,
   $.impl_flags =
         FLAG_IMPL_TYPE_PUNNING |
         FLAG_IMPL_MULTIPLY     |
         FLAG_IMPL_LICENSE_BSD  |
         FLAG_IMPL_SLOW,
   $.bits = 32,
   $.verification_LE = 0xF3199670,
   $.verification_BE = 0xF602E963,
   $.seedfn          = PMPML_32_seed,
   $.hashfn_native   = PMPML_32<false>,
   $.hashfn_bswap    = PMPML_32<true>
 );

REGISTER_HASH(PMP_Multilinear_64,
   $.desc       = "PMP_Multilinear 64-bit",
   $.hash_flags =
         FLAG_HASH_LOOKUP_TABLE,
   $.impl_flags =
         FLAG_IMPL_TYPE_PUNNING     |
         FLAG_IMPL_MULTIPLY_64_128  |
         FLAG_IMPL_LICENSE_BSD,
   $.bits = 64,
   $.verification_LE = 0xB776D2B9,
   $.verification_BE = 0x8E1E0CDF,
   $.seedfn          = PMPML_64_seed,
   $.hashfn_native   = PMPML_64<false>,
   $.hashfn_bswap    = PMPML_64<true>
 );
