/*
 * HalftimeHash
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
 * Copyright (c) 2020 Jim Apple
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */
#include "Platform.h"
#include "Hashlib.h"

#include "Intrinsics.h"

#include <cassert>
#include <climits>
#include <cstring>
#include <initializer_list>
#include <type_traits>

//------------------------------------------------------------
namespace halftime_hash {
    namespace advanced {
        namespace {
//------------------------------------------------------------
            inline uint64_t Xor( uint64_t a, uint64_t b ) { return a ^ b; }

            inline uint64_t Plus( uint64_t a, uint64_t b ) { return a + b; }

            inline uint64_t Minus( uint64_t a, uint64_t b ) { return a - b; }

            inline uint64_t LeftShift( uint64_t a, int s ) { return a << s; }

            inline uint64_t RightShift32( uint64_t a ) { return a >> 32; }

            inline uint64_t Sum( uint64_t a ) { return a; }

            inline uint64_t Negate( uint64_t a ) { return -a; }

            inline uint64_t Plus32( uint64_t a, uint64_t b ) {
                uint64_t result;
                uint32_t temp[2] = {
                    (uint32_t)a + (uint32_t)b,
                    (uint32_t)(a >> 32) + (uint32_t)(b >> 32)
                };

                result = temp[0] + (((uint64_t)temp[1]) << 32);
                return result;
            }

            inline uint64_t Times( uint64_t a, uint64_t b ) {
                constexpr uint64_t mask = (((uint64_t)1) << 32) - 1;

                return (a & mask) * (b & mask);
            }

            template <bool bswap>
            struct BlockWrapperScalar {
                using Block = uint64_t;

                static uint64_t LoadBlock( const void * x ) {
                    auto y = reinterpret_cast<const uint8_t *>(x);

                    return GET_U64<bswap>(y, 0);
                }

                static uint64_t LoadBlockNative( const void * x ) {
                    auto y = reinterpret_cast<const uint8_t *>(x);

                    return GET_U64<false>(y, 0);
                }

                static uint64_t LoadOne( uint64_t entropy ) { return entropy; }
            };

#if defined(HAVE_ARM_NEON)
            using u128 = uint64x2_t;

            inline u128 LeftShift( u128 a, int i ) { return vshlq_s64(a, vdupq_n_s64(i)); }

            inline u128 Plus( u128 a, u128 b ) { return vaddq_s64(a, b); }

            inline u128 Minus( u128 a, u128 b ) { return vsubq_s64(a, b); }

            inline u128 Plus32( u128 a, u128 b ) { return vaddq_s32(a, b); }

            inline u128 RightShift32( u128 a ) { return vshrq_n_u64(a, 32); }

            inline u128 Times( u128 a, u128 b ) {
                uint32x2_t a_lo = vmovn_u64(a);
                uint32x2_t b_lo = vmovn_u64(b);

                return vmull_u32(a_lo, b_lo);
            }

            inline u128 Xor( u128 a, u128 b ) { return veorq_s32(a, b); }

            static inline u128 Negate( u128 a ) {
                const auto zero = vdupq_n_s64(0);

                return Minus(zero, a);
            }

            inline uint64_t Sum( u128 a ) { return vgetq_lane_s64(a, 0) + vgetq_lane_s64(a, 1); }

            template <bool bswap>
            struct BlockWrapper128 {
                using Block = u128;

                static u128 LoadBlock( const void * x ) {
                    auto y = reinterpret_cast<const int32_t *>(x);

                    if (bswap) {
                        return vrev64q_u8(vld1q_s32(y));
                    }
                    return vld1q_s32(y);
                }

                static u128 LoadBlockNative( const void * x ) {
                    auto y = reinterpret_cast<const int32_t *>(x);

                    return vld1q_s32(y);
                }

                static u128 LoadOne( uint64_t entropy ) { return vdupq_n_s64(entropy); }
            };

#elif defined(HAVE_SSE_2)
            using u128 = __m128i;

            inline u128 LeftShift( u128 a, int i ) { return _mm_slli_epi64(a, i); }

            inline u128 Plus( u128 a, u128 b ) { return _mm_add_epi64(a, b); }

            inline u128 Minus( u128 a, u128 b ) { return _mm_sub_epi64(a, b); }

            inline u128 Plus32( u128 a, u128 b ) { return _mm_add_epi32(a, b); }

            inline u128 RightShift32( u128 a ) { return _mm_srli_epi64(a, 32); }

            inline u128 Times( u128 a, u128 b ) { return _mm_mul_epu32(a, b); }

            inline u128 Xor( u128 a, u128 b ) { return _mm_xor_si128(a, b); }

            static inline u128 Negate( u128 a ) {
                const auto zero = _mm_set1_epi64x(0);

                return Minus(zero, a);
            }

            // _mm_extract_epi64 assumes SSE4.1 is also available
            inline uint64_t Sum( u128 a ) { return _mm_cvtsi128_si64(a) + _mm_extract_epi64(a, 1); }

            template <bool bswap>
            struct BlockWrapper128 {
                using Block = u128;

                static u128 LoadBlock( const void * x ) {
                    auto y = reinterpret_cast<const u128 *>(x);

                    if (bswap) {
                        return mm_bswap64(_mm_loadu_si128(y));
                    }
                    return _mm_loadu_si128(y);
                }

                static u128 LoadBlockNative( const void * x ) {
                    auto y = reinterpret_cast<const u128 *>(x);

                    return _mm_loadu_si128(y);
                }

                static u128 LoadOne( uint64_t entropy ) { return _mm_set1_epi64x(entropy); }
            };
#endif

#if defined(HAVE_AVX2)
            using u256 = __m256i;

            inline u256 Plus( u256 a, u256 b ) { return _mm256_add_epi64(a, b); }

            inline u256 Plus32( u256 a, u256 b ) { return _mm256_add_epi32(a, b); }

            inline u256 Times( u256 a, u256 b ) { return _mm256_mul_epu32(a, b); }

            inline u256 Xor( u256 a, u256 b ) { return _mm256_xor_si256(a, b); }

            inline u256 LeftShift( u256 a, int i ) { return _mm256_slli_epi64(a, i); }

            inline u256 RightShift32( u256 a ) { return _mm256_srli_epi64(a, 32); }

            inline u256 Minus( u256 a, u256 b ) { return _mm256_sub_epi64(a, b); }

            static inline u256 Negate( u256 a ) {
                const auto zero = _mm256_set1_epi64x(0);

                return Minus(zero, a);
            }

            inline uint64_t Sum( u256 a ) {
                auto c = _mm256_extracti128_si256(a, 0);
                auto d = _mm256_extracti128_si256(a, 1);

                c = _mm_add_epi64(c, d);
#ifndef _MSC_VER
                static_assert(sizeof(c[0]) == sizeof(uint64_t) , "u256 too granular");
                static_assert(sizeof(c) == 2 * sizeof(uint64_t), "u256 too granular");
#endif
                // _mm_extract_epi64 assumes SSE4.1 is also available (should be always present when AVX2 is enabled)
                return _mm_cvtsi128_si64(c) + _mm_extract_epi64(c, 1);
            }

            template <bool bswap>
            struct BlockWrapper256 {
                using Block = u256;

                static u256 LoadBlock( const void * x ) {
                    auto y = reinterpret_cast<const u256 *>(x);

                    if (bswap) {
                        return mm256_bswap64(_mm256_loadu_si256(y));
                    }
                    return _mm256_loadu_si256(y);
                }

                static u256 LoadBlockNative( const void * x ) {
                    auto y = reinterpret_cast<const u256 *>(x);

                    return _mm256_loadu_si256(y);
                }

                static u256 LoadOne( uint64_t entropy ) { return _mm256_set1_epi64x(entropy); }
            };
#endif

#if defined(HAVE_AVX512_F)
            using u512 = __m512i;

            inline u512 Plus( u512 a, u512 b ) { return _mm512_add_epi64(a, b); }

            inline u512 Plus32( u512 a, u512 b ) { return _mm512_add_epi32(a, b); }

            inline u512 Times( u512 a, u512 b ) { return _mm512_mul_epu32(a, b); }

            inline u512 Xor( u512 a, u512 b ) { return _mm512_xor_epi32(a, b); }

            inline uint64_t Sum( u512 a ) { return _mm512_reduce_add_epi64(a); }

            inline u512 RightShift32( u512 a ) { return _mm512_srli_epi64(a, 32); }

            //  inline u512 RightShift32(u512 a, int i) { return _mm512_shuffle_epi32(a,
            //  _MM_PERM_ACAC); }
            inline u512 LeftShift( u512 a, int i ) { return _mm512_slli_epi64(a, i); }

            inline u512 Minus( u512 a, u512 b ) { return _mm512_sub_epi64(a, b); }

            inline u512 Negate( u512 a ) { return Minus(_mm512_set1_epi64(0), a); }

            template <bool bswap>
            struct BlockWrapper512 {
                using Block = u512;

                static Block LoadBlock( const void * x ) {
                    if (bswap) {
                        return mm512_bswap64(_mm512_loadu_si512(x));
                    }
                    return _mm512_loadu_si512(x);
                }

                static Block LoadBlockNative( const void * x ) {
                    return _mm512_loadu_si512(x);
                }

                static Block LoadOne( uint64_t entropy ) {
                    return _mm512_set1_epi64(entropy);
                }
            };
#endif

            template <typename T>
            T MultiplyAdd( const T & summand, const T & factor1, const T & factor2 ) {
                return Plus(summand, Times(factor1, factor2));
            }

#if defined(HAVE_ARM_NEON)

            template <>
            u128 MultiplyAdd( const u128 & summand, const u128 & factor1, const u128 & factor2 ) {
                return vmlal_u32(summand, vmovn_u64(factor1), vmovn_u64(factor2));
            }

#endif

//------------------------------------------------------------
            template <typename Block>
            inline void Encode3( Block raw_io[9 * 3] ) {
                auto io = reinterpret_cast<Block(*)[3]>(raw_io);
                constexpr unsigned x = 0, y = 1, z = 2;

                const Block * iter = io[0];

                io[7][x] = io[8][x] = iter[x];
                io[7][y] = io[8][y] = iter[y];
                io[7][z] = io[8][z] = iter[z];
                iter    += 1;

                auto DistributeRaw = [io, iter]( unsigned slot, unsigned label,
                        std::initializer_list<unsigned> rest ) {
                        for (unsigned i: rest) {
                            io[slot][i] = Xor(io[slot][i], iter[label]);
                        }
                    };

                auto Distribute3 = [&iter, DistributeRaw, x, y, z]( unsigned idx,
                        std::initializer_list<unsigned> a ,
                        std::initializer_list<unsigned> b ,
                        std::initializer_list<unsigned> c ) {
                        DistributeRaw(idx, x, a);
                        DistributeRaw(idx, y, b);
                        DistributeRaw(idx, z, c);
                        iter += 1;
                    };

                while (iter != io[9]) {
                    Distribute3(7, { x }, { y }, { z });
                }

                iter = io[1];
                Distribute3(8, { z }      , { x, z }   , { y }      );
                Distribute3(8, { x, z }   , { x, y, z }, { y, z }   );
                Distribute3(8, { y }      , { y, z }   , { x, z }   );
                Distribute3(8, { x, y }   , { z }      , { x }      );
                Distribute3(8, { y, z }   , { x, y }   , { x, y, z });
                Distribute3(8, { x, y, z }, { x }      , { x, y }   );
            }

            template <typename Block>
            inline void Encode2( Block raw_io[7 * 3] ) {
                auto io = reinterpret_cast<Block(*)[3]>(raw_io);

                for (int i = 0; i < 3; ++i) {
                    io[6][i] = io[0][i];
                    for (int j = 1; j < 6; ++j) {
                        io[6][i] = Xor(io[6][i], io[j][i]);
                    }
                }
            }

// https://docs.switzernet.com/people/emin-gabrielyan/051102-erasure-10-7-resilient/
            template <typename Block>
            inline void Encode4( Block raw_io[10 * 3] ) {
                auto io = reinterpret_cast<Block(*)[3]>(raw_io);

                constexpr unsigned x = 0, y = 1, z = 2;

                const Block * iter = io[0];

                io[7][x] = io[8][x] = io[9][x] = iter[x];
                io[7][y] = io[8][y] = io[9][y] = iter[y];
                io[7][z] = io[8][z] = io[9][z] = iter[z];
                iter    += 1;

                auto DistributeRaw = [io, iter]( unsigned slot, unsigned label,
                        std::initializer_list<unsigned> rest ) {
                        for (unsigned i: rest) {
                            io[slot][i] = Xor(io[slot][i], iter[label]);
                        }
                    };

                auto Distribute3 = [&iter, DistributeRaw, x, y, z]( unsigned idx,
                        std::initializer_list<unsigned> a ,
                        std::initializer_list<unsigned> b ,
                        std::initializer_list<unsigned> c ) {
                        DistributeRaw(idx, x, a);
                        DistributeRaw(idx, y, b);
                        DistributeRaw(idx, z, c);
                        iter += 1;
                    };

                while (iter != io[10]) {
                    Distribute3(7, { x }, { y }, { z });
                }

                iter = io[1];
                Distribute3(8, { z }      , { x, z }   , { y }      );  // 73
                Distribute3(8, { x, z }   , { x, y, z }, { y, z }   ); // 140
                Distribute3(8, { y }      , { y, z }   , { x, z }   ); // 167
                Distribute3(8, { x, y }   , { z }      , { x }      ); // 198
                Distribute3(8, { y, z }   , { x, y }   , { x, y, z }); // 292
                Distribute3(8, { x, y, z }, { x }      , { x, y }   ); // 323

                iter = io[1];
                Distribute3(9, { x, z }   , { x, y, z }, { y, z }   ); // 140
                Distribute3(9, { x, y }   , { z }      , { x }      ); // 198
                Distribute3(9, { z }      , { x, z }   , { y }      ); // 73
                Distribute3(9, { y, z }   , { x, y }   , { x, y, z }); // 292
                Distribute3(9, { x, y, z }, { x }      , { x, y }   ); // 323
                Distribute3(9, { y }      , { y, z }   , { x, z }   ); // 167
            }

// https://docs.switzernet.com/people/emin-gabrielyan/051103-erasure-9-5-resilient/
            template <typename Block>
            inline void Encode5( Block raw_io[9 * 3] ) {
                auto io = reinterpret_cast<Block(*)[3]>(raw_io);

                constexpr unsigned x = 0, y = 1, z = 2;

                const Block * iter = io[0];

                io[5][x] = io[6][x] = iter[x];
                io[5][y] = io[6][y] = iter[y];
                io[5][z] = io[6][z] = iter[z];

                io[7][x] = io[8][x] = iter[y];
                io[7][y] = io[8][y] = iter[z];
                io[7][z] = io[8][z] = Xor(iter[x], iter[y]);
                iter    += 1;

                auto DistributeRaw = [io, iter]( unsigned slot, unsigned label,
                        std::initializer_list<unsigned> rest ) {
                        for (unsigned i: rest) {
                            io[slot][i] = Xor(io[slot][i], iter[label]);
                        }
                    };

                auto Distribute3 = [&iter, DistributeRaw, x, y, z]( unsigned idx,
                        std::initializer_list<unsigned> a ,
                        std::initializer_list<unsigned> b ,
                        std::initializer_list<unsigned> c ) {
                        DistributeRaw(idx, x, a);
                        DistributeRaw(idx, y, b);
                        DistributeRaw(idx, z, c);
                        iter += 1;
                    };

                while (iter != io[9]) {
                    Distribute3(5, { x }, { y }, { z });
                }

                iter = io[1];
                Distribute3(6, { z }      , { x, z }   , { y }   ); // 73
                Distribute3(6, { x, z }   , { x, y, z }, { y, z }); // 140
                Distribute3(6, { y }      , { y, z }   , { x, z }); // 167
                Distribute3(6, { x, y }   , { z }      , { x }   ); // 198

                iter = io[1];
                Distribute3(7, { x, y, z }, { x }      , { x, y }); // 323
                Distribute3(7, { x, z }   , { x, y, z }, { y, z }); // 140
                Distribute3(7, { x }      , { y }      , { z }   ); // 11
                Distribute3(7, { y }      , { y, z }   , { x, z }); // 167

                iter = io[1];
                Distribute3(8, { x }      , { y }      , { z }      ); // 11
                Distribute3(8, { x, y }   , { z }      , { x }      ); // 198
                Distribute3(8, { y, z }   , { x, y }   , { x, y, z }); // 292
                Distribute3(8, { x, z }   , { x, y, z }, { y, z }   ); // 140
            }

            template <typename Badger, typename Block>
            inline void Combine2( const Block input[7], Block output[2] );

            template <typename Badger, typename Block>
            inline void Combine3( const Block input[9], Block output[3] );

            template <typename Badger, typename Block>
            inline void Combine4( const Block input[10], Block output[3] );

            template <typename Badger, typename Block>
            inline void Combine5( const Block input[9], Block output[3] );

            constexpr inline uint64_t FloorLog( uint64_t a, uint64_t b ) {
                return (0 == a) ? 0 : ((b < a) ? 0 : (1 + (FloorLog(a, b / a))));
            }

            template <typename BlockWrapper, unsigned dimension, unsigned in_width,
                    unsigned encoded_dimension, unsigned out_width, unsigned fanout = 8>
            struct EhcBadger {
                using Block = typename BlockWrapper::Block;

                static Block Mix( const Block & accum, const Block & input, const Block & entropy ) {
                    Block output = Plus32(entropy, input);
                    Block twin   = RightShift32(output);

                    output = MultiplyAdd(accum, output, twin);
                    return output;
                }

                static Block MixOne( const Block & accum, const Block & input, uint64_t entropy ) {
                    return Mix(accum, input, BlockWrapper::LoadOne(entropy));
                }

                static Block MixNone( const Block & input, uint64_t entropy_word ) {
                    Block entropy = BlockWrapper::LoadOne(entropy_word);
                    Block output  = Plus32(entropy, input);
                    Block twin    = RightShift32(output);

                    output = Times(output, twin);
                    return output;
                }

                static void EhcUpperLayer( const Block (& input)[fanout][out_width],
                        const uint64_t entropy[out_width * (fanout - 1)], Block (& output)[out_width] ) {
                    for (unsigned i = 0; i < out_width; ++i) {
                        output[i] = input[0][i];
                        for (unsigned j = 1; j < fanout; ++j) {
                            output[i] = MixOne(output[i], input[j][i], entropy[(fanout - 1) * i + j - 1]);
                        }
                    }
                }

                static void Encode( Block io[encoded_dimension][in_width] ) {
                    static_assert(2 <= out_width && out_width <= 5, "uhoh");
                    if (out_width == 3) { return Encode3<Block>(&io[0][0]); }
                    if (out_width == 2) { return Encode2<Block>(&io[0][0]); }
                    if (out_width == 4) { return Encode4<Block>(&io[0][0]); }
                    if (out_width == 5) { return Encode5<Block>(&io[0][0]); }
                }

                static Block SimpleTimes( std::integral_constant<int, -1>, const Block & x ) { return Negate(x); }

                static Block SimpleTimes( std::integral_constant<int, 1>, const Block & x ) { return x; }

                static Block SimpleTimes( std::integral_constant<int, 2>, const Block & x ) {
                    return LeftShift(x, 1);
                }

                static Block SimpleTimes( std::integral_constant<int, 3>, const Block & x ) {
                    return Plus(x, LeftShift(x, 1));
                }

                static Block SimpleTimes( std::integral_constant<int, 4>, const Block & x ) {
                    return LeftShift(x, 2);
                }

                static Block SimpleTimes( std::integral_constant<int, 5>, const Block & x ) {
                    return Plus(x, LeftShift(x, 2));
                }

                static Block SimpleTimes( std::integral_constant<int, 7>, const Block & x ) {
                    return Minus(LeftShift(x, 3), x);
                }

                static Block SimpleTimes( std::integral_constant<int, 8>, const Block & x ) {
                    return LeftShift(x, 3);
                }

                static Block SimpleTimes( std::integral_constant<int, 9>, const Block & x ) {
                    return Plus(x, LeftShift(x, 3));
                }

                template <int a>
                static Block SimplerTimes( const Block & x ) {
                    return SimpleTimes(std::integral_constant<int, a>{}, x);
                }

                template <int a, int b>
                static void Dot2( Block sinks[2], const Block & x ) {
                    sinks[0] = Plus(sinks[0], SimplerTimes<a>(x));
                    sinks[1] = Plus(sinks[1], SimplerTimes<b>(x));
                }

                template <int a, int b, int c>
                static void Dot3( Block sinks[3], const Block & x ) {
                    Dot2<a, b>(sinks, x);
                    sinks[2] = Plus(sinks[2], SimplerTimes<c>(x));
                }

                template <int a, int b, int c, int d>
                static void Dot4( Block sinks[4], const Block & x ) {
                    Dot3<a, b, c>(sinks, x);
                    sinks[3] = Plus(sinks[3], SimplerTimes<d>(x));
                }

                template <int a, int b, int c, int d, int e>
                static void Dot5( Block sinks[5], const Block & x ) {
                    Dot4<a, b, c, d>(sinks, x);
                    sinks[4] = Plus(sinks[4], SimplerTimes<e>(x));
                }

                static void Combine( const Block input[encoded_dimension], Block (& output)[out_width] ) {
                    if (out_width == 3) { return Combine3<EhcBadger>(input, output); }
                    if (out_width == 2) { return Combine2<EhcBadger>(input, output); }
                    if (out_width == 4) { return Combine4<EhcBadger>(input, output); }
                    if (out_width == 5) { return Combine5<EhcBadger>(input, output); }
                }

                static void Load( const uint8_t input[dimension * in_width * sizeof(Block)],
                        Block output[dimension][in_width] ) {
                    static_assert(dimension * in_width <= 28, "");
#if !defined(__clang__)
  #pragma GCC unroll 28
#else
  #pragma unroll
#endif
                    for (unsigned i = 0; i < dimension; ++i) {
#if !defined(__clang__)
  #pragma GCC unroll 28
#else
  #pragma unroll
#endif
                        for (unsigned j = 0; j < in_width; ++j) {
                            output[i][j] =
                                    BlockWrapper::LoadBlock(&input[(i * in_width + j) * sizeof(Block)]);
                        }
                    }
                }

                static void Hash( const Block (& input)[encoded_dimension][in_width],
                        const uint64_t entropy[encoded_dimension][in_width], Block output[encoded_dimension] ) {
                    for (unsigned i = 0; i < encoded_dimension; ++i) {
                        output[i] = MixNone(input[i][0], entropy[i][0]);
                        // TODO: should loading take care of this?
                    }
                    for (unsigned j = 1; j < in_width; ++j) {
                        for (unsigned i = 0; i < encoded_dimension; ++i) {
                            output[i] = MixOne(output[i], input[i][j], entropy[i][j]);
                            // TODO: this might be optional; it might not matter which way we iterate over
                            // entropy
                        }
                    }
                }

                static void EhcBaseLayer( const uint8_t input[dimension * in_width * sizeof(Block)],
                        const uint64_t raw_entropy[encoded_dimension][in_width], Block (& output)[out_width] ) {
                    Block scratch[encoded_dimension][in_width];
                    Block tmpout[encoded_dimension];

                    Load(input, scratch);
                    Encode(scratch);
                    Hash(scratch, raw_entropy, tmpout);
                    Combine(tmpout, output);
                }

                static void DfsTreeHash( const uint8_t * data, size_t block_group_length,
                        Block stack[][fanout][out_width], int stack_lengths[], const uint64_t * entropy ) {
                    auto entropy_matrix = reinterpret_cast<const uint64_t(*)[in_width]>(entropy);

                    for (size_t k = 0; k < block_group_length; ++k) {
                        int i = 0;
                        while (stack_lengths[i] == fanout) { ++i; }
                        for (int j = i - 1; j >= 0; --j) {
                            EhcUpperLayer(stack[j],
                                    &entropy[encoded_dimension * in_width + (fanout - 1) * out_width * j],
                                    stack[j + 1][stack_lengths[j + 1]]);
                            stack_lengths[j]      = 0;
                            stack_lengths[j + 1] += 1;
                        }

                        EhcBaseLayer(&data[k * dimension * in_width * sizeof(Block)],
                                entropy_matrix, stack[0][stack_lengths[0]]);
                        stack_lengths[0] += 1;
                    }
                }

                // auto b = sizeof(Block) / sizeof(uint64_t);
                static constexpr size_t GEBN_b() { return sizeof(Block) / sizeof(uint64_t); }

                // auto h = FloorLog(fanout, n / (b * dimension * in_width));
                static constexpr size_t GEBN_h( size_t n ) {
                    return FloorLog(fanout, n / (GEBN_b() * dimension * in_width));
                }

                static constexpr size_t GetEntropyBytesNeeded( size_t n ) {
                    return sizeof(uint64_t) * (encoded_dimension * in_width + (fanout - 1) * out_width * GEBN_h(n) +
                           GEBN_b() * fanout * out_width * GEBN_h(n) + GEBN_b() * dimension * in_width + out_width - 1);
                }

                struct BlockGreedy {
                  private:
                    const uint64_t * seeds;
                    Block            accum[out_width] = {};

                  public:
                    BlockGreedy( const uint64_t seeds[] ) :
                        seeds( seeds ) {}

                    void Insert( const Block (& x)[out_width] ) {
                        for (unsigned i = 0; i < out_width; ++i) {
                            accum[i] = Mix(accum[i], x[i], BlockWrapper::LoadBlockNative(seeds));
                            seeds   += sizeof(Block) / sizeof(uint64_t);
                        }
                    }

                    void Insert( const Block & x ) {
                        for (unsigned i = 0; i < out_width; ++i) {
                            accum[i] =
                                    Mix(accum[i], x, BlockWrapper::LoadBlockNative(
                                    &seeds[i * sizeof(Block) / sizeof(uint64_t)]));
                        }
                        // Toeplitz
                        seeds += sizeof(Block) / sizeof(uint64_t);
                    }

                    void Hash( uint64_t output[out_width] ) const {
                        for (unsigned i = 0; i < out_width; ++i) {
                            output[i] = Sum(accum[i]);
                        }
                    }
                };

                static void DfsGreedyFinalizer( const Block stack[][fanout][out_width], const int stack_lengths[],
                        const uint8_t * uint8_t_input, size_t uint8_t_length, const uint64_t * entropy,
                        uint64_t output[out_width] ) {
                    BlockGreedy b( entropy );

                    for (int j = 0; stack_lengths[j] > 0; ++j) {
                        for (int k = 0; k < stack_lengths[j]; k += 1) {
                            b.Insert(stack[j][k]);
                        }
                    }

                    size_t i = 0;
                    for (; i + sizeof(Block) <= uint8_t_length; i += sizeof(Block)) {
                        b.Insert(BlockWrapper::LoadBlock(&uint8_t_input[i]));
                    }

                    if (1) {
                        uint8_t extra[sizeof(Block)];
                        memcpy(extra, &uint8_t_input[i], uint8_t_length - i);
                        memset(extra + uint8_t_length - i, 0, sizeof(extra) - uint8_t_length + i);
                        b.Insert(BlockWrapper::LoadBlock(extra));
                    } else if (1) {
                        Block extra = {};
                        memcpy(&extra, &uint8_t_input[i], uint8_t_length - i);
                        b.Insert(extra);
                    } else {
                        Block     extra;
                        uint8_t * extra_uint8_t = reinterpret_cast<uint8_t *>(&extra);
                        for (unsigned j = 0; j < sizeof(Block); ++j) {
                            if (j < uint8_t_length - i) {
                                extra_uint8_t[j] = uint8_t_input[i + j];
                            } else {
                                extra_uint8_t[j] = 0;
                            }
                        }
                        b.Insert(extra);
                    }
                    b.Hash(output);
                }
            }; // EhcBadger

// evenness: 2 weight: 10
//  0   0   1   4   1   1   2   2   1
//  1   1   0   0   1   4   1   2   2
//  1   4   1   1   0   0   2   1   2

            template <typename Badger, typename Block>
            inline void Combine3( const Block input[9], Block output[3] ) {
                output[1] = input[0];
                output[2] = input[0];

                output[1] = Plus(output[1], input[1]);
                output[2] = Plus(output[2], LeftShift(input[1], 2));

                output[0] = input[2];
                output[2] = Plus(output[2], input[2]);

                output[0] = Plus(output[0], LeftShift(input[3], 2));
                output[2] = Plus(output[2], input[3]);

                output[0] = Plus(output[0], input[4]);
                output[1] = Plus(output[1], input[4]);

                output[0] = Plus(output[0], input[5]);
                output[1] = Plus(output[1], LeftShift(input[5], 2));

                Badger::template Dot3<2, 1, 2>(output, input[6]);
                Badger::template Dot3<2, 2, 1>(output, input[7]);
                Badger::template Dot3<1, 2, 2>(output, input[8]);
            }

            template <typename Badger, typename Block>
            inline void Combine2( const Block input[7], Block output[2] ) {
                output[0] = input[0];
                output[1] = input[1];

                Badger::template Dot2<1, 1>(output, input[2]);
                Badger::template Dot2<1, 2>(output, input[3]);
                Badger::template Dot2<2, 1>(output, input[4]);
                Badger::template Dot2<1, 4>(output, input[5]);
                Badger::template Dot2<4, 1>(output, input[6]);
            }

// evenness: 4 weight: 16
//   8   8   0   2   1   8   2   1   2   4
//   0   8   1   0   1   1   4   1   4   2
//   1   8   1   4   2   8   1   4   1   2
//   8   1   1   1   1   8   1   8   4   1

// evenness: 3 weight: 21
// 0   0   0   1   1   4   2   4   1   1
// 0   1   2   0   0   1   1   2   4   1
// 2   0   1   0   4   0   1   1   1   1
// 1   1   0   1   0   0   4   1   2   8

            template <typename Badger, typename Block>
            inline void Combine4( const Block input[10], Block output[4] ) {
                output[2] = LeftShift(input[0], 1);
                output[3] = input[0];

                output[1] = input[1];
                output[3] = Plus(output[3], input[1]);

                output[1] = Plus(output[1], LeftShift(input[2], 1));
                output[2] = Plus(output[2], input[2]);

                output[0] = input[3];
                output[3] = Plus(output[3], input[3]);

                output[0] = Plus(output[0], input[4]);
                output[2] = Plus(output[2], LeftShift(input[4], 2));

                output[0] = Plus(output[0], LeftShift(input[5], 2));
                output[1] = Plus(output[1], input[5]);

                Badger::template Dot4<2, 1, 1, 4>(output, input[6]);
                Badger::template Dot4<4, 2, 1, 1>(output, input[7]);
                Badger::template Dot4<1, 4, 1, 2>(output, input[8]);
                Badger::template Dot4<1, 1, 1, 8>(output, input[9]);
            }

// TODO:
// 0   0   0   0   1   x   x   x   x
// 1   0   0   0   0   1   x   x   x
// x   1   0   0   0   0   1   x   x
// x   x   1   0   0   0   0   1   x
// x   x   x   1   0   0   0   0   1

// evenness: 3 weight: 15
// 1   0   0   0   0   1   1   2   4
// 0   1   0   0   0   1   2   1   7
// 0   0   1   0   0   1   3   8   5
// 0   0   0   1   0   1   4   9   8
// 0   0   0   0   1   1   5   3   9

            template <typename Badger, typename Block>
            inline void Combine5( const Block input[10], Block output[5] ) {
                output[0] = input[0];
                output[1] = input[1];
                output[2] = input[2];
                output[3] = input[3];
                output[4] = input[4];

                output[0] = Plus(output[0], input[5]);
                output[1] = Plus(output[1], input[5]);
                output[2] = Plus(output[2], input[5]);
                output[3] = Plus(output[3], input[5]);
                output[4] = Plus(output[4], input[5]);

                Badger::template Dot5<1, 2, 3, 4, 5>(output, input[6]);
                Badger::template Dot5<2, 1, 8, 9, 3>(output, input[7]);
                Badger::template Dot5<4, 7, 5, 8, 9>(output, input[8]);
            }

            template <int width>
            inline uint64_t TabulateBytes( uint64_t input, const uint64_t entropy[256 * width] ) {
                const uint64_t(&table)[width][256] =
                        *reinterpret_cast<const uint64_t(*)[width][256]>(entropy);
                uint64_t result = 0;
                for (unsigned i = 0; i < width; ++i) {
                    uint8_t index = input >> (i * CHAR_BIT);
                    result ^= table[i][index];
                }
                return result;
            }

            template <typename BlockWrapper, unsigned dimension, unsigned in_width,
                    unsigned encoded_dimension, unsigned out_width>
            static void Hash( const uint64_t * entropy, const uint8_t * uint8_t_input,
                    size_t length, uint64_t output[out_width] ) {
                constexpr unsigned kMaxStackSize = 9;
                constexpr unsigned kFanout       = 8;

                using Block = typename BlockWrapper::Block;

                Block  stack[kMaxStackSize][kFanout][out_width];
                int    stack_lengths[kMaxStackSize] = {};
                size_t wide_length = length / sizeof(Block) / (dimension * in_width);

                EhcBadger<BlockWrapper, dimension, in_width, encoded_dimension, out_width,
                        kFanout>::DfsTreeHash(uint8_t_input, wide_length, stack, stack_lengths, entropy);
                entropy += encoded_dimension * in_width + out_width * (kFanout - 1) * kMaxStackSize;

                auto used_uint8_ts = wide_length * sizeof(Block) * (dimension * in_width);
                uint8_t_input += used_uint8_ts;

                EhcBadger<BlockWrapper, dimension, in_width, encoded_dimension, out_width,
                        kFanout>::DfsGreedyFinalizer(stack, stack_lengths, uint8_t_input,
                        length - used_uint8_ts, entropy, output);
            }

            template <typename Block, unsigned count>
            struct alignas( alignof(Block)) Repeat {
                Block  it[count];
            };

            template <typename InnerBlockWrapper, unsigned count>
            struct RepeatWrapper {
                using InnerBlock = typename InnerBlockWrapper::Block;

                using Block      = Repeat<InnerBlock, count>;

                static Block LoadOne( uint64_t entropy ) {
                    Block result;

                    for (unsigned i = 0; i < count; ++i) {
                        result.it[i] = InnerBlockWrapper::LoadOne(entropy);
                    }
                    return result;
                }

                static Block LoadBlock( const void * x ) {
                    auto  y = reinterpret_cast<const uint8_t *>(x);
                    Block result;

                    for (unsigned i = 0; i < count; ++i) {
                        result.it[i] = InnerBlockWrapper::LoadBlock(y + i * sizeof(InnerBlock));
                    }
                    return result;
                }

                static Block LoadBlockNative( const void * x ) {
                    auto  y = reinterpret_cast<const uint8_t *>(x);
                    Block result;

                    for (unsigned i = 0; i < count; ++i) {
                        result.it[i] = InnerBlockWrapper::LoadBlockNative(y + i * sizeof(InnerBlock));
                    }
                    return result;
                }
            };

            template <typename Block, unsigned count>
            inline Repeat<Block, count> Xor( const Repeat<Block, count> & a, const Repeat<Block, count> & b ) {
                Repeat<Block, count> result;

                for (unsigned i = 0; i < count; ++i) {
                    result.it[i] = Xor(a.it[i], b.it[i]);
                }
                return result;
            }

            template <typename Block, unsigned count>
            inline Repeat<Block, count> Plus32( const Repeat<Block, count> & a, const Repeat<Block, count> & b ) {
                Repeat<Block, count> result;

                for (unsigned i = 0; i < count; ++i) {
                    result.it[i] = Plus32(a.it[i], b.it[i]);
                }
                return result;
            }

            template <typename Block, unsigned count>
            inline Repeat<Block, count> Plus( const Repeat<Block, count> & a, const Repeat<Block, count> & b ) {
                Repeat<Block, count> result;

                for (unsigned i = 0; i < count; ++i) {
                    result.it[i] = Plus(a.it[i], b.it[i]);
                }
                return result;
            }

            template <typename Block, unsigned count>
            inline Repeat<Block, count> Minus( const Repeat<Block, count> & a, const Repeat<Block, count> & b ) {
                Repeat<Block, count> result;

                for (unsigned i = 0; i < count; ++i) {
                    result.it[i] = Minus(a.it[i], b.it[i]);
                }
                return result;
            }

            template <typename Block, unsigned count>
            inline Repeat<Block, count> LeftShift( const Repeat<Block, count> & a, int s ) {
                Repeat<Block, count> result;

                for (unsigned i = 0; i < count; ++i) {
                    result.it[i] = LeftShift(a.it[i], s);
                }
                return result;
            }

            template <typename Block, unsigned count>
            inline Repeat<Block, count> RightShift32( const Repeat<Block, count> & a ) {
                Repeat<Block, count> result;

                for (unsigned i = 0; i < count; ++i) {
                    result.it[i] = RightShift32(a.it[i]);
                }
                return result;
            }

            template <typename Block, unsigned count>
            inline Repeat<Block, count> Times( const Repeat<Block, count> & a, const Repeat<Block, count> & b ) {
                Repeat<Block, count> result;

                for (unsigned i = 0; i < count; ++i) {
                    result.it[i] = Times(a.it[i], b.it[i]);
                }
                return result;
            }

            template <typename Block, unsigned count>
            inline uint64_t Sum( const Repeat<Block, count> & a ) {
                uint64_t result = 0;

                for (unsigned i = 0; i < count; ++i) {
                    result += Sum(a.it[i]);
                }
                return result;
            }

            template <typename Block, unsigned count>
            inline Repeat<Block, count> Negate( const Repeat<Block, count> & a ) {
                Repeat<Block, count> b;

                for (unsigned i = 0; i < count; ++i) {
                    b.it[i] = Negate(a.it[i]);
                }
                return b;
            }
        } // namespace

//------------------------------------------------------------
        template <typename Wrapper, unsigned out_width>
        inline constexpr size_t GetEntropyBytesNeeded( size_t n ) {
            return (3 == out_width) ?
                       EhcBadger<Wrapper, 7, 3, 9, out_width>::GetEntropyBytesNeeded(n) :
                       (2 == out_width) ?
                           EhcBadger<Wrapper, 6, 3, 7,
                                   out_width>::GetEntropyBytesNeeded(n)
                       :
                           (4 == out_width) ?
                               EhcBadger<Wrapper, 7, 3, 10,
                                       out_width>::GetEntropyBytesNeeded(n)
                           :
                               EhcBadger<Wrapper, 5, 3, 9, out_width>::GetEntropyBytesNeeded(n);
        }

// auto b = 8;
        inline constexpr size_t MEBN_b() { return 8; }

// auto h = FloorLog(8, ~0ull / 21);
        inline constexpr size_t MEBN_h() { return FloorLog(8, ~0ull / 21); }

// auto tab_words = 0;//6 * 8 * 256; // TODO: include words of tabulation?
        inline constexpr size_t MEBN_tab_words() { return 0; }

// auto words = 21 + 7 * 5 * h + b * 8 * 5 * h + b * 21 + 5 - 1;
        inline constexpr size_t MEBN_words() {
            return 21 + 7 * 5 * MEBN_h() + MEBN_b() * 8 * 5 * MEBN_h() + MEBN_b() * 21 + 5 - 1;
        }

        inline constexpr size_t MaxEntropyBytesNeeded() {
            return sizeof(uint64_t) * (MEBN_words() + MEBN_tab_words());
        }

        template <void(*Hasher)(const uint64_t * entropy, const uint8_t * uint8_t_input, size_t length,
                uint64_t output[]),
                int width>
        inline uint64_t TabulateAfter( const uint64_t * entropy, const uint8_t * uint8_t_input, size_t length ) {
            const uint64_t(&table)[sizeof(uint64_t) * (1 + width)][256] =
                    *reinterpret_cast<const uint64_t(*)[sizeof(uint64_t) * (1 + width)][256]>(entropy);
            entropy += width * 256;
            uint64_t output[width];
            Hasher(entropy, uint8_t_input, length, output);
            uint64_t result = TabulateBytes<sizeof(length)>(length, &table[0][0]);
            for (int i = 0; i < width; ++i) {
                result ^= TabulateBytes<sizeof(output[i])>(output[i], &table[8 * (i + 1)][0]);
            }
            return result;
        }

//------------------------------------------------------------
        template <unsigned dimension, unsigned in_width, unsigned encoded_dimension,
                unsigned out_width, bool bswap>
        inline void V4Scalar( const uint64_t * entropy, const uint8_t * uint8_t_input,
                size_t length, uint64_t output[out_width] ) {
            return Hash<RepeatWrapper<BlockWrapperScalar<bswap>, 8>, dimension, in_width,
                    encoded_dimension, out_width>(entropy, uint8_t_input, length, output);
        }

        template <unsigned dimension, unsigned in_width, unsigned encoded_dimension,
                unsigned out_width, bool bswap>
        inline void V3Scalar( const uint64_t * entropy, const uint8_t * uint8_t_input,
                size_t length, uint64_t output[out_width] ) {
            return Hash<RepeatWrapper<BlockWrapperScalar<bswap>, 4>, dimension, in_width,
                    encoded_dimension, out_width>(entropy, uint8_t_input, length, output);
        }

        template <unsigned dimension, unsigned in_width, unsigned encoded_dimension,
                unsigned out_width, bool bswap>
        inline void V2Scalar( const uint64_t * entropy, const uint8_t * uint8_t_input,
                size_t length, uint64_t output[out_width] ) {
            return Hash<RepeatWrapper<BlockWrapperScalar<bswap>, 2>, dimension, in_width,
                    encoded_dimension, out_width>(entropy, uint8_t_input, length, output);
        }

        template <unsigned dimension, unsigned in_width, unsigned encoded_dimension,
                unsigned out_width, bool bswap>
        inline void V1Scalar( const uint64_t * entropy, const uint8_t * uint8_t_input,
                size_t length, uint64_t output[out_width] ) {
            return Hash<BlockWrapperScalar<bswap>, dimension, in_width, encoded_dimension, out_width>(
                    entropy, uint8_t_input, length, output);
        }

#if defined(HAVE_ARM_NEON)

        template <unsigned dimension, unsigned in_width, unsigned encoded_dimension,
                unsigned out_width, bool bswap>
        inline void V2Neon( const uint64_t * entropy, const uint8_t * uint8_t_input,
                size_t length, uint64_t output[out_width] ) {
            return Hash<BlockWrapper128<bswap>, dimension, in_width, encoded_dimension, out_width>(
                    entropy, uint8_t_input, length, output);
        }

        template <unsigned dimension, unsigned in_width, unsigned encoded_dimension,
                unsigned out_width, bool bswap>
        inline void V3Neon( const uint64_t * entropy, const uint8_t * uint8_t_input,
                size_t length, uint64_t output[out_width] ) {
            return Hash<RepeatWrapper<BlockWrapper128<bswap>, 2>, dimension, in_width, encoded_dimension,
                    out_width>(entropy, uint8_t_input, length, output);
        }

        template <unsigned dimension, unsigned in_width, unsigned encoded_dimension,
                unsigned out_width, bool bswap>
        inline void V4Neon( const uint64_t * entropy, const uint8_t * uint8_t_input,
                size_t length, uint64_t output[out_width] ) {
            return Hash<RepeatWrapper<BlockWrapper128<bswap>, 4>, dimension, in_width, encoded_dimension,
                    out_width>(entropy, uint8_t_input, length, output);
        }

#else // HAVE_ARM_NEON
  #if defined(HAVE_SSE_2)

        template <unsigned dimension, unsigned in_width, unsigned encoded_dimension,
                unsigned out_width, bool bswap>
        inline void V2Sse2( const uint64_t * entropy, const uint8_t * uint8_t_input,
                size_t length, uint64_t output[out_width] ) {
            return Hash<BlockWrapper128<bswap>, dimension, in_width, encoded_dimension, out_width>(
                    entropy, uint8_t_input, length, output);
        }

        template <unsigned dimension, unsigned in_width, unsigned encoded_dimension,
                unsigned out_width, bool bswap>
        inline void V3Sse2( const uint64_t * entropy, const uint8_t * uint8_t_input,
                size_t length, uint64_t output[out_width] ) {
            return Hash<RepeatWrapper<BlockWrapper128<bswap>, 2>, dimension, in_width, encoded_dimension,
                    out_width>(entropy, uint8_t_input, length, output);
        }

        template <unsigned dimension, unsigned in_width, unsigned encoded_dimension,
                unsigned out_width, bool bswap>
        inline void V4Sse2( const uint64_t * entropy, const uint8_t * uint8_t_input,
                size_t length, uint64_t output[out_width] ) {
            return Hash<RepeatWrapper<BlockWrapper128<bswap>, 4>, dimension, in_width, encoded_dimension,
                    out_width>(entropy, uint8_t_input, length, output);
        }

  #endif

  #if defined(HAVE_AVX2)

        template <unsigned dimension, unsigned in_width, unsigned encoded_dimension,
                unsigned out_width, bool bswap>
        inline void V3Avx2( const uint64_t * entropy, const uint8_t * uint8_t_input,
                size_t length, uint64_t output[out_width] ) {
            return Hash<BlockWrapper256<bswap>, dimension, in_width, encoded_dimension, out_width>(
                    entropy, uint8_t_input, length, output);
        }

        template <unsigned dimension, unsigned in_width, unsigned encoded_dimension,
                unsigned out_width, bool bswap>
        inline void V4Avx2( const uint64_t * entropy, const uint8_t * uint8_t_input,
                size_t length, uint64_t output[out_width] ) {
            return Hash<RepeatWrapper<BlockWrapper256<bswap>, 2>, dimension, in_width, encoded_dimension,
                    out_width>(entropy, uint8_t_input, length, output);
        }

  #endif

  #if defined(HAVE_AVX512_F)

        template <unsigned dimension, unsigned in_width, unsigned encoded_dimension,
                unsigned out_width, bool bswap>
        inline void V4Avx512( const uint64_t * entropy, const uint8_t * uint8_t_input,
                size_t length, uint64_t output[out_width] ) {
            return Hash<BlockWrapper512<bswap>, dimension, in_width, encoded_dimension, out_width>(
                    entropy, uint8_t_input, length, output);
        }

  #endif

#endif // HAVE_ARM_NEON

        template <unsigned out_width, bool bswap>
        static inline void V4( const uint64_t * entropy, const uint8_t * uint8_t_input,
                size_t length, uint64_t output[out_width] );

        template <unsigned out_width, bool bswap>
        static inline void V3( const uint64_t * entropy, const uint8_t * uint8_t_input,
                size_t length, uint64_t output[out_width] );

        template <unsigned out_width, bool bswap>
        static inline void V2( const uint64_t * entropy, const uint8_t * uint8_t_input,
                size_t length, uint64_t output[out_width] );

        template <unsigned out_width, bool bswap>
        static inline void V1( const uint64_t * entropy, const uint8_t * uint8_t_input,
                size_t length, uint64_t output[out_width] );

//------------------------------------------------------------
#define SPECIALIZE(version, isa, out_width, dimension, in_width, encoded_dimension)                 \
    template <>                                                                                     \
    inline void V##version<out_width, false>(const uint64_t* entropy, const uint8_t* uint8_t_input, \
            size_t length, uint64_t output[out_width]) {                                            \
        return V##version##isa<dimension, in_width, encoded_dimension, out_width, false>(           \
        entropy, uint8_t_input, length, output);                                                    \
    }                                                                                               \
    template <>                                                                                     \
    inline void V##version<out_width, true>(const uint64_t* entropy, const uint8_t* uint8_t_input,  \
            size_t length, uint64_t output[out_width]) {                                            \
        return V##version##isa<dimension, in_width, encoded_dimension, out_width, true>(            \
        entropy, uint8_t_input, length, output);                                                    \
    }


#define SPECIALIZE_4(version, isa)      \
  SPECIALIZE(version, isa, 5, 5, 3, 9)  \
  SPECIALIZE(version, isa, 4, 7, 3, 10) \
  SPECIALIZE(version, isa, 3, 7, 3, 9)  \
  SPECIALIZE(version, isa, 2, 6, 3, 7)

// XXX Assumes (e.g.) AVX512F implies having AVX2 and SSE2

#if defined(HAVE_ARM_NEON)
  #define HALFTIME_IMPL_STR "neon"

        SPECIALIZE_4(4, Neon  )
        SPECIALIZE_4(3, Neon  )
        SPECIALIZE_4(2, Neon  )
        SPECIALIZE_4(1, Scalar)

#elif defined(HAVE_AVX512_F)
  #define HALFTIME_IMPL_STR "avx512f"

        SPECIALIZE_4(4, Avx512)
        SPECIALIZE_4(3, Avx2  )
        SPECIALIZE_4(2, Sse2  )
        SPECIALIZE_4(1, Scalar)

#elif defined(HAVE_AVX2)
  #define HALFTIME_IMPL_STR "avx2"

        SPECIALIZE_4(4, Avx2  )
        SPECIALIZE_4(3, Avx2  )
        SPECIALIZE_4(2, Sse2  )
        SPECIALIZE_4(1, Scalar)

#elif defined(HAVE_SSE_2)
  #define HALFTIME_IMPL_STR "sse2"

        SPECIALIZE_4(4, Sse2  )
        SPECIALIZE_4(3, Sse2  )
        SPECIALIZE_4(2, Sse2  )
        SPECIALIZE_4(1, Scalar)

#else
  #define HALFTIME_IMPL_STR "portable"

        SPECIALIZE_4(4, Scalar)
        SPECIALIZE_4(3, Scalar)
        SPECIALIZE_4(2, Scalar)
        SPECIALIZE_4(1, Scalar)

#endif
    } // namespace advanced

//------------------------------------------------------------
    static constexpr size_t kEntropyBytesNeeded =
            256 * 3 * sizeof(uint64_t) * sizeof(uint64_t) +
            advanced::GetEntropyBytesNeeded<
            advanced::RepeatWrapper<advanced::BlockWrapperScalar<false>, 8>, 2>(~0ul);

    template <bool bswap>
    static inline uint64_t HalftimeHashStyle512( const uint64_t entropy[kEntropyBytesNeeded / sizeof(uint64_t)],
            const uint8_t input[], size_t length ) {
        return advanced::TabulateAfter<advanced::V4<2, bswap>, 2>(entropy, input, length);
    }

    template <bool bswap>
    static inline uint64_t HalftimeHashStyle256( const uint64_t entropy[kEntropyBytesNeeded / sizeof(uint64_t)],
            const uint8_t input[], size_t length ) {
        return advanced::TabulateAfter<advanced::V3<2, bswap>, 2>(entropy, input, length);
    }

    template <bool bswap>
    static inline uint64_t HalftimeHashStyle128( const uint64_t entropy[kEntropyBytesNeeded / sizeof(uint64_t)],
            const uint8_t input[], size_t length ) {
        return advanced::TabulateAfter<advanced::V2<2, bswap>, 2>(entropy, input, length);
    }

    template <bool bswap>
    static inline uint64_t HalftimeHashStyle64( const uint64_t entropy[kEntropyBytesNeeded / sizeof(uint64_t)],
            const uint8_t input[], size_t length ) {
        return advanced::TabulateAfter<advanced::V1<2, bswap>, 2>(entropy, input, length);
    }
} // namespace halftime_hash

//------------------------------------------------------------
alignas(64) static thread_local uint64_t
halftime_hash_random[8 * ((halftime_hash::kEntropyBytesNeeded / 64) + 1)];

// romu random number generator for seeding the HalftimeHash entropy
static uint64_t splitmix( uint64_t & state ) {
    uint64_t z = (state += UINT64_C(0x9e3779b97f4a7c15));

    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    return z ^ (z >> 31);
}

static uintptr_t halftime_hash_seed_init( const seed_t seed ) {
    uint64_t mState = seed;
    uint64_t wState = splitmix(mState);
    uint64_t xState = splitmix(mState);
    uint64_t yState = splitmix(mState);
    uint64_t zState = splitmix(mState);

    for (unsigned i = 0; i < 10; i++) {
        const uint64_t wp = wState, xp = xState, yp = yState, zp = zState;
        wState = zp * UINT64_C(15241094284759029579);
        xState = zp + ROTL64(wp, 52);
        yState = yp - xp;
        zState = ROTL64(yp + wp, 19);
    }

    unsigned cnt = sizeof(halftime_hash_random) / sizeof(halftime_hash_random[0]);
    for (unsigned i = 0; i < cnt; ++i) {
        const uint64_t wp = wState, xp = xState, yp = yState, zp = zState;
        wState = zp * UINT64_C(15241094284759029579);
        xState = zp + ROTL64(wp, 52);
        yState = yp - xp;
        zState = ROTL64(yp + wp, 19);
        halftime_hash_random[i] = xp;
    }

    return (uintptr_t)(halftime_hash_random);
}

//------------------------------------------------------------
template <bool bswap>
static void HalftimeHash64( const void * in, const size_t len, const seed_t seed, void * out ) {
    const uint64_t * random_words = (const uint64_t *)(uintptr_t)seed;
    uint64_t         h = halftime_hash::HalftimeHashStyle64<bswap>(random_words, (const uint8_t *)in, (size_t)len);

    PUT_U64<bswap>(h, (uint8_t *)out, 0);
}

template <bool bswap>
static void HalftimeHash128( const void * in, const size_t len, const seed_t seed, void * out ) {
    const uint64_t * random_words = (const uint64_t *)(uintptr_t)seed;
    uint64_t         h = halftime_hash::HalftimeHashStyle128<bswap>(random_words, (const uint8_t *)in, (size_t)len);

    PUT_U64<bswap>(h, (uint8_t *)out, 0);
}

template <bool bswap>
static void HalftimeHash256( const void * in, const size_t len, const seed_t seed, void * out ) {
    const uint64_t * random_words = (const uint64_t *)(uintptr_t)seed;
    uint64_t         h = halftime_hash::HalftimeHashStyle256<bswap>(random_words, (const uint8_t *)in, (size_t)len);

    PUT_U64<bswap>(h, (uint8_t *)out, 0);
}

template <bool bswap>
static void HalftimeHash512( const void * in, const size_t len, const seed_t seed, void * out ) {
    const uint64_t * random_words = (const uint64_t *)(uintptr_t)seed;
    uint64_t         h = halftime_hash::HalftimeHashStyle512<bswap>(random_words, (const uint8_t *)in, (size_t)len);

    PUT_U64<bswap>(h, (uint8_t *)out, 0);
}

//------------------------------------------------------------
REGISTER_FAMILY(halftimehash,
   $.src_url    = "https://github.com/jbapple/HalftimeHash",
   $.src_status = HashFamilyInfo::SRC_STABLEISH
 );

REGISTER_HASH(HalftimeHash_64,
   $.desc       = "Halftime Hash (64-bit blocks)",
   $.impl       = HALFTIME_IMPL_STR,
   $.sort_order = 10,
   $.hash_flags =
         FLAG_HASH_LOOKUP_TABLE,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY     |
         FLAG_IMPL_ROTATE       |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0xED42E424,
   $.verification_BE = 0x7EE5ED6F,
   $.hashfn_native   = HalftimeHash64<false>,
   $.hashfn_bswap    = HalftimeHash64<true>,
   $.seedfn          = halftime_hash_seed_init
 );

REGISTER_HASH(HalftimeHash_128,
   $.desc       = "Halftime Hash (128-bit blocks)",
   $.impl       = HALFTIME_IMPL_STR,
   $.sort_order = 20,
   $.hash_flags =
         FLAG_HASH_LOOKUP_TABLE,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY     |
         FLAG_IMPL_ROTATE       |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x952DF141,
   $.verification_BE = 0xD79E990B,
   $.hashfn_native   = HalftimeHash128<false>,
   $.hashfn_bswap    = HalftimeHash128<true>,
   $.seedfn          = halftime_hash_seed_init
 );

REGISTER_HASH(HalftimeHash_256,
   $.desc       = "Halftime Hash (256-bit blocks)",
   $.impl       = HALFTIME_IMPL_STR,
   $.sort_order = 30,
   $.hash_flags =
         FLAG_HASH_LOOKUP_TABLE,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY     |
         FLAG_IMPL_ROTATE       |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x912330EA,
   $.verification_BE = 0x23C24991,
   $.hashfn_native   = HalftimeHash256<false>,
   $.hashfn_bswap    = HalftimeHash256<true>,
   $.seedfn          = halftime_hash_seed_init
 );

REGISTER_HASH(HalftimeHash_512,
   $.desc       = "Halftime Hash (512-bit blocks)",
   $.impl       = HALFTIME_IMPL_STR,
   $.sort_order = 40,
   $.hash_flags =
         FLAG_HASH_LOOKUP_TABLE,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY     |
         FLAG_IMPL_ROTATE       |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x1E0F99EA,
   $.verification_BE = 0xA3A0AE42,
   $.hashfn_native   = HalftimeHash512<false>,
   $.hashfn_bswap    = HalftimeHash512<true>,
   $.seedfn          = halftime_hash_seed_init
 );
