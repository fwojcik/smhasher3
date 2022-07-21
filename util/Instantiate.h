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
#include <tuple>

// When this list gets extended, add more ",void*" entries to the
// C++11 version of INSTANTIATE() below.
#define HASHTYPELIST Blob<32>, Blob<64>, Blob<128>, Blob<160>, Blob<224>, Blob<256>

#if defined(__cplusplus) && (__cplusplus >= 201402L)
// C++14 allows auto variables to determine function return types
#define INSTANTIATE(FN, TYPELIST)                          \
    template < typename ... Types>                         \
    auto FN ## _instantiator() {                           \
        static auto instances =                            \
            std::tuple_cat(std::make_tuple(FN<Types>)...); \
        return &instances;                                 \
    }                                                      \
    template auto FN ## _instantiator<TYPELIST>();
#else
// C++11 doesn't, so YOU get a void*, and YOU get a void*,....
#define INSTANTIATE(FN, TYPELIST)                                       \
    template < typename ... Types>                                      \
    auto FN ## _instantiator() -> void* {                               \
        static std::tuple<void*,void*,void*,void*,void*,void*>          \
            instances = std::tuple_cat(                                 \
                               std::make_tuple((void*)(FN<Types>))...); \
        return (void*)(&instances);                                     \
    }                                                                   \
    template void* FN ## _instantiator<TYPELIST>();
#endif
