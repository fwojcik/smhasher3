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

#define HASHTYPELIST Blob<32>, Blob<64>, Blob<128>, Blob<160>, Blob<224>, Blob<256>

#if defined(__cplusplus) && (__cplusplus >= 201402L)
// C++14 allows auto variables to determine function return types
#define INSTANTIATE(FN, TYPELIST)                          \
    template < typename... Types>                          \
    auto FN ## _instantiator() {                           \
        static auto instances =                            \
            std::tuple_cat(std::make_tuple(FN<Types>)...); \
        return &instances;                                 \
    }                                                      \
    template auto FN ## _instantiator<TYPELIST>()
#else
// C++11 doesn't, so YOU get a void*, and YOU get a void*,....
#define INSTANTIATE(FN, TYPELIST)                      \
    template < typename... Types>                      \
    void * FN ## _instantiator() {                     \
        static auto instances =                        \
            std::make_tuple(((void *)(FN<Types>))...); \
        return (void *)(&instances);                   \
    }                                                  \
    template void * FN ## _instantiator<TYPELIST>()
#endif

// If you get a compiler error from this macro that looks like:
//
// SomeFile.cpp: In instantiation of 'void* SomeFunction_instantiator() [with Types = {Blob<32>, Blob<64>, Blob<128>, Blob<160>, Blob<224>, Blob<256>}]':
// SomeFile.cpp:176:1:   required from here
// Instantiate.h:39:30: error: insufficient contextual information to determine type
//   39 |             std::make_tuple(((void *)(FN<Types>))...);
//      |                             ~^~~~~~~~~~~~~~~~~~~~
// SomeFile.cpp:176:1: note: in expansion of macro 'INSTANTIATE'
//  176 | INSTANTIATE(SomeFunction, HASHTYPELIST);
//
// then the most common cause is a mismatch between the types in the
// definition of SomeFunction() versus its declaration.
