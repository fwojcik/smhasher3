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

#define HASHTYPELIST uint32_t, uint64_t, uint128_t, Blob<160>, Blob<224>, uint256_t

#define INSTANTIATE(FN, TYPELIST)                               \
    template < typename ... Types>                              \
    auto FN ## _instantiator() {                                \
    static auto instances =                                     \
        std::tuple_cat(std::make_tuple(FN<Types>)...);          \
    return &instances;                                          \
    }                                                           \
    template auto FN ## _instantiator<TYPELIST>();