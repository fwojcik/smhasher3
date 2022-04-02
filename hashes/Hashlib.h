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

#define CONCAT_INNER(x, y) x##y
#define CONCAT(x,y) CONCAT_INNER(x, y)

#define REGISTER_FAMILY(N)                                  \
    static const char * THIS_HASH_FAMILY = #N;              \
    unsigned CONCAT(N,_ref)

#define REGISTER_HASH(N, ...)                               \
    static_assert(sizeof(#N) > 1,                           \
            "REGISTER_HASH() needs a non-empty name");      \
    static HashInfo CONCAT(Details,N) = []{                 \
        HashInfo $(#N, THIS_HASH_FAMILY);                   \
        __VA_ARGS__;                                        \
        return $;                                           \
    }();

#define USE_FAMILY(N)                                       \
    extern unsigned CONCAT(N,_ref);                         \
    CONCAT(N,_ref) = 1
