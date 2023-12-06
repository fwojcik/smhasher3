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
 *     Copyright (c) 2015      Paul G
 *     Copyright (c) 2015-2021 Reini Urban
 *     Copyright (c) 2016      Vlad Egorov
 *     Copyright (c) 2019-2020 Yann Collet
 *     Copyright (c) 2020      Bradley Austin Davis
 *     Copyright (c) 2020      Paul Khuong
 *     Copyright (c) 2021      Jim Apple
 *     Copyright (c) 2021      Ori Livneh
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
template <typename hashtype>
void PrintCollisions( const std::map<hashtype, uint32_t> & collisions, const size_t maxCollisions,
        const uint32_t maxPerCollision = 0, const std::vector<hidx_t> & idxs = {}, const KeyFn keyprint = NULL,
        const unsigned delta = 0, const bool deltaXaxis = false, const hidx_t nbH = 0, const uint32_t nbBits = sizeof(hashtype) * 8,
        const uint32_t prevBits = sizeof(hashtype) * 8, const bool reversebits = false );

template <typename hashtype>
void ShowOutliers( const std::vector<hashtype> & hashes, const std::vector<hidx_t> & hashidxs, const KeyFn keyprint,
        const unsigned delta, const bool deltaXaxis, const uint32_t maxEntries, const uint32_t maxPerEntry,
        const uint32_t bitOffset, const uint32_t bitWidth );

bool ReportBias( const uint32_t * counts, const int coinflips, const int trials,
        const int hashbits, const flags_t flags );

bool ReportChiSqIndep( const uint32_t * popcount, const uint32_t * andcount, size_t keybits,
        size_t hashbits, size_t testcount, const flags_t flags );

bool ReportCollisions( uint64_t const nbH, int collcount, unsigned hashsize, int * logpp,
        bool maxcoll, bool highbits, bool header, const flags_t flags );

bool ReportBitsCollisions( uint64_t nbH, const int * collcounts, int minBits, int maxBits,
        int * logpp, int * maxbitsp, bool highbits, const flags_t flags );

bool ReportDistribution( const std::vector<double> & score, int tests, int hashbits, int maxwidth, int minwidth,
        int * logpp, int * worstStartp, int * worstWidthp, const flags_t flags );
