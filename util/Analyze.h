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
bool ReportBias( const uint32_t * counts, const int coinflips, const int trials,
        const int hashbits, const bool drawDiagram );

bool ReportChiSqIndep( const uint32_t * popcount, const uint32_t * andcount, size_t keybits,
        size_t hashbits, size_t testcount, bool drawDiagram );

template <typename hashtype>
unsigned int FindCollisions( std::vector<hashtype> & hashes, std::set<hashtype> & collisions,
        int maxCollisions = 1000, bool drawDiagram = false );

template <typename hashtype>
void PrintCollisions( std::set<hashtype> & collisions );

//-----------------------------------------------------------------------------
// This is not intended to be used directly; see below
template <typename hashtype>
bool TestHashListImpl( std::vector<hashtype> & hashes, unsigned testDeltaNum, int * logpSumPtr, bool drawDiagram,
        bool testCollision, bool testMaxColl, bool testDist, bool testHighBits, bool testLowBits, bool verbose );

// This provides a user-friendly wrapper to TestHashListImpl<>() by using
// the Named Parameter Idiom.
//
// There is also a wrapper function for this wrapper class, so that the
// template type of the class can be inferred from the type of the hash
// vector. This is needed since we are on C++11, and class types can't be
// automatically inferred from constructor parameters until C++17.

template <typename hashtype>
class TestHashListWrapper {
  private:
    std::vector<hashtype> & hashes_;
    unsigned  deltaNum_;
    int *     logpSumPtr_;
    bool      testCollisions_;
    bool      testMaxCollisions_;
    bool      testDistribution_;
    bool      testHighBits_;
    bool      testLowBits_;
    bool      verbose_;
    bool      drawDiagram_;

  public:
    inline TestHashListWrapper( std::vector<hashtype> & hashes ) :
        hashes_( hashes ), deltaNum_( 0 ), logpSumPtr_( NULL ),
        testCollisions_( true ), testMaxCollisions_( false ), testDistribution_( true ),
        testHighBits_( true ), testLowBits_( true ),
        verbose_( true ), drawDiagram_( false ) {}

    inline TestHashListWrapper & sumLogp( int * p )         { logpSumPtr_       = p; return *this; }

    inline TestHashListWrapper & testCollisions( bool s )   { testCollisions_   = s; return *this; }

    inline TestHashListWrapper & testMaxCollisions( bool s ){ testMaxCollisions_= s; return *this; }

    inline TestHashListWrapper & testDistribution( bool s ) { testDistribution_ = s; return *this; }

    inline TestHashListWrapper & testDeltas( unsigned n )   { deltaNum_         = n; return *this; }

    inline TestHashListWrapper & testHighBits( bool s )     { testHighBits_     = s; return *this; }

    inline TestHashListWrapper & testLowBits( bool s )      { testLowBits_      = s; return *this; }

    inline TestHashListWrapper & verbose( bool s )          { verbose_          = s; return *this; }

    inline TestHashListWrapper & drawDiagram( bool s )      { drawDiagram_      = s; return *this; }

    // This can't be explicit, because we want code like
    // "bool result = TestHashList()" to Just Work(tm),
    // even if that allows other, nonsensical uses of TestHashList().
    inline operator bool () const {
        return TestHashListImpl(hashes_, deltaNum_, logpSumPtr_, drawDiagram_,
                testCollisions_, testMaxCollisions_, testDistribution_,
                testHighBits_, testLowBits_, verbose_);
    }
}; // class TestHashListWrapper

template <typename hashtype>
TestHashListWrapper<hashtype> TestHashList( std::vector<hashtype> & hashes ) {
    return TestHashListWrapper<hashtype>(hashes);
}
