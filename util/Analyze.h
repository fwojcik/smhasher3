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
hidx_t FindCollisions( std::vector<hashtype> & hashes, std::map<hashtype, uint32_t> & collisions, hidx_t maxCollisions );

template <typename hashtype>
hidx_t FindCollisionsIndices( std::vector<hashtype> & hashes, std::map<hashtype, uint32_t> & collisions,
        hidx_t maxCollisions, uint32_t maxPerCollision, std::vector<hidx_t> & collisionidxs,
        std::vector<hidx_t> & hashidxs );

//-----------------------------------------------------------------------------
// These is not intended to be used directly; see below
template <typename hashtype>
bool TestHashListImpl( std::vector<hashtype> & hashes, int * logpSumPtr, KeyFn keyprint,
        unsigned testDeltaNum, flags_t testFlags, flags_t reportFlags );

#define TEST(flagname, var) (!!(var & FLAG_TEST_ ## flagname))
#define FLAG_TEST_COLLISIONS    (1 << 0)
#define FLAG_TEST_MAXCOLLISIONS (1 << 1)
#define FLAG_TEST_DISTRIBUTION  (1 << 2)
#define FLAG_TEST_HIGHBITS      (1 << 3)
#define FLAG_TEST_LOWBITS       (1 << 4)
#define FLAG_TEST_DELTAXAXIS    (1 << 5)

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
    KeyFn     keyPrint_;
    flags_t   reportFlags_;
    bool      testCollisions_;
    bool      testMaxCollisions_;
    bool      testDistribution_;
    bool      testHighBits_;
    bool      testLowBits_;
    bool      quietMode_;

  public:
    inline TestHashListWrapper( std::vector<hashtype> & hashes ) :
        hashes_( hashes ), deltaNum_( 0 ), logpSumPtr_( NULL ), keyPrint_( NULL ), reportFlags_( 0 ),
        testCollisions_( true ), testMaxCollisions_( false ), testDistribution_( true ),
        testHighBits_( true ), testLowBits_( true ), quietMode_( false ) {}

    inline TestHashListWrapper & sumLogp( int * p )         { logpSumPtr_       = p; return *this; }

    inline TestHashListWrapper & testCollisions( bool s )   { testCollisions_   = s; return *this; }

    inline TestHashListWrapper & testMaxCollisions( bool s ){ testMaxCollisions_= s; return *this; }

    inline TestHashListWrapper & testDistribution( bool s ) { testDistribution_ = s; return *this; }

    inline TestHashListWrapper & testDeltas( unsigned n )   { deltaNum_         = n; return *this; }

    inline TestHashListWrapper & testHighBits( bool s )     { testHighBits_     = s; return *this; }

    inline TestHashListWrapper & testLowBits( bool s )      { testLowBits_      = s; return *this; }

    inline TestHashListWrapper & dumpFailKeys( KeyFn p )    { keyPrint_         = std::move(p); return *this; }

    inline TestHashListWrapper & quiet( bool s )            { quietMode_        = s; return *this; }

    inline TestHashListWrapper & reportFlags( flags_t f )   { reportFlags_      = f; return *this; }

    // This can't be explicit, because we want code like
    // "bool result = TestHashList()" to Just Work(tm),
    // even if that allows other, nonsensical uses of TestHashList().
    inline operator bool () const {
        flags_t testFlags_ = 0;

        if (testCollisions_)    { testFlags_ |= FLAG_TEST_COLLISIONS;    }
        if (testMaxCollisions_) { testFlags_ |= FLAG_TEST_MAXCOLLISIONS; }
        if (testDistribution_)  { testFlags_ |= FLAG_TEST_DISTRIBUTION;  }
        if (testHighBits_)      { testFlags_ |= FLAG_TEST_HIGHBITS;      }
        if (testLowBits_)       { testFlags_ |= FLAG_TEST_LOWBITS;       }

        return TestHashListImpl(hashes_, logpSumPtr_, keyPrint_, deltaNum_,
                testFlags_, quietMode_ ? FLAG_REPORT_QUIET : reportFlags_);
    }
}; // class TestHashListWrapper

template <typename hashtype>
TestHashListWrapper<hashtype> TestHashList( std::vector<hashtype> & hashes ) {
    return TestHashListWrapper<hashtype>(hashes);
}
