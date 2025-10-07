/*
 * SMHasher3
 * Copyright (C) 2021-2023  Frank J. T. Wojcik
 * Copyright (C) 2023       jason
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
double CalcMean( std::vector<double> & v );
double CalcStdv( std::vector<double> & v );
void FilterOutliers( std::vector<double> & v );

uint64_t chooseK( int b, int k );
uint64_t chooseUpToK( int n, int k );
uint32_t InverseKChooseUpToK( uint32_t & count, const uint32_t minK, const uint32_t maxK, const uint32_t N );
uint32_t InverseNChooseUpToK( uint32_t & count, const uint32_t minN, const uint32_t maxN, const uint32_t K );
uint32_t Sum1toN( uint32_t n );
uint32_t InverseSum1toN( uint32_t sum );
void GetDoubleLoopIndices( uint32_t m, uint32_t sum, uint32_t & i, uint32_t & j );
uint64_t nthlex( uint64_t rank, const uint64_t setbits );

double EstimateNbCollisions( const unsigned long nbH, const int nbBits );
void ReportCollisionEstimates( void );
double GetMissingHashesExpected( size_t nbH, int nbBits );

int GetNLogNBound( unsigned nbH );
double ScalePValue( double p_value, unsigned testcount );
double ScalePValue2N( double p_value, int testbits );
int GetLog2PValue( double p_value );
double GetStdNormalPValue( const double variable );
double GetCoinflipBinomialPValue( const unsigned long coinflips, const unsigned long delta );
double EstimateMaxCollPValue( const unsigned long nbH, const int nbBits, const int maxColl );
double EstimateMaxCollisions( const unsigned long nbH, const int nbBits );
double GetBoundedPoissonPValue( const double expected, const uint64_t collisions );

// sumSquares() is currently instantiated for uint8_t and uint32_t.
// See SUMSQ_TYPES in Stats.cpp to expand this as needed.
// NB: bincount must be a non-zero multiple of 64!
template <typename T>
uint64_t sumSquares( const T * bins, size_t bincount );

// sumSquaresBasic() is currently instantiated for uint32_t.
// See SUMSQBASIC_TYPES in Stats.cpp to expand this as needed.
// NB: bincount can be any value.
template <typename T>
uint64_t sumSquaresBasic( const T * bins, size_t bincount );

double calcScore( const uint64_t sumsq, const int bincount, const int ballcount );
double normalizeScore( double score, int scorewidth );

double ChiSqIndepValue( const uint32_t * boxes, size_t total );
double ChiSqPValue( double chisq, uint64_t dof );
