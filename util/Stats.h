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
double CalcMean( std::vector<double> & v );
double CalcMean( std::vector<double> & v, int a, int b );
double CalcStdv( std::vector<double> & v );
double CalcStdv( std::vector<double> & v, int a, int b );
bool ContainsOutlier( std::vector<double> & v, size_t len );
void FilterOutliers( std::vector<double> & v );

double chooseK( int b, int k );
double chooseUpToK( int n, int k );

double EstimateNbCollisions( const unsigned long nbH, const int nbBits );
void ReportCollisionEstimates( void );

int GetNLogNBound( unsigned nbH );
double ScalePValue( double p_value, unsigned testcount );
double ScalePValue2N( double p_value, unsigned testbits );
int GetLog2PValue( double p_value );
double GetNormalPValue( const double mu, const double sd, const double variable );
double EstimatedBinomialPValue( const unsigned long nbH, const int nbBits, const int maxColl );
double EstimateMaxCollisions( const unsigned long nbH, const int nbBits );
double BoundedPoissonPValue( const double expected, const uint64_t collisions );

double calcScore( const unsigned * bins, const int bincount, const int ballcount );
double normalizeScore( double score, int scorewidth, int tests );

double ChiSqIndepValue( const uint32_t * boxes, size_t total );
double ChiSqPValue( double chisq, uint64_t dof );
