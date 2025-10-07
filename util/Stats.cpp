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
#include "Platform.h"
#include "Instantiate.h"

#include <vector>
#include <algorithm>
#include <numeric>
#include <math.h>

#include "Stats.h"

//-----------------------------------------------------------------------------
// Some useful constant(s). These are not guaranteed to be available from
// math.h or cmath, so we simply define them here, instead of having
// additional platform detection (for things like _USE_MATH_DEFINES) and
// fallback code.

#if !defined(M_SQRT1_2)
  #define M_SQRT1_2 0.70710678118654752440 //  1.0 / sqrt(2.0)
#endif

//-----------------------------------------------------------------------------
// Means, standard deviations, and outlier removal

double CalcMean( std::vector<double> & v ) {
    double sum = std::accumulate(v.begin(), v.end(), 0.0);

    return sum / v.size();
}

// Calculate the sum of squared differences from the mean.
// (The input data values are all well-behaved enough that
// there is no need to worry about numeric overflow.)
static double CalcSumSq( std::vector<double>::const_iterator first, std::vector<double>::const_iterator last,
        double mean ) {
    auto   n   = std::distance(first, last);
    double sum = 0, sumsq = 0;

    while (first != last) {
        double x = *first++ - mean;
        sum   += x;
        sumsq += x * x;
    }
    // This is the "corrected two-pass" algorithm.  If arithmetic were exact,
    // sum would be zero, but including the sum*sum term improves precision.
    return sumsq - sum * sum / n;
}

double CalcStdv( std::vector<double> & v ) {
    double mean  = CalcMean(v);
    double sumsq = CalcSumSq(v.cbegin(), v.cend(), mean);

    return sqrt(sumsq / v.size());
}

// Remove outliers from the vector until all members
// are within 3 standard deviations of the mean.
//
// This only removes high outliers, as it is applied to
// benchmark timings where crazy-low values don't happen.
//
// The vector is permuted in place (sorted, actually)
// to accomplish this.
void FilterOutliers( std::vector<double> & v ) {
    std::sort(v.begin(), v.end());

    if (v.size() <= 2) {
        return;
    }

    double mean  = CalcMean(v);
    double sumsq = CalcSumSq(v.cbegin(), v.cend(), mean);

    do {
        double n_1  = v.size() - 1;
        double diff = v.back() - mean; // Always positive

        // Is this difference more than 3 standard deviations?
        //
        // Rather than test abs(diff) > 3*sqrt(variance) = 3*sqrt(sumsq/(n-1)),
        // we test (n-1) * diff**2 > 9 * sumsq.
        if (diff * diff * n_1 <= 9 * sumsq) {
            break; // All samples are in range
        }

        v.pop_back();

        // Welford's incremental algorithm in reverse
        // (or, equivalently, with a sample weight of -1).
        // Remove the sample from the mean and sum of squares.
        double delta = diff / n_1;
        mean  -= delta;
        sumsq -= diff * (diff - delta);
    } while (v.size() > 2);
}

//-----------------------------------------------------------------------------
// Some combinatoric math

uint64_t chooseK( int n, int k ) {
    if ((k <  0) || (k >  n)) { return 0; }
    if ((k == 0) || (k == n)) { return 1; }
    if (k > (n - k))          { k = n - k; }

    double c = 1;

    for (int i = 0; i < k; i++) {
        c *= double(n - i) / double(i + 1);
    }

    return (uint64_t)round(c);
}

uint64_t chooseUpToK( int n, int k ) {
    uint64_t c = 0;

    for (int i = 1; i <= k; i++) {
        c += chooseK(n, i);
    }

    return c;
}

// Returns largest K such that ChooseUpToK(N,K) < count, where
// minK<=K<=maxK. The value of input is set to the remainder (count -
// chooseUpToK(N,K)). If ChooseUpToK(N,maxK) >= count, then maxK is
// returned with the remainder set correctly.
uint32_t InverseKChooseUpToK( uint32_t & count, const uint32_t minK, const uint32_t maxK, const uint32_t N ) {
    uint64_t K;

    for (K = minK; K <= maxK; K++) {
        uint64_t curcount = chooseK(N, K);
        if (count < curcount) { break; }
        count -= curcount;
    }
    return K;
}

// Returns largest N such that ChooseUpToK(N,K) < count, where
// minN<=N<=maxN. The value of input is set to the remainder (count -
// chooseUpToK(N,K)). If ChooseUpToK(maxN,K) >= count, then maxN is
// returned with the remainder set correctly.
uint32_t InverseNChooseUpToK( uint32_t & count, const uint32_t minN, const uint32_t maxN, const uint32_t K ) {
    uint64_t N;

    for (N = minN; N <= maxN; N++) {
        uint64_t curcount = chooseK(N, K);
        if (count < curcount) { break; }
        count -= curcount;
    }
    return N;
}

uint32_t Sum1toN( uint32_t n ) {
    return n * (n + 1) / 2;
}

// Returns largest N such that Sum1toN(N) <= sum.
uint32_t InverseSum1toN( uint32_t sum ) {
    return (uint32_t)(floor((sqrt(1.0 + 8.0 * sum) - 1.0) / 2.0));
}

// This is a numeric expression to calculate:
// SUM(a = 0..x-1)(SUM(b = a+1..m-1)(1)), or, in ASCII:
//
//  x-1   m-1
//  ---   ---
//  \     \    1
//  /     /
//  ---   ---
//  a=0  b=a+1
//
// This computes how many times a nested loop like:
// for (int a = 0; a < m - 1; a++) {
//     for (int b = a + 1; b < m; b++) {
//         do_one_thing();
//     }
//     ...expression valid here...
// }
// has run so far for given values of m and a at the
// indicated place in the code.
static uint32_t DoubleSum( uint32_t m, uint32_t x ) {
    return (2 * m * x - x * x - x) / 2;
}

// This computes the inverse of DoubleSum(). That is, it finds the largest
// value of x for which DoubleSum(m, x) < n. This allows computing how many
// times the outer loop in the DoubleSum() example has run for a given
// count of how many times do_one_thing() has been called.
static uint32_t InverseDoubleSum( uint32_t m, uint32_t n ) {
    return (2 * m - 1 - sqrt(4 * m * m - 4 * m - 8 * n + 1)) / 2;
}

// This finds the inner and outer loop indices for the code in the
// DoubleSum() examples, given the value of m and the count of how many
// times do_one_thing() has been called.
//
// It first finds the largest number of outer loops which could have been
// done, then finds how many times do_one_thing() was called during all
// those full outer loops, and subtracts that from the number of times it
// was done to find the number of times the inner loop was done during the
// current partial outer loop. It then converts that count into an index by
// adding "i + 1", since the values for j start there in the for() loop.
void GetDoubleLoopIndices( uint32_t m, uint32_t sum, uint32_t & i, uint32_t & j ) {
    i = InverseDoubleSum(m, sum);
    j = sum - DoubleSum(m, i) + i + 1;
}

// This computes the value gotten by repeating nextlex() N times when
// starting with the smallest value with setbits set.
uint64_t nthlex( uint64_t N, const uint64_t setbits ) {
    uint64_t out = 0;
    int64_t i = setbits - 1;
    while (i >= 0) {
        uint64_t l = i, t;
        while ((t = chooseK(l, i + 1)) <= N) {
            l++;
        }
        //printf("r %ld, C(%ld,%ld)=%ld\t", N, l, i+1, t);
        out |= UINT64_C(1) << (l - 1);
        N -= chooseK(l - 1, i + 1);
        i--;
    }
    return out;
}

//-----------------------------------------------------------------------------
// Different ways of estimating collision counts across N numbers,
// each of which is i.i.d. distributed across M bins.

// The previous best calculation, highly prone to inaccuracies with low results (1.0 - 10.0)
static double EstimateNbCollisions_prevprev( const double nbH, const double nbBits ) {
    double exp    = exp2(nbBits); // 2 ^ bits
    double result = (nbH * (nbH - 1)) / (2.0 * exp);

    if (result > nbH) {
        result = nbH;
    }
    // improved floating point accuracy
    if ((result <= exp) || (nbBits > 32)) {
        return result;
    }
    return result - exp;
}

static double EstimateNbCollisions_prev( const double nbH, const int nbBits ) {
    // If the probability that there are 1 or more collisions (p(C >=
    // 1)) is not much higher than the probability of exactly 1
    // collision (p(C == 1)), then the classically-good approximation
    // of the probability of any collisions is also a good estimate
    // for the expected number of collisions.
    //
    // If there are 2**n buckets and 2**(n-r) hashes, then the ratio
    // of p(C >= 1)/p(C == 1) is about 1/(1-2**(n-2r-1)). This uses
    // the new estimator if that ratio is > 1 + 2**-8. That cutoff
    // minimizes the error around the values we care about.
    if (nbBits - 2.0 * log2(nbH) >= 8 - 1) {
        return nbH * (nbH - 1) * exp2(-nbBits - 1);
    }

    // The probability that any given hash bucket is empty after nbH
    // insertions is:
    //    pE     = ((2**nbBits - 1)/(2**nbBits))**nbH
    // so we compute:
    //    ln(pE) = nbH * ln((2**nbBits - 1)/(2**nbBits))
    //           = nbH * ln(1 - 1/2**(nbBits))
    //           = nbH * ln(1 - 2**(-nbBits))
    //           = nbH * ln(1 + -(2**(-nbBits)))
    // This means the probability that any given hash bucket is
    // occupied after nbH insertions is:
    //     pF = 1 - pE
    //     pF = 1 - exp(ln(pE))
    //     pF = -(exp(ln(pE)) - 1)
    //     pF = -expm1(ln(pE))
    // And the expected number of collisions is:
    //     C = m - n + n * pE
    //     C = m - n * (1 - pE)
    //     C = n * (m/n - 1 + pE)
    //     C = n * (m/n - (1 - pE))
    //     C = n * (m/n - pF)
    //     C = n * (m/n - (-expm1(ln(pE))))
    //     C = n * (m/n + expm1(ln(pE)))
    // Since the format of floats/doubles is k*2**n, multiplying by
    // exp2(x) doesn't lose any precision, and this formulation keeps
    // m/n and pF at the same general orders of magnitude, so it tends
    // to have very good precision. At low hash occupancy, pF is too
    // close to m/n for this formula to work well.
    double logpE  = (double)nbH * log1p(-exp2(-nbBits));
    double result = exp2(nbBits) * (exp2(-nbBits) * (double)nbH + expm1(logpE));

    return result;
}

static double EstimateNbCollisions_cur( const double nbH, const int nbBits ) {
    // It would be nice if we could always use the full formula for
    // computing the expected collision count. However, one of its
    // requirements for giving usable results is that 1-2**(-nbBits) needs
    // to fit in a double with room for a guard bit and an error bit. Since
    // doubles have 53 bits of mantissa, nbBits cannot exceed 51 to use it.
    //
    // If it cannot be used, then we use the simpler estimation here. This
    // is a good estimate when the probability that there are 1 or more
    // collisions (p(C >= 1)) is not much higher than the probability of
    // exactly 1 collision (p(C == 1)).
    //
    // As is probably less of a coincidence than it seems, this simpler
    // formula is also the first term in the Taylor/Laurent series of the
    // full formula.
    //
    // Because of that, we know the maximum absolute error for the simpler
    // estimation is bounded by the magnitude of the second term, which is
    // ((nbH-2)*(nbH-1)*nbH)/((2**nbBits)*3!), so relative error goes as
    // nbH/(2**nbBits) approximately.
    //
    // The error for the full formula is quite complicated, and doesn't
    // form a smooth graph. I tested this empirically by plotting out the
    // values it produces versus those from exactcoll.c. This cutoff is
    // fairly simple, and produces RMSE close to the minimum possible with
    // these two choices for estimation.
    if ((nbBits > 51) || (nbH < exp2(nbBits - 25.5))) {
        return ldexp(nbH * (nbH - 1), -nbBits - 1);
    }

    // The probability that any given hash bucket is empty after nbH
    // insertions is:
    //    pE     = ((2**nbBits - 1)/(2**nbBits))**nbH
    // so we compute:
    //    ln(pE) = nbH * ln((2**nbBits - 1)/(2**nbBits))
    //           = nbH * ln(1 - 1/2**(nbBits))
    //           = nbH * ln(1 - 2**(-nbBits))
    //           = nbH * ln(1 + -(2**(-nbBits)))
    // This means the probability that any given hash bucket is
    // occupied after nbH insertions is:
    //     pF = 1 - pE
    //     pF = 1 - exp(ln(pE))
    //     pF = -(exp(ln(pE)) - 1)
    //     pF = -expm1(ln(pE))
    // And the expected number of collisions is:
    //     C = m - nF
    //     C = m - n * pF
    //     C = m - n * (-expm1(ln(pE)))
    //     C = m + n * expm1(ln(pE))
    //
    // If 1-2**(-nbBits) is too close to 1, then (the correct answer for)
    // log1p(-exp2(-nbBits)) is -exp2(-nbBits). This means that expm1(nbH *
    // -exp2(-nbBits)) is also (again, correctly) -nbH * exp2(-nbBits), and
    // so the result becomes nbH + (-nbH) which is 0.
    //
    // In other words, with this formulation, the answer's delta from nbH
    // must be expressable in a double, and if 1-2**(-nbBits) is too close
    // to 1 then it cannot be.
    double logpE  = nbH * log1p(-exp2(-nbBits));
    double result = nbH + ldexp(expm1(logpE), nbBits);
    return result;
}

double EstimateNbCollisions( const unsigned long nbH, const int nbBits ) {
    return EstimateNbCollisions_cur((double)nbH, (double)nbBits);
}

#define COLLISION_ESTIMATORS 3

static double EstimateNbCollisionsCand( const unsigned long nbH, const int nbBits, const int estimator ) {
    switch (estimator) {
    case 0: return EstimateNbCollisions_cur((double)nbH, (double)nbBits);
    case 1: return EstimateNbCollisions_prev((double)nbH, (double)nbBits);
    case 2: return EstimateNbCollisions_prevprev((double)nbH, (double)nbBits);
    default: { printf("Invalid estimator requested\n"); exit(1); }
    }
    return NAN;
}

//-----------------------------------------------------------------------------

/*
 * This list of actual expected collision values was generated via the
 * exactcoll.c program which uses the MPFI or MPFR library to compute
 * these values with 768 bits of precision, and then post-processed
 * via strtod() to get the maximum number of digits that can fit in a
 * double.
 */
static const double realcoll[59][24] = {
    /* 149633745 */
    {
        9.66830188511513408e-62, 4.15250404044246501e-52, 7.66001792990870096e-33,
        3.28995264957314909e-23, 6.06889145411344312e-04, 4.85511316319886099e-03,
        3.88409052997096826e-02, 3.10727242021280714e-01, 2.48581791208085123e+00,
        1.98865417549256875e+01, 1.59092235369305229e+02, 1.27273156809446004e+03,
        1.01814484072519826e+04, 8.14257293862626102e+04, 6.49754472522680881e+05,
        2.57656049031511368e+06, 1.90430490019698478e+07, 8.97430373397975862e+07,
        1.41245137150265992e+08, 1.48585169000000000e+08, 1.49502673000000000e+08,
        1.49617361000000000e+08, 1.49629649000000000e+08, 1.49633489000000000e+08
    },
    /* 86536545 */
    {
        3.23362916384237121e-62, 1.38883315060948101e-52, 2.56194496903768089e-33,
        1.10034698561685720e-23, 2.02978192359201898e-04, 1.62382553885584077e-03,
        1.29906043097091622e-02, 1.03924834404869174e-01, 8.31398670579490129e-01,
        6.65118906643028396e+00, 5.32094934462872544e+01, 4.25674726123333983e+02,
        3.40531963789505289e+03, 2.72375549284073895e+04, 2.17580696700989734e+05,
        8.65959061394601478e+05, 6.61418293104189448e+06, 3.79101215295847207e+07,
        7.81482146675371230e+07, 8.54879690000000000e+07, 8.64054730000000000e+07,
        8.65201610000000000e+07, 8.65324490000000000e+07, 8.65362890000000000e+07
    },
    /* 75498113 */
    {
        2.46129292104772484e-62, 1.05711726017762883e-52, 1.95003715543977527e-33,
        8.37534580859870329e-24, 1.54497860659825494e-04, 1.23598288526680046e-03,
        9.88786308137898882e-03, 7.91029046026853616e-02, 6.32823233727303203e-01,
        5.06258567179093433e+00, 4.05006727005713998e+01, 3.24004570485895670e+02,
        2.59198465316912234e+03, 2.07325553884721230e+04, 1.65648075271684327e+05,
        6.59692186580697889e+05, 5.06817564395631664e+06, 3.01760989953613915e+07,
        6.71105401568118781e+07, 7.44495370000000000e+07, 7.53670410000000000e+07,
        7.54817290000000000e+07, 7.54940170000000000e+07, 7.54978570000000000e+07
    },
    /* 56050289 */
    {
        1.35658440124283578e-62, 5.82648563760172142e-53, 1.07479689405983373e-33,
        4.61621750982936253e-24, 8.51541829923128089e-05, 6.81233463933672676e-04,
        5.44986771116027276e-03, 4.35989416694992429e-02, 3.48791532089885836e-01,
        2.79033217568816827e+00, 2.23226522195275905e+01, 1.78580885854164848e+02,
        1.42862584536822192e+03, 1.14276474456061078e+04, 9.13342530600300379e+04,
        3.64148636055323470e+05, 2.82665629721443821e+06, 1.80520066603827029e+07,
        4.76721971728630289e+07, 5.50017130000000000e+07, 5.59192170000000000e+07,
        5.60339050000000000e+07, 5.60461930000000000e+07, 5.60500330000000000e+07
    },
    /* 49925029 */
    {
        1.07628616390943998e-62, 4.62261387512834023e-53, 8.52721751060712554e-34,
        3.66241203339361373e-24, 6.75595774724252468e-05, 5.40476619775988798e-04,
        4.32381295798947053e-03, 3.45905036499356000e-02, 2.76724028304754399e-01,
        2.21379216917528954e+00, 1.77103336885872338e+01, 1.41682434960860121e+02,
        1.13344446879300199e+03, 9.06659513901044375e+03, 7.24713259290786373e+04,
        2.89045130868813896e+05, 2.25101610920316912e+06, 1.47088038565696087e+07,
        4.15582470078917369e+07, 4.88764530000000000e+07, 4.97939570000000000e+07,
        4.99086450000000000e+07, 4.99209330000000000e+07, 4.99247730000000000e+07
    },
    /* 44251425 */
    {
        8.45562327779528750e-63, 3.63166254454270828e-53, 6.69923495212561545e-34,
        2.87729950275996440e-24, 5.30768075507823733e-05, 4.24614460403882252e-04,
        3.39691568307894749e-03, 2.71753254548965095e-02, 2.17402603016127682e-01,
        1.73922078425417981e+00, 1.39137637220439760e+01, 1.11309946449228335e+02,
        8.90469118761454069e+02, 7.12308402182333521e+03, 5.69418878892858920e+04,
        2.27182256963651860e+05, 1.77461480911257491e+06, 1.18487668776659127e+07,
        3.59057417517580613e+07, 4.32028490000000000e+07, 4.41203530000000000e+07,
        4.42350410000000000e+07, 4.42473290000000000e+07, 4.42511690000000000e+07
    },
    /* 43691201 */
    {
        8.24288176206433810e-63, 3.54029075928611856e-53, 6.53068375830698963e-34,
        2.80490731624468888e-24, 5.17414074132004304e-05, 4.13931259303315831e-04,
        3.31145007428012032e-03, 2.64916005848709717e-02, 2.11932804079288328e-01,
        1.69546239425482215e+00, 1.35636966977519453e+01, 1.08509416379863268e+02,
        8.68065270199544671e+02, 6.94387831824725799e+03, 5.55098463480068531e+04,
        2.21476017148987623e+05, 1.73055958502948540e+06, 1.15794825654172357e+07,
        3.53484823256153688e+07, 4.26426250000000000e+07, 4.35601290000000000e+07,
        4.36748170000000000e+07, 4.36871050000000000e+07, 4.36909450000000000e+07
    },
    /* 33558529 */
    {
        4.86291784915122170e-63, 2.08860731252391586e-53, 3.85280045646069782e-34,
        1.65476519585125690e-24, 3.05250300699314860e-05, 2.44200240558415337e-04,
        1.95360192440098080e-03, 1.56288153909619858e-02, 1.25030522855960641e-01,
        1.00024416545663009e+00, 8.00195221062565132e+00, 6.40155464513191390e+01,
        5.12119812688887009e+02, 4.09666674805581533e+03, 3.27546707358589847e+04,
        1.30763213462519823e+05, 1.02731598739112553e+06, 7.15076352258244343e+06,
        2.53234886574383602e+07, 3.25099530000000149e+07, 3.34274570000000000e+07,
        3.35421450000000000e+07, 3.35544330000000000e+07, 3.35582730000000000e+07
    },
    /* 33554432 */
    {
        4.86173054093815170e-63, 2.08809736752937507e-53, 3.85185977398010151e-34,
        1.65436117580224877e-24, 3.05175772154867956e-05, 2.44140617722858139e-04,
        1.95312494171654793e-03, 1.56249995294880754e-02, 1.24999995964268876e-01,
        9.99999950329464760e-01, 7.99999849001593066e+00, 6.39999167125279200e+01,
        5.11994776448079449e+02, 4.09566656497021177e+03, 3.27466761046086358e+04,
        1.30731328417170167e+05, 1.02706774802737299e+06, 7.14915140285272896e+06,
        2.53194666782758720e+07, 3.25058560000000149e+07, 3.34233600000000000e+07,
        3.35380480000000000e+07, 3.35503360000000000e+07, 3.35541760000000000e+07
    },
    /* 26977161 */
    {
        3.14256005499304537e-63, 1.34971926619110914e-53, 2.48979258747824472e-34,
        1.06935777370422802e-24, 1.97261691747440925e-05, 1.57809353397414244e-04,
        1.26247482714484977e-03, 1.00997986149531007e-02, 8.07983887784601701e-02,
        6.46387101193144242e-01, 5.17109623133483520e+00, 4.13687328452462069e+01,
        3.30947494428591369e+02, 2.64742838941390892e+03, 2.11697306377375826e+04,
        8.45461443414444802e+04, 6.66574543746769894e+05, 4.76323769433162268e+06,
        1.89250877744348980e+07, 2.59285850000070371e+07, 2.68460890000000000e+07,
        2.69607770000000000e+07, 2.69730650000000000e+07, 2.69769050000000000e+07
    },
    /* 22370049 */
    {
        2.16085171788696973e-63, 9.28078745982995323e-54, 1.71200311073976113e-34,
        7.35299737127754043e-25, 1.35638860682561044e-05, 1.08511088545741802e-04,
        8.68088708346283688e-04, 6.94470966551262447e-03, 5.55576772436117278e-02,
        4.44461412797580446e-01, 3.55569097269661327e+00, 2.84455066818081725e+01,
        2.27562703076283753e+02, 1.82041520386826460e+03, 1.45577924753465522e+04,
        5.81554370404469810e+04, 4.59645385789985245e+05, 3.34648071803403785e+06,
        1.45642806271550488e+07, 2.13214730005694665e+07, 2.22389770000000000e+07,
        2.23536650000000000e+07, 2.23659530000000000e+07, 2.23697930000000000e+07
    },
    /* 18877441 */
    {
        1.53878283990836292e-63, 6.60902197305242237e-54, 1.21914936914420980e-34,
        5.23620666941341261e-25, 9.65909643476873488e-06, 7.72727714779653614e-05,
        6.18182171811914086e-04, 4.94545737373954832e-03, 3.95636589415474457e-02,
        3.16509268436767577e-01, 2.53207394937498709e+00, 2.02565789153807430e+01,
        1.62051819830848984e+02, 1.29636262490162721e+03, 1.03675781381119505e+04,
        4.14247903550759002e+04, 3.28028082683300890e+05, 2.42268551654417766e+06,
        1.13726618273047991e+07, 1.78288650159229226e+07, 1.87463690000000000e+07,
        1.88610570000000000e+07, 1.88733450000000000e+07, 1.88771850000000000e+07
    },
    /* 18616785 */
    {
        1.49658179329122305e-63, 6.42776985797483522e-54, 1.18571425534766178e-34,
        5.09260394911920045e-25, 9.39419617181328754e-06, 7.51535693743293179e-05,
        6.01228554983308208e-04, 4.80982843914157677e-03, 3.84786274667397454e-02,
        3.07829016764774366e-01, 2.46263194409301622e+00, 1.97010433911390486e+01,
        1.57607568789630221e+02, 1.26081073825066096e+03, 1.00832987837376331e+04,
        4.02895318773614636e+04, 3.19083263398166222e+05, 2.35915656000438472e+06,
        1.11398998287577368e+07, 1.75682090204164460e+07, 1.84857130000000000e+07,
        1.86004010000000000e+07, 1.86126890000000000e+07, 1.86165290000000000e+07
    },
    /* 17676661 */
    {
        1.34924729526152486e-63, 5.79497300736470505e-54, 1.06898383980911691e-34,
        4.59125063193266000e-25, 8.46936253854919755e-06, 6.77549003082420902e-05,
        5.42039202456241027e-04, 4.33631361902940549e-03, 3.46905089125217683e-02,
        2.77524068758511822e-01, 2.22019238740171643e+00, 1.77615286885706851e+01,
        1.42091563230046631e+02, 1.13668986536479952e+03, 9.09079062335223534e+03,
        3.63257830806934944e+04, 2.87837384102243173e+05, 2.13641760546809947e+06,
        1.03078996469587795e+07, 1.66280850500445329e+07, 1.75455890000000000e+07,
        1.76602770000000000e+07, 1.76725650000000000e+07, 1.76764050000000000e+07
    },
    /* 16777216 */
    {
        1.21543259901182161e-63, 5.22024326324805573e-54, 9.62964914796432828e-35,
        4.13590281624610549e-25, 7.62939407650033587e-06, 6.10351526118731654e-05,
        4.88281220886695622e-04, 3.90624976656302669e-03, 3.12499980985497493e-02,
        2.49999982615312394e-01, 1.99999972184502894e+00, 1.59999888738063110e+01,
        1.27999341331538730e+02, 1.02395827357716189e+03, 8.18933349644321879e+03,
        3.27253730219586105e+04, 2.59434518880420335e+05, 1.93278773688231292e+06,
        9.52388250430562906e+06, 1.57286401180007830e+07, 1.66461440000000000e+07,
        1.67608320000000000e+07, 1.67731200000000000e+07, 1.67769600000000000e+07
    },
    /* 16777214 */
    {
        1.21543230923011700e-63, 5.22024201864511143e-54, 9.62964685207712960e-35,
        4.13590183017006213e-25, 7.62939225751109495e-06, 6.10351380599592381e-05,
        4.88281104471384203e-04, 3.90624883524053534e-03, 3.12499906479698324e-02,
        2.49999923010673836e-01, 1.99999924500797022e+00, 1.59999850591130244e+01,
        1.27999310814196164e+02, 1.02395802945145931e+03, 8.18933154427175668e+03,
        3.27253652246982456e+04, 2.59434457346894662e+05, 1.93278729448391078e+06,
        9.52388077497621253e+06, 1.57286381180010084e+07, 1.66461420000000000e+07,
        1.67608300000000000e+07, 1.67731180000000000e+07, 1.67769580000000000e+07
    },
    /* 15082603 */
    {
        9.82298962180288047e-64, 4.21894191745907802e-54, 7.78257418132130597e-35,
        3.34259015874689832e-25, 6.16599052016874108e-06, 4.93279241612558199e-05,
        3.94623393284023653e-04, 3.15698714588672326e-03, 2.52558971424239609e-02,
        2.02047175560522901e-01, 1.61637730343658670e+00, 1.29310119604492382e+01,
        1.03447681794209998e+02, 8.27554966148465496e+02, 6.61874485025192644e+03,
        2.64517551029136412e+04, 2.09891694997857179e+05, 1.57474499124399060e+06,
        8.08341736988548376e+06, 1.40340275939534362e+07, 1.49515310000000000e+07,
        1.50662190000000000e+07, 1.50785070000000000e+07, 1.50823470000000000e+07
    },
    /* 14986273 */
    {
        9.69791481108703163e-64, 4.16522269530128191e-54, 7.68347970702294475e-35,
        3.30002940611432092e-25, 6.08747978902901173e-06, 4.86998383121397741e-05,
        3.89598706491209995e-04, 3.11678965155155231e-03, 2.49343171882122662e-02,
        1.99474535956888466e-01, 1.59579618853129279e+00, 1.27663631643288511e+01,
        1.02130499305017295e+02, 8.17018010522127611e+02, 6.53448147035659167e+03,
        2.61151435765585957e+04, 2.07231508480752498e+05, 1.55541067031408940e+06,
        8.00313466924665868e+06, 1.39376976511033699e+07, 1.48552010000000000e+07,
        1.49698890000000000e+07, 1.49821770000000000e+07, 1.49860170000000000e+07
    },
    /* 14776336 */
    {
        9.42810913278675722e-64, 4.04934203884380436e-54, 7.46971762574649011e-35,
        3.20821929129359426e-25, 5.91812001988149620e-06, 4.73449601589634851e-05,
        3.78759681266044443e-04, 3.03007744976589765e-03, 2.42406195749298829e-02,
        1.93924955114811864e-01, 1.55139954590235973e+00, 1.24111902861887344e+01,
        9.92891331048678722e+01, 7.94288157680852578e+02, 6.35271154067807493e+03,
        2.53890076205234654e+04, 2.01492261805796676e+05, 1.51365776516602421e+06,
        7.82881540820809267e+06, 1.37277607954277638e+07, 1.46452640000000000e+07,
        1.47599520000000000e+07, 1.47722400000000000e+07, 1.47760800000000000e+07
    },
    /* 14196869 */
    {
        8.70314528971027262e-64, 3.73797243916420662e-54, 6.89534209398419660e-35,
        2.96152687883942827e-25, 5.46305284013487504e-06, 4.37044227210005176e-05,
        3.49635381762981249e-04, 2.79708305378238405e-03, 2.23766644096852554e-02,
        1.79013313960757731e-01, 1.43210642741570937e+00, 1.14568460260252643e+01,
        9.16544230380726361e+01, 7.33213293977843364e+02, 5.86429285837726184e+03,
        2.34378018895664463e+04, 1.86065371296118683e+05, 1.40115124523116555e+06,
        7.35241444278085325e+06, 1.31482943822986707e+07, 1.40657970000000000e+07,
        1.41804850000000000e+07, 1.41927730000000000e+07, 1.41966130000000000e+07
    },
    /* 12204240 */
    {
        6.43150420527001539e-64, 2.76231002257211870e-54, 5.09556260386307283e-35,
        2.18852747383125011e-25, 4.03712062080382464e-06, 3.22969649663807374e-05,
        2.58375719727855038e-04, 2.06700575761862432e-03, 1.65360460478791819e-02,
        1.32288367546565450e-01, 1.05830688683857321e+00, 8.46645166853692821e+00,
        6.77313940739083478e+01, 5.41837119337156651e+02, 4.33379898342356046e+03,
        1.73228893695771148e+04, 1.37669261714004766e+05, 1.04539574996315304e+06,
        5.77381250494920462e+06, 1.11556732448609304e+07, 1.20731680000000000e+07,
        1.21878560000000000e+07, 1.22001440000000000e+07, 1.22039840000000000e+07
    },
    /* 11017633 */
    {
        5.24164589759972754e-64, 2.25126977074033947e-54, 4.15285973017258180e-35,
        1.78363967259666233e-25, 3.29023445600991739e-06, 2.63218756480426558e-05,
        2.10575005181993570e-04, 1.68460004130569592e-03, 1.34768003208293984e-02,
        1.07814401951200442e-01, 8.62515176221781310e-01, 6.90011888895440162e+00,
        5.52007897795627400e+01, 4.41595993187555280e+02, 3.53210724664455256e+03,
        1.41193736003445592e+04, 1.12282200585662198e+05, 8.56885134855132666e+05,
        4.88474748515134398e+06, 9.96908566580592468e+06, 1.08865610000000000e+07,
        1.10012490000000000e+07, 1.10135370000000000e+07, 1.10173770000000000e+07
    },
    /* 9437505 */
    {
        3.84596615253128342e-64, 1.65182988466448099e-54, 3.04708831357108469e-35,
        1.30871446548116017e-25, 2.41415208102884383e-06, 1.93132166482076944e-05,
        1.54505733184186038e-04, 1.23604586537905408e-03, 9.88836691698865254e-03,
        7.91069349491072549e-02, 6.32855454837533138e-01, 5.06284205435988710e+00,
        4.05026350373090906e+01, 3.24014590963653006e+02, 2.59170146642069403e+03,
        1.03611138831922271e+04, 8.24657129882121953e+04, 6.33553501839086646e+05,
        3.77217489083762467e+06, 8.38905836439505406e+06, 9.30643300000000000e+06,
        9.42112100000000000e+06, 9.43340900000000000e+06, 9.43724900000000000e+06
    },
    /* 8390657 */
    {
        3.04006590453258966e-64, 1.30569836376521308e-54, 2.40858835538382027e-35,
        1.03448082158999336e-25, 1.90828029650285053e-06, 1.52662423720066022e-05,
        1.22129938975015833e-04, 9.77039511733760911e-04, 7.81631608962266890e-03,
        6.25305284451466020e-02, 5.00244210163749314e-01, 4.00195256787515063e+00,
        3.20155492833050630e+01, 2.56119833714405274e+02, 2.04866682946284163e+03,
        8.19066683023702899e+03, 6.52277588009487954e+04, 5.03349352254306141e+05,
        3.08729154638380744e+06, 7.34243207002917770e+06, 8.25958500000000000e+06,
        8.37427300000000000e+06, 8.38656100000000000e+06, 8.39040100000000000e+06
    },
    /* 8388608 */
    {
        3.03858131641597245e-64, 1.30506073802432296e-54, 2.40741214349811932e-35,
        1.03397564243176815e-25, 1.90734840543853551e-06, 1.52587872434920922e-05,
        1.22070297946900538e-04, 9.76562383508887020e-04, 7.81249906382678900e-03,
        6.24999922389786536e-02, 4.99999920527147979e-01, 3.99999825159784450e+00,
        3.19999148052787241e+01, 2.55994761230423023e+02, 2.04766646333135259e+03,
        8.18666829515939844e+03, 6.51959881527814287e+04, 5.03108560814804456e+05,
        3.08599623930656072e+06, 7.34038375671866629e+06, 8.25753600000000000e+06,
        8.37222400000000000e+06, 8.38451200000000000e+06, 8.38835200000000000e+06
    },
    /* 8303633 */
    {
        2.97733261180485959e-64, 1.27875461970161355e-54, 2.35888592027094511e-35,
        1.01313378825585727e-25, 1.86890197043808392e-06, 1.49512157634889673e-05,
        1.19609726106906697e-04, 9.56877808790931330e-04, 7.65502246621082346e-03,
        6.12401794662224483e-02, 4.89921418868075276e-01, 3.91937027179577813e+00,
        3.13548931089698328e+01, 2.50834724752109139e+02, 2.00639494400443255e+03,
        8.02170245095559312e+03, 6.38851939022925071e+04, 4.93171232907488535e+05,
        3.03244066254391614e+06, 7.25543844943913259e+06, 8.17256100000000000e+06,
        8.28724900000000000e+06, 8.29953700000000000e+06, 8.30337700000000000e+06
    },
    /* 6445069 */
    {
        1.79368505410408035e-64, 7.70381864670101568e-55, 1.42110370965965099e-35,
        6.10359395721248029e-26, 1.12591435658525644e-06, 9.00731485267470771e-06,
        7.20585188209277007e-05, 5.76468150537344320e-04, 4.61174520237380304e-03,
        3.68939614957935341e-02, 2.95151684081747634e-01, 2.36121296803962988e+00,
        1.88896714490451600e+01, 1.51115304718813519e+02, 1.20879017005499418e+03,
        4.83334738231306892e+03, 3.85317788870130607e+04, 2.99814696351015300e+05,
        1.94705736284375284e+06, 5.39873796207638085e+06, 6.31399700000000000e+06,
        6.42868500000000000e+06, 6.44097300000000000e+06, 6.44481300000000000e+06
    },
    /* 5471025 */
    {
        1.29249369610449219e-64, 5.55121815505495657e-55, 1.02401900603628891e-35,
        4.39812814140828746e-26, 8.11311442279305058e-07, 6.49049153822994949e-06,
        5.19239323055521333e-05, 4.15391458426019348e-04, 3.32313166623070299e-03,
        2.65850532544887157e-02, 2.12680421213067516e-01, 1.70144306104268694e+00,
        1.36115247340070820e+01, 1.08890933607039230e+02, 8.71046562235948159e+02,
        3.48307701466327671e+03, 2.77819973005047868e+04, 2.17072810391432606e+05,
        1.45204357135021687e+06, 4.42813274199278094e+06, 5.33995300000000000e+06,
        5.45464100000000000e+06, 5.46692900000000000e+06, 5.47076900000000000e+06
    },
    /* 5461601 */
    {
        1.28804481454968919e-64, 5.53211035427330002e-55, 1.02049423892798245e-35,
        4.38298938195209473e-26, 8.08518834066487105e-07, 6.46815067252742874e-06,
        5.17452053799334513e-05, 4.13961643021164814e-04, 3.31169314299794085e-03,
        2.64935450690153597e-02, 2.11948355754160239e-01, 1.69558653896372014e+00,
        1.35646726592818290e+01, 1.08516123531166983e+02, 8.68048498988900974e+02,
        3.47109048311671313e+03, 2.76865308479067826e+04, 2.16335615528118069e+05,
        1.44753129245587252e+06, 4.41876005447029416e+06, 5.33052900000000000e+06,
        5.44521700000000000e+06, 5.45750500000000000e+06, 5.46134500000000000e+06
    },
    /* 5000000 */
    {
        1.07952085348259170e-64, 4.63650676105773906e-55, 8.55284536172561161e-36,
        3.67341911163567920e-26, 6.77626222278107512e-07, 5.42100977822143131e-06,
        4.33680782255520283e-05, 3.46944625790372989e-04, 2.77555700542421718e-03,
        2.22044559858726627e-02, 1.77635644205632687e-01, 1.42108491803878367e+00,
        1.13686642655253518e+01, 9.09483490906079339e+01, 7.27525034998112233e+02,
        2.90925341562651647e+03, 2.32109475844556837e+04, 1.81723447544976982e+05,
        1.23339477218969096e+06, 3.96033079507008009e+06, 4.86892800000000000e+06,
        4.98361600000000000e+06, 4.99590400000000000e+06, 4.99974400000000000e+06
    },
    /* 4720129 */
    {
        9.62052468491602810e-65, 4.13198388920750452e-55, 7.62216493209018785e-36,
        3.27369491080454178e-26, 6.03890121950116545e-07, 4.83112097559804736e-06,
        3.86489678045997799e-05, 3.09191742424983634e-04, 2.47353393864373520e-03,
        1.97882714607573278e-02, 1.58306168588935148e-01, 1.26644915049560436e+00,
        1.01315805181621226e+01, 8.10518322607852468e+01, 6.48362700990590611e+02,
        2.59273843912307711e+03, 2.06888306707860320e+04, 1.62171735912496864e+05,
        1.11032992554972158e+06, 3.68318454016744206e+06, 4.58905700000000000e+06,
        4.70374500000000000e+06, 4.71603300000000000e+06, 4.71987300000000000e+06
    },
    /* 4598479 */
    {
        9.13102296289999889e-65, 3.92174450046805166e-55, 7.23434171226120578e-36,
        3.10712610622505210e-26, 5.73163600862704501e-07, 4.58530880689896870e-06,
        3.66824704550210555e-05, 2.93459763629244023e-04, 2.34767810833478707e-03,
        1.87814248219317463e-02, 1.50251395711674757e-01, 1.20201098241155191e+00,
        9.61607612926632882e+00, 7.69278583186424783e+01, 6.15374823922561973e+02,
        2.46084059619524533e+03, 1.96376437319819379e+04, 1.54012240468632139e+05,
        1.05848624475353491e+06, 3.56296536146653164e+06, 4.46740700000000000e+06,
        4.58209500000000000e+06, 4.59438300000000000e+06, 4.59822300000000000e+06
    },
    /* 4514873 */
    {
        8.80201481185765059e-65, 3.78043657558362023e-55, 6.97367459966819779e-36,
        2.99517043385208020e-26, 5.52511424504064165e-07, 4.42009139602998916e-06,
        3.53607311680783604e-05, 2.82885849334287552e-04, 2.26308679401258147e-03,
        1.81046943097506359e-02, 1.44837551767604267e-01, 1.15870024067520339e+00,
        9.26959082361247866e+00, 7.41560160801382153e+01, 5.93202659021079739e+02,
        2.37218721144947949e+03, 1.89310433056085276e+04, 1.48523857053826563e+05,
        1.02344613051130890e+06, 3.48044350867863977e+06, 4.38380100000000000e+06,
        4.49848900000000000e+06, 4.51077700000000000e+06, 4.51461700000000000e+06
    },
    /* 4216423 */
    {
        7.67678466448147999e-65, 3.29715390723822894e-55, 6.08217542984550923e-36,
        2.61227445597212045e-26, 4.81879583396028819e-07, 3.85503666716617480e-06,
        3.08402933371978102e-05, 2.46722346689160995e-04, 1.97377877297431198e-03,
        1.57902301493000295e-02, 1.26321838986754365e-01, 1.01057457060471689e+00,
        8.08458752232991174e+00, 6.46761214625078082e+01, 5.17371936104562906e+02,
        2.06897994841936315e+03, 1.65139961617354602e+04, 1.29726989105084707e+05,
        9.02364612475432223e+05, 3.18665142270817654e+06, 4.08535100000000140e+06,
        4.20003900000000000e+06, 4.21232700000000000e+06, 4.21616700000000000e+06
    },
    /* 4194304 */
    {
        7.59645238547202323e-65, 3.26265145612235253e-55, 6.01852964128048457e-36,
        2.58493879793062928e-26, 4.76837044516251121e-07, 3.81469635612798540e-06,
        3.05175708488943550e-05, 2.44140566782865192e-04, 1.95312453373238325e-03,
        1.56249962359046226e-02, 1.24999967714152560e-01, 9.99999602635834095e-01,
        7.99998792014230276e+00, 6.39993337049769480e+01, 5.11958213835826825e+02,
        2.04733300825732044e+03, 1.63414126607763610e+04, 1.28383442816345399e+05,
        8.93643792677999707e+05, 3.16493330273212725e+06, 4.06323200000000186e+06,
        4.17792000000000000e+06, 4.19020800000000000e+06, 4.19404800000000000e+06
    },
    /* 4000000 */
    {
        6.90893311684184468e-65, 2.96736417870870697e-55, 5.47382075781328512e-36,
        2.35098811389739960e-26, 4.33680760573953185e-07, 3.46944608458987000e-06,
        2.77555686766066130e-05, 2.22044549405662773e-04, 1.77635639478513382e-03,
        1.42108511288302850e-02, 1.13686807145792074e-01, 9.09494336535936476e-01,
        7.27594697194879725e+00, 5.82070816774528126e+01, 4.65625032950634250e+02,
        1.86206657745167763e+03, 1.48642188911844787e+04, 1.16875662144908347e+05,
        8.18566615032645874e+05, 2.97453917313572019e+06, 3.86892800000000745e+06,
        3.98361600000000000e+06, 3.99590400000000000e+06, 3.99974400000000000e+06
    },
    /* 3981553 */
    {
        6.84535550514410596e-65, 2.94005780240874949e-55, 5.42344938429471275e-36,
        2.32935377370571273e-26, 4.29689929206757446e-07, 3.43751943365232823e-06,
        2.75001554691078272e-05, 2.20001243745771501e-04, 1.76000994951234081e-03,
        1.40800795670535245e-02, 1.12640634677535281e-01, 9.01124958451149261e-01,
        7.20899205359147022e+00, 5.76714491350714198e+01, 4.61340408064934138e+02,
        1.84493404804906459e+03, 1.47276033582964737e+04, 1.15810651261431485e+05,
        8.11583072414637543e+05, 2.95650242346870853e+06, 3.85048100000000838e+06,
        3.96516900000000000e+06, 3.97745700000000000e+06, 3.98129700000000000e+06
    },
    /* 3469497 */
    {
        5.19785334334943400e-65, 2.23246101190900781e-55, 4.11816369412201186e-36,
        1.76873783858285884e-26, 3.26274542418221493e-07, 2.61019633934462633e-06,
        2.08815707146836983e-05, 1.67052565712777593e-04, 1.33642052540193382e-03,
        1.06913641839971076e-02, 8.55309122420016277e-02, 6.84247219217605229e-01,
        5.47397271576666089e+00, 4.37914592977887409e+01, 3.50311039993776660e+02,
        1.40096122943031264e+03, 1.11865973776804603e+04, 8.81598666830800648e+04,
        6.28005802858588984e+05, 2.45925804168874957e+06, 3.33842500000041863e+06,
        3.45311300000000000e+06, 3.46540100000000000e+06, 3.46924100000000000e+06
    },
    /* 2796417 */
    {
        3.37671825984804601e-65, 1.45028944938533875e-55, 2.67531183056124863e-36,
        1.14903768188624562e-26, 2.11960040488029904e-07, 1.69568032390363953e-06,
        1.35654425911907287e-05, 1.08523540727069068e-04, 8.68188325659320029e-04,
        6.94550659521167395e-03, 5.55640521176686761e-02, 4.44512375723771114e-01,
        3.55609636786680872e+00, 2.84486021166847394e+01, 2.27578012486296558e+02,
        9.10163898031904523e+02, 7.27026311537105084e+03, 5.74622214410676097e+04,
        4.18355590119508212e+05, 1.82068469561887509e+06, 2.66534500007109111e+06,
        2.78003300000000000e+06, 2.79232100000000000e+06, 2.79616100000000000e+06
    },
    /* 2396744 */
    {
        2.48047143920984062e-65, 1.06535437100683176e-55, 1.96523194297708407e-36,
        8.44060692414111294e-27, 1.55701715756405132e-07, 1.24561372605086349e-06,
        9.96490980838274040e-06, 7.97192784655151597e-05, 6.37754227625128957e-04,
        5.10203381466552055e-03, 4.08162701118514812e-02, 3.26530134944561956e-01,
        2.61223941874139021e+00, 2.08978090582205311e+01, 1.67175670029830997e+02,
        6.68609402176202252e+02, 5.34191798810462478e+03, 4.22939678474027605e+04,
        3.11985183987068827e+05, 1.45480963913677842e+06, 2.26567200150002539e+06,
        2.38036000000000000e+06, 2.39264800000000000e+06, 2.39648800000000000e+06
    },
    /* 2098177 */
    {
        1.90096951102133711e-65, 8.16460188052975446e-56, 1.50610321353860109e-36,
        6.46866404654879610e-27, 1.19325790165487525e-07, 9.54606321323646940e-07,
        7.63685057057295992e-06, 6.10948045635459623e-05, 4.88758436441953160e-04,
        3.91006748728509653e-03, 3.12805396262469254e-02, 2.50244299599810205e-01,
        2.00195328254843341e+00, 1.60155549486522943e+01, 1.28119875775335288e+02,
        5.12416921058289972e+02, 4.09466699542457309e+03, 3.24608451232006155e+04,
        2.41825159858795436e+05, 1.19137154379842151e+06, 1.96710501463441807e+06,
        2.08179300000000000e+06, 2.09408100000000000e+06, 2.09792100000000000e+06
    },
    /* 2097152 */
    {
        1.89911264358405187e-65, 8.15662669561360700e-56, 1.50463205158771428e-36,
        6.46234545408261769e-27, 1.19209232707357876e-07, 9.53673861658609958e-07,
        7.62939089325268947e-06, 6.10351271449853099e-05, 4.88281017093565247e-04,
        3.90624813250421915e-03, 3.12499847883983932e-02, 2.49999860922525130e-01,
        1.99999777476235363e+00, 1.59999109908239898e+01, 1.27994730797902378e+02,
        5.11916432816754536e+02, 4.09066992542314756e+03, 3.24293016088167678e+04,
        2.41598381928946561e+05, 1.19048519461980974e+06, 1.96608001474931021e+06,
        2.08076800000000000e+06, 2.09305600000000000e+06, 2.09689600000000000e+06
    },
    /* 1271626 */
    {
        6.98247791753670586e-66, 2.99895143008623366e-56, 5.53208895202860154e-37,
        2.37601411275257565e-27, 4.38297242534678273e-08, 3.50637794027686185e-07,
        2.80510235221788027e-06, 2.24408188175120292e-05, 1.79526550525311456e-04,
        1.43621240325626678e-03, 1.14896991654917374e-02, 9.19175894481966127e-02,
        7.35340467538457609e-01, 5.88270786532842571e+00, 4.70606469424629239e+01,
        1.88228655326640251e+02, 1.50478955000098654e+03, 1.19720852290071271e+04,
        9.16915004100973601e+04, 5.34883907302838517e+05, 1.14056201831748476e+06,
        1.25524200000000000e+06, 1.26753000000000000e+06, 1.27137000000000000e+06
    },
    /* 1180417 */
    {
        6.01674571488324041e-66, 2.58417260737716580e-56, 4.76695707305772932e-37,
        2.04739247302188301e-27, 3.77677249682731562e-08, 3.02141799746140145e-07,
        2.41713439796623405e-06, 1.93370751835450871e-05, 1.54696601456534572e-04,
        1.23757281089540458e-03, 9.90058243872342369e-03, 7.92046564096394179e-02,
        6.33637052867698447e-01, 5.06908372476573899e+00, 4.05518571286129870e+01,
        1.62196284074367895e+02, 1.29673859731428774e+03, 1.03209111840751666e+04,
        7.92897822088251705e+04, 4.72014036787257937e+05, 1.04936108039310528e+06,
        1.16403300000000000e+06, 1.17632100000000000e+06, 1.18016100000000000e+06
    },
    /* 1048576 */
    {
        4.74777934504035996e-66, 2.03915570155726458e-56, 3.76157833530725135e-37,
        1.61558559314867667e-27, 2.98022939659853163e-08, 2.38418351727850926e-07,
        1.90734681382078342e-06, 1.52587745104367425e-05, 1.22070196075204293e-04,
        9.76561568071097354e-04, 7.81249251061440653e-03, 6.24999379118355361e-02,
        4.99999364217615039e-01, 3.99998601282519894e+00, 3.19993184525517833e+01,
        1.27989461928571330e+02, 1.02333268407003743e+03, 8.14949178914149161e+03,
        6.28885218402970859e+04, 3.85749368965992646e+05, 9.17547968415727606e+05,
        1.03219200000000000e+06, 1.04448000000000000e+06, 1.04832000000000000e+06
    },
    /* 1000000 */
    {
        4.31807995946294477e-66, 1.85460122074063535e-56, 3.42113540777918151e-37,
        1.46936646915992086e-27, 2.71050272070828090e-08, 2.16840217656635049e-07,
        1.73472174125132492e-06, 1.38777739298982540e-05, 1.11022191431995915e-04,
        8.88177530995799824e-04, 7.10542021851567982e-03, 5.68433598632794995e-02,
        4.54746758276122764e-01, 3.63796634589555756e+00, 2.91032366741829662e+01,
        1.16406170946493603e+02, 9.30743673031597268e+02, 7.41370327597679898e+03,
        5.73050521340394553e+04, 3.55463869940310891e+05, 8.68991693239986780e+05,
        9.83616000000000000e+05, 9.95904000000000000e+05, 9.99744000000000000e+05
    },
    /* 819841 */
    {
        2.90235045358949550e-66, 1.24655002796976490e-56, 2.29947893410337365e-37,
        9.87618681981492889e-28, 1.82183490689266710e-08, 1.45746792551398253e-07,
        1.16597434041021872e-06, 9.32779472321984348e-06, 7.46223577817966530e-05,
        5.96978862000799261e-04, 4.77583087977766566e-03, 3.82066459995826849e-02,
        3.05653101523800708e-01, 2.44522055793356285e+00, 1.95614921942280446e+01,
        7.82422349713714453e+01, 6.25659192034058037e+02, 4.98749101738754598e+03,
        3.87887110338050406e+04, 2.51044514778300771e+05, 6.89020788076388882e+05,
        8.03457000000000000e+05, 8.15745000000000000e+05, 8.19585000000000000e+05
    },
    /* 652545 */
    {
        1.83870213969147930e-66, 7.89716555706012712e-57, 1.45676991938802090e-37,
        6.25677916156810610e-28, 1.15417203919164522e-08, 9.23337631353239941e-08,
        7.38670105082104167e-07, 5.90936084062561679e-06, 4.72748867230070682e-05,
        3.78199093656193005e-04, 3.02559274106627921e-03, 2.42047414048012985e-02,
        1.93637897719763419e-01, 1.54910103656720777e+00, 1.23926710016034001e+01,
        4.95688012285943671e+01, 3.96409870457700265e+02, 3.16230592680692143e+03,
        2.47350036353880460e+04, 1.66739905924648541e+05, 5.22375311517453403e+05,
        6.36161000000000000e+05, 6.48449000000000000e+05, 6.52289000000000000e+05
    },
    /* 524801 */
    {
        1.18926762015466819e-66, 5.10786553475605035e-57, 9.42234882825664415e-38,
        4.04686800688662073e-28, 7.46515384231198445e-09, 5.97212307384919184e-08,
        4.77769845907681555e-07, 3.82215876724521482e-06, 3.05772701369224701e-05,
        2.44618161028867969e-04, 1.95694528397418821e-03, 1.56555619993611755e-02,
        1.25244478559222217e-01, 1.00195471259212709e+00, 8.01556628484824074e+00,
        3.20612857504726705e+01, 2.56417175606829119e+02, 2.04666733063496758e+03,
        1.60790004722360081e+04, 1.11907267203897281e+05, 3.96120253337166389e+05,
        5.08417000000000175e+05, 5.20705000000000000e+05, 5.24545000000000000e+05
    },
    /* 401857 */
    {
        6.97321585851295025e-67, 2.99497340602616845e-57, 5.52475079285309336e-38,
        2.37286239738541065e-28, 4.37715853666972486e-09, 3.50172682933560188e-08,
        2.80138146346734224e-07, 2.24110517076658296e-06, 1.79288413656660603e-05,
        1.43430730895465814e-04, 1.14744584525251574e-03, 9.17956663970264167e-03,
        7.34365252893028342e-02, 5.87491701302411684e-01, 4.69990154583516961e+00,
        1.87991664504370917e+01, 1.50360504164546711e+02, 1.20078616968526399e+03,
        9.47359440190469468e+03, 6.80414486512187577e+04, 2.76894283483037434e+05,
        3.85473000000364729e+05, 3.97761000000000000e+05, 4.01601000000000000e+05
    },
    /* 264097 */
    {
        3.01173257048041585e-67, 1.29352928945114011e-57, 2.38614037543525460e-38,
        1.02483948761595803e-28, 1.89049517446831162e-09, 1.51239613957459867e-08,
        1.20991691165935574e-07, 9.67933529325415291e-07, 7.74346823447088025e-06,
        6.19477458672908172e-05, 4.95581966395847824e-04, 3.96465569644814751e-03,
        3.17172433495926734e-02, 2.53737804589288074e-01, 2.02989333547172190e+00,
        8.11944852670449713e+00, 6.49462697901977464e+01, 5.18974356349252048e+02,
        4.11395716647436348e+03, 3.06331296576855930e+04, 1.50501181500645878e+05,
        2.47713001635784021e+05, 2.60001000000000000e+05, 2.63841000000000000e+05
    },
    /* 204800 */
    {
        1.81112697232874206e-67, 7.77873111505544409e-58, 1.43492262097629106e-38,
        6.16294572938377368e-29, 1.13686282610103304e-09, 9.09490260880802771e-09,
        7.27592208704491472e-08, 5.82073766962628089e-07, 4.65659013563926331e-06,
        3.72527210811613425e-05, 2.98021768396313955e-04, 2.38417413097999657e-03,
        1.90733920116470494e-02, 1.52587069776853601e-01, 1.22069231398262268e+00,
        4.88271104998955341e+00, 3.90573427578099199e+01, 3.12180829715757227e+02,
        2.47976660777121424e+03, 1.87590097398547114e+04, 1.01202019977427597e+05,
        1.88416061034197483e+05, 2.00704000000000000e+05, 2.04544000000000000e+05
    },
    /* 200000 */
    {
        1.72722507485033383e-67, 7.41837520931333590e-58, 1.36844868928954633e-38,
        5.87744236675266698e-29, 1.08419675147463808e-09, 8.67357401179688459e-09,
        6.93885920943610345e-08, 5.55108736753989574e-07, 4.44086989397439628e-06,
        3.55269591481138769e-05, 2.84215672949308083e-04, 2.27372536851587741e-03,
        1.81898019830974977e-02, 1.45518354102912639e-01, 1.16414288007511435e+00,
        4.65651731179381212e+00, 3.72480912910018702e+01, 2.97725899171951994e+02,
        2.36533874598445755e+03, 1.79164344745092531e+04, 9.74268023473391077e+04,
        1.83616081811024836e+05, 1.95904000000000000e+05, 1.99744000000000000e+05
    },
    /* 102774 */
    {
        4.56093001325520124e-68, 1.95890452462759358e-58, 3.61354104306368883e-39,
        1.55200406027122712e-29, 2.86294217011813689e-10, 2.29035373609447973e-09,
        1.83228298887539320e-08, 1.46582639109909510e-07, 1.17266111287147088e-06,
        9.38128890247224633e-06, 7.50503111878085755e-05, 6.00402487456427967e-04,
        4.80321976870481948e-03, 3.84257497690574379e-02, 3.07405461796057433e-01,
        1.22961449148191515e+00, 9.83636673154418517e+00, 7.86557982750542379e+01,
        6.27004472923565913e+02, 4.87594964501844061e+03, 3.15399697939153557e+04,
        8.64209088311287778e+04, 9.86780000000517612e+04, 1.02518000000000000e+05
    },
    /* 100000 */
    {
        4.31804109670444684e-68, 1.85458452931295726e-58, 3.42110461752972125e-39,
        1.46935324484847411e-29, 2.71047832615944429e-10, 2.16838266092752773e-09,
        1.73470612874184682e-08, 1.38776490299235408e-07, 1.11021192238669322e-06,
        8.88169537863339005e-06, 7.10535629996172078e-05, 5.68428502112142500e-04,
        4.54742789627025652e-03, 3.63794154500428554e-02, 2.91034829513422078e-01,
        1.16413254204269756e+00, 9.31255441700961661e+00, 7.44680683686491989e+01,
        5.93679123947771245e+02, 4.62029194177156842e+03, 3.00458780821981018e+04,
        8.36526113620496035e+04, 9.59040000001018925e+04, 9.97440000000000000e+04
    },
    /* 77163 */
    {
        2.57100957639565332e-68, 1.10424020483221446e-58, 2.03696364544404734e-39,
        8.74869224032312274e-30, 1.61384886736889072e-10, 1.29107909389509996e-09,
        1.03286327511599940e-08, 8.26290620092283361e-08, 6.61032496070523366e-07,
        5.28825996835277598e-06, 4.23060797332919000e-05, 3.38448637000395610e-04,
        2.70758904058303156e-03, 2.16607087777761914e-02, 1.73285443221624619e-01,
        6.93138659749164665e-01, 5.54487683849644686e+00, 4.43441427884696751e+01,
        3.53803490158028808e+02, 2.77073535802625520e+03, 1.88416306375775675e+04,
        6.09265638602578401e+04, 7.30670000269061129e+04, 7.69070000000000000e+04
    },
    /* 50643 */
    {
        1.10744301397987420e-68, 4.75643152722723048e-59, 8.77406750868841857e-40,
        3.76843330027129536e-30, 6.95153246489491803e-11, 5.56122597191589927e-10,
        4.44898077753249111e-09, 3.55918462202453374e-08, 2.84734769761028846e-07,
        2.27787815802846539e-06, 1.82230252604027392e-05, 1.45784201838422859e-04,
        1.16627359904024406e-03, 9.33018778962516233e-03, 7.46414381444532316e-02,
        2.98564872499666734e-01, 2.38845326899687205e+00, 1.91034214287983026e+01,
        1.52558668462478067e+02, 1.20347485170217601e+03, 8.63630719761463843e+03,
        3.50036860916488222e+04, 4.65470174614963616e+04, 5.03870000000000000e+04
    },
    /* 16388 */
    {
        1.15962220635645385e-69, 4.98053945201633260e-60, 9.18747366203589011e-41,
        3.94598989113055048e-31, 7.27906656391302647e-12, 5.82325325113040825e-11,
        4.65860260090425009e-10, 3.72688208072290542e-09, 2.98150566457516053e-08,
        2.38520453163987852e-07, 1.90816362518230592e-06, 1.52653089931642262e-05,
        1.22122471414483764e-04, 9.76979737342747187e-04, 7.81583572446263239e-03,
        3.12633130791898986e-02, 2.50104278189982043e-01, 2.00069174169475472e+00,
        1.59964193504148877e+01, 1.27390257914498051e+02, 9.83048913714464220e+02,
        6.02968148160985038e+03, 1.23669110286182531e+04, 1.61320000000000000e+04
    },
    /* 6 */
    {
        1.29542528326416669e-76, 5.56380922603113208e-67, 1.02634164867540313e-47,
        4.40810381558357815e-38, 8.13151629364128326e-19, 6.50521303491302660e-18,
        5.20417042793042128e-17, 4.16333634234433703e-16, 3.33066907387546883e-15,
        2.66453525910036939e-14, 2.13162820728026017e-13, 1.70530256582398195e-12,
        1.36424205265773800e-11, 1.09139364211692597e-10, 8.73114913634248473e-10,
        3.49245965372384226e-09, 2.79396771690754164e-08, 2.23517413466822798e-07,
        1.78813905904464986e-06, 1.43050965562127250e-05, 1.14439753822193055e-04,
        9.15452841354552627e-04, 3.66091750036190520e-03, 5.82894668923472636e-02
    },
};

static void printdouble( const int width, const double value ) {
    if (width < 10) {
        printf("%.*s|", width - 1, "----------");
    } else if (value == 0.0) {
        printf(" %*.3f |", width - 2, value);
    } else if (value < 1.0e-100) {
        printf(" %.*e |", width - 9, value);
    } else if (value < 1.0e-6) {
        printf(" %.*e  |", width - 9, value);
    } else if (value < 1.0) {
        printf("  %*.*f |", width - 3, width - 5, value);
    } else if (value < 1.0e6) {
        printf(" %*.3f |", width - 2, value);
    } else {
        printf(" %*.1f   |", width - 4, value);
    }
}

void ReportCollisionEstimates( void ) {
    const int keys[] = {
        149633745, 86536545, 75498113, 56050289, 49925029, 44251425,
         43691201, 33558529, 33554432, 26977161, 22370049, 18877441,
         18616785, 17676661, 16777216, 16777214, 15082603, 14986273,
         14776336, 14196869, 12204240, 11017633,  9437505,  8390657,
          8388608,  8303633,  6445069,  5471025,  5461601,  5000000,
          4720129,  4598479,  4514873,  4216423,  4194304,  4000000,
          3981553,  3469497,  2796417,  2396744,  2098177,  2097152,
          1271626,  1180417,  1048576,  1000000,   819841,   652545,
           524801,   401857,   264097,   204800,   200000,   102774,
           100000,    77163,    50643,    16388,        6
    };
    const int bits[] = {
        256, 224, 160, 128, 64, 61, 58, 55, 52, 49, 46, 43,
         40,  37,  34,  32, 29, 26, 23, 20, 17, 14, 12,  8
    };

    printf("EstimateNbCollisions:\n");
    printf(
            "  # keys   : bits|    True answer     |     A: _cur()      |     B: _prev()     |   C: _prevprev()   |    Error A   |    Error B   |    Error C   |\n");
    printf(
            "---------------------------------------------------------------------------------------------------------------------------------------------------\n");
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        const int key = keys[i];
        for (size_t j = 0; j < sizeof(bits) / sizeof(bits[0]); j++) {
            const int bit = bits[j];
            printf(" %9d : %3d |", key, bit);
            printdouble(20, realcoll[i][j]);
            for (int k = 0; k < COLLISION_ESTIMATORS; k++) {
                printdouble(20, EstimateNbCollisionsCand(key, bit, k));
            }
            for (int k = 0; k < COLLISION_ESTIMATORS; k++) {
                double delta    = EstimateNbCollisionsCand(key, bit, k) - realcoll[i][j];
                double deltapct = delta / realcoll[i][j] * 100.0;
                if (deltapct > 9999.999) {
                    deltapct = 9999.999;
                }
                printf(" %+11.5f%% |", deltapct);
            }
            printf("\n");
        }
    }
}

//-----------------------------------------------------------------------------
// The number of bins expected to be empty
double GetMissingHashesExpected( size_t nbH, int nbBits ) {
    double pE = exp((double)nbH * log1p(-exp2(-nbBits)));

    return ldexp(pE, nbBits);
}

//-----------------------------------------------------------------------------
// p-value formulas for various distributions, and related utility functions

/*
 * Compute the lowest number of hash bits (n) such that there are
 * fewer than (2**n)*log(2**n) hashes, for a given hash count.
 *
 * This may validly return a value exceeding the number of hash bits
 * that exist for the hash being tested!
 */
int GetNLogNBound( unsigned nbH ) {
    int nbHBits;

    for (nbHBits = 1; nbHBits <= 255; nbHBits++) {
        if (nbH < (log(2.0) * nbHBits * exp2(nbHBits))) {
            break;
        }
    }
    return nbHBits - 1;
}

/*
 * What SMHasher3 frequently reports on is the worst result across some
 * number of tests. If we compute the CDF/p-value of each test and
 * consider only those, then the tests become statistically identical,
 * since CDFs are continuous ~Uniform(0,1). Assuming sufficient
 * independence also, the CDF of the maximum of N values is equal to
 * the CDF of a single value raised to the Nth power, so we can just
 * raise the p-value itself to the power of the number of tests.
 *
 * The p-values in SMHasher3 are usually stored in variables as 1.0-p,
 * so that p-values very close to 1 (which are in the vicinity of
 * failing results) can be kept as accurate as possible in the face of
 * floating-point representation realities. This means we can't just
 * use pow(), but this alternate formulation does the same thing for
 * values in 1-p space.
 */
double ScalePValue( double p_value, unsigned testcount ) {
    return -expm1(log1p(-p_value) * testcount);
}

/*
 * This is exactly the same as ScalePValue, but for 2**N tests.
 */
double ScalePValue2N( double p_value, int testbits ) {
    return -expm1(ldexp(log1p(-p_value), testbits));
}

/*
 * SMHasher3 reports p-values by displaying how many powers of 2 the
 * improbability is. This is the nicest way of summarizing the p-value
 * I've found. And since the really, truly most important result of
 * these tests is "does a hash pass or fail", and perhaps how close to
 * the line it is, the precise p-value is generally better left
 * unprinted.
 *
 * This is not a percentage or a ratio, and there is no standard unit
 * of log probability that I can find, so I've semi-arbitrarily chosen
 * the caret (^) to display these values, as that can indicate
 * exponentiation, and the p-value is no less than 1/(2**logp_value).
 */
int GetLog2PValue( double p_value ) {
    return (log2(p_value) <= -99.0) ? 99 : -ceil(log2(p_value));
}

/*
 * Return (1.0 - p) for the given random standard normal variate.
 */
double GetStdNormalPValue( const double variable ) {
    return erfc(variable * M_SQRT1_2) * 0.5;
}

/*
 * A helper function for the Peizer and Pratt approximation below.
 */
static double GFunc_PeizerPratt( const double x ) {
    if (x <= 0.0) {
        if (x == 0.0) {
            return 1.0;
        } else {
            return NAN;
        }
    }
    if (x >= 1.0) {
        if (x == 1.0) {
            return 0.0;
        } else {
            return -GFunc_PeizerPratt(1.0 / x);
        }
    }
    return (1.0 - x * x + 2 * x * log(x)) / ((1.0 - x) * (1.0 - x));
}

/*
 * Assume that m balls are i.i.d. randomly across n bins, with m >=
 * n*log(n). Then, the number of balls in any given bin tends to have
 * about log(n) balls and follows a binomial distribution. That is, if
 * Xi is the number of balls in bin i, then Xi ~ Bin(m, 1/n).
 *
 * But we aren't reporting on Xi, we are reporting on Xm = max{i=1..n;
 * Xi}. All the Xi are from identical distributions, and are actually
 * sufficiently independent in the random case that we can use the
 * usual {CDF(Xm)} = {CDF(Xi)}**n.
 *
 * The best non-iterative approximation to the Binomial distribution
 * CDF that I've found is the Peizer and Pratt transformation into a
 * standard normal distribution. We use that to find a p-value for Xi.
 * NB: "best" here is akin to "closest to p-values obtained through
 * simulation for Xm in the extreme tails", and not "least error
 * compared to actual overall binomial distribution values".
 *
 * Thanks to the paper:
 *   "APPROXIMATIONS TO THE BINOMIAL", by MYRTLE ANNA BRUCE
 *   https://core.ac.uk/download/pdf/33362622.pdf
 */
double EstimateMaxCollPValue( const unsigned long nbH, const int nbBits, const int maxColl ) {
    const double s     = (double)maxColl + 0.5;
    const double n     = nbH;
    const double t     = n - s;
    const double p     = exp2(-nbBits);
    const double q     = 1.0 - p;

    const double d1    = s + 1.0 / 6.0 - p * (n + 1.0 / 3.0);
    const double d2    = d1 + 0.02 * (q / (s + 0.5) - p / (t + 0.5) + (q - 0.5) / (n + 1));

    const double num   = 1.0 + q * GFunc_PeizerPratt(s / (n * p)) + p * GFunc_PeizerPratt(t / (n * q));
    const double denom = (n + 1.0 / 6.0) * p * q;
    const double z2    = d2 * sqrt(num / denom);

    // (1.0 - p) for one hash bin
    double p_value = GetStdNormalPValue(z2);
    // fprintf(stderr, "Pr(Xi > %ld; %d, %d) ~= 1.0 - N(%f)\n", nbH, nbBits, maxColl, z2);

    // (1.0 - p) across all 2**nbBits hash bins
    double pm_value = ScalePValue2N(p_value, nbBits);

    // fprintf(stderr,"Pr(Xm > %ld; %d, %d) ~= 1.0-((1.0-%e)**(2**n)) == %.12f\n", nbH, nbBits, maxColl, p_value,
    // pm_value, pm_value);

    return pm_value;
}

/*
 * This is the same Peizer and Pratt transformation as above, except
 * hardcoded to p = 0.5, and this returns the two-tailed value.
 */
double GetCoinflipBinomialPValue( const unsigned long coinflips, const unsigned long delta ) {
    // assert(coinflips >= 2 * delta);
    const double n       = coinflips;
    const double two_s   = coinflips + 2 * delta;
    const double two_t   = coinflips - 2 * delta;

    const double d2      = delta + 0.02 * (1.0 / (two_s + 1.0) - 1.0 / (two_t + 1.0));

    const double num     = 2.0 + GFunc_PeizerPratt(two_s / n) + GFunc_PeizerPratt(two_t / n);
    const double denom   = n / 2.0 + 1.0 / 12.0;
    const double z2      = d2  * sqrt(num                / denom);

    const double p_value = 2.0 * GetStdNormalPValue(z2);

    // printf("\nPr(Xi > %ld; %ld, 0.5) ~= 1.0 - N(%f) ~= %e (Cbound %e)\n",
    //        (unsigned long)(two_s / 2.0), coinflips, z2, p_value, 2.0 * exp(-(double)delta * 2.0 / n * delta));

    return p_value;
}

/*
 * For estimating the maximum value, we could get the normal value
 * with p=0.5 and back-convert, but the C standard library doesn't
 * have an inverse erf(), and I don't want to add an external
 * dependency just for this.
 *
 * This function computes an estimate of an upper bound on the number
 * of balls in the most-occupied bin. This set of formulas comes from:
 *
 * '"Balls into Bins" - A Simple and Tight Analysis', by
 *   Martin Raab and Angelika Steger
 *   http://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.399.3974
 *
 * The adjustments for calculating the value that corresponds to the
 * 50th-percentile for a given nbBits were computed via linear
 * regression from Monte Carlo experiments by fwojcik [N ~= 80,000,000].
 */
double EstimateMaxCollisions( const unsigned long nbH, const int nbBits ) {
    double alpha = -expm1(-0.128775055 * nbBits - 0.759110989);
    double m     = (double)nbH - 16;
    double n     = exp2(nbBits);
    double logn  = nbBits * log(2);

    return (m / n) + alpha * sqrt(2.0 * (m / n) * logn);
}

/*
 * While computing p-values for Poisson distributions is generally
 * straightforward, it is also iterative and can require special care
 * due to floating-point considerations, especially in the long tail
 * of the distribution. Instead, this computes an upper bound on the
 * p-value using a single calculation. This is taken from:
 *
 * "Sharp Bounds on Tail Probabilities for Poisson Random Variables", by
 *   Peter Harremoës
 *   https://helda.helsinki.fi/bitstream/handle/10138/229679/witmse_proc_17.pdf
 *
 * Similar to other places in SMHasher3, this returns 1.0-p, so the
 * closer to 0 the worse the result. This also doesn't bother
 * computing real p-values for lower-than-expected collision counts,
 * since that is never a failure condition.
 */
double GetBoundedPoissonPValue( const double expected, const uint64_t collisions ) {
    if (collisions < expected) {
        return 1.0;
    }
    double x            = (double)collisions - 0.5;
    double g_over_root2 = sqrt(x * log(x / expected) + expected - x);
    double p_lbound     = erfc(g_over_root2) / 2.0;
    return p_lbound;
}

//-----------------------------------------------------------------------------
// Distribution score

// Compute the sum of squares of a series of integer values
// NB: bincount must be a non-zero multiple of 64!
template <typename T>
uint64_t sumSquares( const T * bins, size_t bincount ) {
    static_assert(std::is_integral<T>::value, "sumSquares only uses integer data");
    uint64_t sumsq = 0;

    // To allow the compiler to vectorize this loop
    assume(bincount % 64 == 0);
    assume(bincount > 0);
    for (size_t i = 0; i < bincount; i++) {
        sumsq += (uint64_t)bins[i] * bins[i];
    }

    return sumsq;
}

#define SUMSQ_TYPES uint8_t, uint32_t
INSTANTIATE(sumSquares, SUMSQ_TYPES);

// Compute the sum of squares of a series of integer values
// NB: bincount can be any value
template <typename T>
uint64_t sumSquaresBasic( const T * bins, size_t bincount ) {
    static_assert(std::is_integral<T>::value, "sumSquares only uses integer data");
    uint64_t sumsq = 0;

    for (size_t i = 0; i < bincount; i++) {
        sumsq += (uint64_t)bins[i] * bins[i];
    }

    return sumsq;
}

#define SUMSQBASIC_TYPES uint32_t
INSTANTIATE(sumSquaresBasic, SUMSQBASIC_TYPES);

// Randomly distributing m balls into n bins is a well-studied
// statistical model, relevant to a wide range of real world
// problems. It is exactly analogous to hashing k keys into n
// bins. The count of balls in a bin approximately follows a Poisson
// distribution, if the number of balls and bins are large enough.
//
// The previous version of this test was intended to compare the total
// set of key counts in each hash bin against a truly random Poisson
// distribution. It computed the Root Mean Square (RMS) of the actual
// key counts, and then computed how many bins would be needed to get
// that same RMS value assuming a random hash, finally comparing the
// two to come up with a single score value. For this score, less than
// 0 meant flatter/more even than random, 0.000 meant exactly random,
// and 1.000 (percent, as it happens) was considered a failure.
//
// This was very clever, but one of the key goals of the test turns
// out not to have been met. The previous comments said: "This makes
// for a nice uniform way to rate a distribution that isn't dependent
// on the number of bins or the number of keys". Unfortunately, it
// turns out that while a score of 0 did hold the desired meaning
// across all bin/key counts, the _variance_ of the score _was_
// dependent on the number of bins. This means that higher bin counts
// typically had higher scores from this test, even if the
// distributions were closer to the random ideal. And since only the
// highest score gets reported on, this also distorted which bit
// widths were reported as having the highest bias.
//
// I tried applying some corrections to the score with the goal of
// keeping this test. Multiplying the score by (keycount/bincount)
// comes close to having it be independent of the test sizes, but not
// close enough. The resulting score is very accurate when the bin
// counts are close to random, but it under-reports failures, and the
// worse the failure the more inaccurate the adjusted score was. A
// further correction to the score, to accurately report failures,
// seems to require bin- and hash-dependent constants for both
// score**2 and score**3 terms at the least.
//
// Rather than go down that complicated route, I changed this test to
// compute Root Mean Square Error (RMSE) across the bin counts. A
// truly random Poisson distribution will have an expected MSE of
// lambda (keycount/bincount), and multiplying the ratio of
// actual/expected by a factor of sqrt(2.0 * bincount) makes the score
// be a standard normal variable (E[score] = 0, Var[score] = 1)
// independent of bincount and keycount.
//
// The way the RMSE is calculated is a little odd. One term in what we want
// is sumN{(Bi - lambda)**2}. But Bi values are integers, and doing all
// that math in a loop is expensive. So that formula gets rearranged:
//
// sumN{(Bi - lambda)**2}
// sumN{(Bi**2 - 2 * Bi * lambda + lambda**2)}
// sumN{(Bi**2)} - 2 * sumN{(Bi * lamba)} + sumN{(lambda**2)}
// sumN{(Bi**2)} - 2 * lambda * sumN{(Bi)} + N * (lambda**2)
// sumN{(Bi**2)} - 2 * lambda * M + N * (lambda**2)
// sumN{(Bi**2)} - 2 * M / N * M + N * M**2 / N**2
// sumN{(Bi**2)} - 2 * M**2 / N + M**2 / N
// sumN{(Bi**2)} - M**2 / N
// sumN{(Bi**2)} - M * lambda
//
// This also allows the sum of the square of all the terms to be computed
// externally from this function, perhaps by sumSquares() defined above.
//
// From there, the formula for the score is:
//
// RMSE    = sqrt((sumN{(Bi**2)} - M * lambda) / N)
// score   = (RMSE/sqrt(lambda) - 1.0) * sqrt(2.0 * N)
//
// but the first part of the score formula gets further rearranged, to
// minimize the number of math operations:
//
// sqrt((sumN{(Bi**2)} - M * lambda) / N) / sqrt(lambda)
// sqrt((sumN{(Bi**2)} - M * lambda) / N) / sqrt(M / N)
// sqrt(((sumN{(Bi**2)} - M * lambda) / N) / (M / N))
// sqrt(((sumN{(Bi**2)} - M * lambda) / N) * (N / M))
// sqrt((sumN{(Bi**2)} - M * lambda) / M)
// sqrt((sumN{(Bi**2)} / M - lambda))
double calcScore( const uint64_t sumsq, const int bincount, const int keycount ) {
    const double n      = bincount;
    const double m      = keycount;
    const double lambda = m / n;

    double rmse_ratio   = sqrt(((double)sumsq) / m - lambda);
    double score        = (rmse_ratio - 1.0) * sqrt(2.0 * n);

    return score;
}

// Convert the score from calcScore back into (rmse/sqrt(lambda) -
// 1.0), to show the user something like the previous report.
double normalizeScore( double score, int scorewidth ) {
    if (score <= 0) {
        return 0.0;
    }

    double result = score / sqrt(2.0 * scorewidth);

    // Never return a result higher than 999.9, as a precise value
    // would be visually cluttered and not really meaningful.
    return std::min(result, 999.9);
}

//----------------------------------------------------------------------------
// Return the chi-square value for a chi-square test of independence on a 2x2
// contingency matrix. Note that there is only one (1) degree of freedom here.
//
// This formulation works better than the normal chi-square test, and much better
// than raw bias calculations, when the individual bits might themselves be biased
// (e.g. bit X not being a 50/50 coin flip might throw off the result for
// independence between bits X and Y).
//
// While I don't know that this is the very best test for this, it performs very well
// in my tests. Fisher's exact test can't be used because the row and column sums
// (aka the margin values) aren't fixed. The same is true of Barnard's exact test and
// Boschloo's test. We might be able to get a p-value from the binomial approximation
// above, since we know these are being compared against Bernoulli trials with p =
// 0.5 exactly. That sounds complicated, tho. :) We might also be able to use a
// G-test for mutual information.

double ChiSqIndepValue( const uint32_t * boxes, size_t total ) {
    const double   N         = (double)total;
    const uint64_t colsum[2] = { boxes[0] + boxes[1], boxes[2] + boxes[3] };
    const uint64_t rowsum[2] = { boxes[0] + boxes[2], boxes[1] + boxes[3] };
    const double   expect[4] = {
        colsum[0] * rowsum[0] / N,
        colsum[0] * rowsum[1] / N,
        colsum[1] * rowsum[0] / N,
        colsum[1] * rowsum[1] / N,
    };
    double chisq = 0.0;

    for (int i = 0; i < 4; i++) {
        if (expect[i] < 10.0) {
            // printf("chisq of %d %d %d %d is INF, chi is INF, cdf is INF 99", boxes[0], boxes[1], boxes[2], boxes[3]);
            return total;
        }
        chisq += ((double)boxes[i] - expect[i]) * ((double)boxes[i] - expect[i]) / expect[i];
    }
#if 0
    printf("chisq of %d %d %d %d vs. %d %d %d %d is %f, chi is %f, cdf is %e %2d", boxes[0],
            boxes[1], boxes[2], boxes[3], (int)expect[0], (int)expect[1], (int)expect[2],
            (int)expect[3], chisq, sqrt(chisq), cdf, GetLog2PValue(cdf));
#endif
    return chisq;
}

double ChiSqPValue( double chisq, uint64_t dof ) {
    if (dof == 1) {
        // Chi-sq CDF for 1 degree-of-freedom is P(x) = 1 - 2 * Q(sqrt(x)) where
        // Q(y) = 1 - StandardNormalCDF(y).
        //
        // Since we want this result in our usual "1.0 - p" format, and we
        // already have a function for 1 - Q(y), this is easy to compute.
        return 2.0 * GetStdNormalPValue(sqrt(chisq));
    }

    double ddof = (double)dof;

    if (chisq <= ddof) {
        return 1.0;
    }

    return exp(-ddof / 2.0 * (chisq / ddof - 1.0 - log(chisq / ddof)));
}
