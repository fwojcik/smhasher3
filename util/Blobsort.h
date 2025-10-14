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
 */

#include <numeric>

static constexpr ssize_t SMALLSORT_CUTOFF = 1024;

//-----------------------------------------------------------------------------
// Blob sorting routines

// This moves the smallest element in [begin, end) to be the first
// element. It is one step in insertionsort, and it is used to ensure there
// is a sentinel at the beginning that is less than or equal to every other
// element, so that the array bounds don't need to be checked inside the
// loop. This makes flagsort() (and thus blobsort()) unstable sorts,
// because the std::iter_swap() below can move the first element past some
// other element that it equals. This could be rectified by using
// std::rotate() at some runtime cost.
template <bool track_idxs, typename T>
static void movemin( T * begin, T * end, hidx_t * idxs ) {
    T * min = begin;

    for (T * i = begin + 1; i != end; i++) {
        if (*i < *min) {
            min = i;
        }
    }
    if (track_idxs) {
        std::iter_swap(idxs, idxs + (min - begin));
    }
    std::iter_swap(begin, min);
}

// When this is called with unguarded==true, begin-1 must be guaranteed to
// exist and to be less than all elements in [begin, end). This can be done
// via movemin(), or with the magic knowledge (that comes from sorting a
// larger array by sections) there are more elements before begin that are
// smaller than any element in [begin, end).
//
// When this is called with unlimited == false, we estimate the maximum
// number of moves that should be seen by the time we're halfway done (as a
// function of _work_, not elements), if insertionsort is likely to be
// faster than radixsort. If we hit this number and we're not halfway done,
// give up so the caller can fallback to radixsort (or possibly some other
// sort). This number depends on the length of the type being sorted, and
// was determined empirically.
//
// Since work for non-trivial cases of insertionsort goes as the square of
// the number of elements, half the work should be done when sqrt(1/2) =~
// .7071 of the elements are completed.
template <bool unlimited, bool unguarded, bool track_idxs, typename T>
static bool insertionsort( T * begin, T * end, hidx_t * idxs ) {
    const T * const  midpoint = begin  + (end - begin) * 7 / 10;
    const size_t     movlimit = T::len * (end - begin) / 2;
    size_t           movcount = 0;
    hidx_t           v;

    for (T * i = begin + 1; i != end; i++) {
        T * node = i;
        T * next = i - 1;
        T   val  = std::move(*node);
        if (track_idxs) {
            v = std::move(*(idxs + (node - begin)));
        }
        while ((unguarded || (next >= begin)) && (val < *next)) {
            if (track_idxs) {
                *(idxs + (node - begin)) = std::move(*(idxs + (next - begin)));
            }
            *node = std::move(*next);
            node  = next--;
            movcount++;
        }
        if (track_idxs) {
            *(idxs + (node - begin)) = std::move(v);
        }
        *node = std::move(val);
        if (!unlimited) {
            if (unlikely(movcount > movlimit)) {
                if (i < midpoint) {
                    return false;
                }
                movcount = 0;
            }
        }
    }

    return true;
}

// Sort entry point for small blocks of items, where "small" is defined via
// SMALLSORT_CUTOFF, the value of which is obtained by benchmarking the
// resulting code.
//
// The original intent was to have smallsort incorporate a series of
// routines based on sorting networks for very small (<= ~24 entries)
// blocks, but that ended up not being faster no matter the cutoff.
template <bool track_idxs, typename T>
static void smallsort( T * begin, T * end, hidx_t * idxs, bool guarded = true ) {
    assume((end - begin) > 1);
    if (guarded) {
        movemin<track_idxs>(begin++, end, idxs++);
    }
    insertionsort<true, true, track_idxs>(begin, end, idxs);
}

//-----------------------------------------------------------------------------
static const uint32_t RADIX_BITS = 8;
static const uint32_t RADIX_SIZE = (uint32_t)1 << RADIX_BITS;
static const uint32_t RADIX_MASK = RADIX_SIZE - 1;

template <bool track_idxs, typename T>
static void radixsort( T * begin, T * end, hidx_t * idxs ) {
    constexpr uint32_t RADIX_LEVELS = T::len;
    const size_t       count        = end - begin;

    uint32_t freqs[RADIX_SIZE][RADIX_LEVELS] = {};
    T *      last = begin + count - 1;

    // Record byte frequencies in each position over all items except
    // the last one.
    assume(begin < last);
    for (T * ptr = begin; ptr < last; ptr++) {
        prefetch(ptr + 64);
        for (uint32_t pass = 0; pass < RADIX_LEVELS; pass++) {
            uint8_t value = (*ptr)[pass];
            ++freqs[value][pass];
        }
    }
    // Process the last item separately, so that we can record which
    // passes (if any) would do no reordering of items, and which can
    // therefore be skipped entirely.
    uint32_t trivial_passes = 0;
#pragma GCC unroll 1
    for (uint32_t pass = 0; pass < RADIX_LEVELS; pass++) {
        uint8_t value = (*last)[pass];
        if (unlikely(++freqs[value][pass] == count)) {
            trivial_passes |= 1UL << pass;
        }
    }

    std::unique_ptr<T[]> queue_area( new T[count] );
    T * from = begin;
    T * to   = queue_area.get();

    std::unique_ptr<uint32_t[]> idxs_area( new uint32_t[track_idxs ? count : 1] );
    uint32_t * idxfrom = idxs;
    uint32_t * idxto   = idxs_area.get();

    for (uint32_t pass = 0; pass < RADIX_LEVELS; pass++) {
        // If this pass would do nothing, just skip it.
        if (unlikely(trivial_passes & (1UL << pass))) {
            continue;
        }

        // Array of pointers to the current position in each queue,
        // pre-arranged based on the known final sizes of each queue. This
        // way all the entries end up contiguous with no gaps.
        T * queue_ptrs[RADIX_SIZE];
        T * next = to;
#pragma GCC unroll 8
        for (size_t i = 0; i < RADIX_SIZE; i++) {
            queue_ptrs[i] = next;
            next += freqs[i][pass];
        }

        // Copy each element into its queue based on the current byte.
#pragma GCC unroll 4
        for (size_t i = 0; i < count; i++) {
            uint8_t index = from[i][pass];
            if (track_idxs) {
                *(idxto + (queue_ptrs[index] - to)) = std::move(idxfrom[i]);
            }
            *queue_ptrs[index]++ = std::move(from[i]);
            // These prefetch() calls make a small but significant
            // difference (e.g. 41.1ms -> 35.9ms).
            prefetch(&from[i + 64]);
            prefetch(queue_ptrs[index]);
        }

        if (track_idxs) {
            std::swap(idxfrom, idxto);
        }
        std::swap(from, to);
    }

    // Because the swap always happens in the above loop, the "from"
    // area has the sorted payload. If that's not the original array,
    // then do a final copy.
    if (unlikely(from != begin)) {
        assume(count >= SMALLSORT_CUTOFF);
        if (track_idxs) {
            std::copy(idxfrom, idxfrom + count, idxs);
        }
        std::copy(from, from + count, begin);
    }
}

//-----------------------------------------------------------------------------
// This is an in-place MSB radix sort that recursively sorts each
// block, sometimes known as an "American Flag Sort". Testing shows
// that performance increases by devolving to alternate sorts once we get
// down to small block sizes. Both 40 and 60 items are best on my
// system, but there could be a better value for the general case.
template <bool track_idxs, typename T>
static void flagsort( T * begin, T * end, hidx_t * idxs, T * base, int digit ) {
    const int    DIGITS = T::len;
    const size_t count  = end - begin;

    assume(digit >= 0     );
    assume(digit <  DIGITS);

    // Each pass must compute its own frequency table, because the
    // counts depend on all previous bytes, since each pass operates on
    // a successively smaller subset of the total list to sort.
    uint32_t freqs[RADIX_SIZE] = {};
    T *      ptr = begin;
    do {
        ++freqs[(*ptr)[digit]];
    } while (++ptr < (end - 1));
    // As in radix sort, if this pass would do no rearrangement, then
    // there's no need to iterate over every item. If there are no more
    // passes, then we're just done. Otherwise, hitting this condition in
    // real-world data is a little suspicious. This is only likely to hit
    // in oddball cases.
    //
    // Currently, if this case is hit then we first try devolving into
    // insertionsort with a heuristic maximum number of item movements. In
    // cases where every item is identical (e.g. donothing128), or where
    // the items are nearly sorted, or where there are not too many items,
    // insertionsort will have enough leeway to finish sorting this
    // section. That won't be true in the more degenerate cases, because
    // insertionsort has dreadful worst-case performance, and so we'll
    // further fallback to radixsort.
    //
    // smallsort() isn't used here because these blocks must be large.
    if (unlikely(++freqs[(*ptr)[digit]] == count)) {
        if (digit != 0) {
            assume((end - begin) > SMALLSORT_CUTOFF);
            // Start with a limited version of insertionsort
            if (begin == base) {
                if (insertionsort<false, false, track_idxs>(begin, end, idxs)) {
                    return;
                }
            } else {
                if (insertionsort<false, true, track_idxs>(begin, end, idxs)) {
                    return;
                }
            }
            // If that takes too much time, fallback further to radixsort
            radixsort<track_idxs>(begin, end, idxs);
        }
        return;
    }

    T * block_ptrs[RADIX_SIZE];
    ptr = begin;
    for (size_t i = 0; i < RADIX_SIZE; i++) {
        block_ptrs[i] = ptr;
        ptr += freqs[i];
    }

    // Move all values into their correct block.
    ptr = begin;
    T *     nxt      = begin + freqs[0];
    uint8_t curblock = 0;
    while (true) {
        if (expectp((ptr >= nxt), 0.0944)) {
            if (++curblock >= (RADIX_SIZE - 1)) {
                break;
            }
            nxt += freqs[curblock];
            continue;
        }
        uint8_t value = (*ptr)[digit];
        if (unpredictable(value == curblock)) { // p ~= 0.501155
            ptr++;
            continue;
        }
        // assert(block_ptrs[value] < end);
        if (track_idxs) {
            std::iter_swap(idxs + (ptr - begin), idxs + (block_ptrs[value] - begin));
        }
        std::iter_swap(ptr, block_ptrs[value]++);
    }

    if (digit == 0) {
        return;
    }

    // Sort each block by the next less-significant byte, or by
    // smallsort if there are only a few entries in the block.
    ptr = begin;
    for (size_t i = 0; i < RADIX_SIZE; i++) {
        if (expectp((freqs[i] > SMALLSORT_CUTOFF), 0.00390611)) {
            flagsort<track_idxs>(ptr, ptr + freqs[i], idxs, base, digit - 1);
        } else if (expectp((freqs[i] > 1), 0.3847)) {
            smallsort<track_idxs>(ptr, ptr + freqs[i], idxs, (ptr == base));
        }
        ptr += freqs[i];
        if (track_idxs) {
            idxs += freqs[i];
        }
    }
}

//-----------------------------------------------------------------------------
// For 32-bit values, radix sorting is a clear win on my system, while for 64-bit
// values radix sorting wins for more common cases but loses for some degenerate
// cases, and flag sorting handily wins for all other item sizes. I'm not 100% sure
// why that is, so some more effort into finding the right cutoff for the more
// general case might be appropriate. This approach overwhelmingly beats just using
// std::sort, at least on my system.
template <bool track_idxs = true, class Iter>
static void blobsort( Iter iter_begin, Iter iter_end, std::vector<hidx_t> & idxvec ) {
    typedef typename std::iterator_traits<Iter>::value_type T;
    const size_t count = iter_end - iter_begin;
    T *          begin = &(*iter_begin);
    T *          end   = &(*iter_end);

    if (track_idxs) {
        if (idxvec.size() != count) {
            idxvec.resize(count);
            std::iota(idxvec.begin(), idxvec.end(), 0);
        }
    }

    hidx_t * idxs = track_idxs ? &(*idxvec.begin()) : NULL;
    if (unlikely(count <= SMALLSORT_CUTOFF)) {
        if (count <= 1) {
            return;
        }
        smallsort<track_idxs>(begin, end, idxs);
    } else if (T::len > 8) {
        flagsort<track_idxs>(begin, end, idxs, begin, T::len - 1);
    } else {
        radixsort<track_idxs>(begin, end, idxs);
    }
}

template <class Iter>
static void blobsort( Iter iter_begin, Iter iter_end ) {
    std::vector<hidx_t> dummy;

    blobsort<false>(iter_begin, iter_end, dummy);
}

//-----------------------------------------------------------------------------
void BlobsortTest( void );
void BlobsortBenchmark( void );
