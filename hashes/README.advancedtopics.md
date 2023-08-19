Coding a hash function, specific advanced topics
================================================

Compiler hints
--------------

The following functions are guaranteed to exist for hash implementations to use. They
are generally used to improve performance and code generation. However, they are not
guaranteed to do anything! The compiler being used to build SMHasher3 may not support
these hints, or the build system may not know how to implement them for that
compiler. But you should be able to use them without fear of syntax errors.

- `likely(x)` hints to the compiler that the statement `x` is very likely to be true.
- `unlikely(x)` hints to the compiler that the statement `x` is very unlikely to be true.
- `expectp(x, p)` hints to the compiler that the statement `x` is likely to be true
  with probability p, where p is a number between 0 and 1 inclusive.
- `unpredictable(x)` hints to the compiler that the truth of the statement `x` is
  likely to be difficult for the CPU to predict.
- `assume(x)` tells the compiler that it can treat the statement `x` as always
  true. If the statement is ever false, then that can be treated as Undefined
  Behavior, and the compiler is allowed to do _anything_ in that case.
- `unreachable()` tells the compiler that control flow will never reach the current
  point. If it does ever reach that point, then that can be treated as Undefined
  Behavior, and the compiler is allowed to do _anything_ in that case.
- `prefetch(ptr)` hints to the compiler or CPU that memory at `ptr` should be loaded
  into cache. If supported, the hint is that the data will be used for reading, and
  that access will be maximally temporal (likely to be accessed again).
- `FORCE_INLINE` preceeding a function definition hints to the compiler that the
  function should be inlined if at all possible.
- `NEVER_INLINE` preceeding a function definition hints to the compiler that the
  function should not be inlined.
- `RESTRICT` can be used like the C `restrict` keyword, to hint to the compiler that
  two pointers do not have overlapping destinations even when aliasing rules allow
  it.

Debugging assistance macros
---------------------------

SMHasher3 provides a function called `verify(x)`. If the statement `x` is ever false,
then a warning is printed to stdout.

However, if the `DEBUG` preprocessor keyword is defined, `verify(x)`, `assume(x)`,
and `unreachable()` have different behavior. `verify(x)` and `assume(x)` will fire an
`assert()` if x is ever false, and `unreachable()` will always fire an `assert()`. In
those cases, execution will stop and the program will exit abnormally.

Other ways of reading/writing memory
------------------------------------

The reason that nearly all hashes in SMHasher use the `GET_U`* and `PUT_U`* functions
for transferring data to and from memory is because that is the only way to guarantee
that they will all work on all platforms, regardless of memory alignment or platform
restrictions, and will not invoke Undefined Behavior. It also allows people to easily
find the places where a hash implementations interfaces with "the outside world".
Finally, enforcing uniformity of memory access is also the most fair way to compare
performance across hashes.

Memory transfer routines are one thing that varies very widely across hashes, and
seems to be sometimes given little thought. Since it is usually isolated, it is also
easy to change if a better method is found. By having all hashes use the same
function, it is possible to replace the implementations and still verify that all
hashes work, and this will still produce valid performance comparisons across
whatever hashes you are interested in.

If you want to test out a different, perhaps less-portable, implementation for your
uses, you can just alter it in `platform/Platform.h.in` and recompile. Then you can
easily compare that performance change across _all_ the hashes in SMHasher3.

Alternate implementations may become an explicit configuration-time option for
SMHasher3 in the future.

Hash initialization / startup
-----------------------------

If a hash implementation requires or can make use of an initialization function, it
can provide one by setting the `$.initfn` member in its metadata block. The
function's signature must match `HashInitFn` in
`include/common/Hashinfo.h`. Currently that looks like: `bool MyHashInitFn( void )`.

This function must return true if initialization succeeds, and false if it fails.

The initialization function will be called exactly once for each hash that lists it
shortly before that hash is used. It is allowed to do anything sensical; it might set
up a table of values, it might verify that some supplied constants are valid, or it
might run a full self-test of the hash.

If your hash implementation uses any global variables that are modified after
initialization, make sure to read the section on "Thread-safety and global variables"
below.

If needed, I could definitely see enhancing this with a pointer to the HashInfo
object that is being initialized. If you require that functionality, it should be
easy to add.

Hashes with some unusable seeds
-------------------------------

Some hashes have a list or other subset of seeds that should not be used. A hash may
specify a function that can sanitize seeds before use. This is done by setting the
`$.seedfixfn` member in its metadata block. The function's signature must match
`HashSeedfixFn` in `include/common/Hashinfo.h`. Currently that looks like:
`seed_t MyHashSeedfixFn( const HashInfo * hinfo, const seed_t seed )`.

That function is given the seed value that SMHasher3 would like to use, and it must
return a valid seed value to use. If the given seed value is acceptable, then it
should be returned unchanged. If it isn't, then any valid seed value can be returned
instead.

SMHasher3 also supplies a utility function to handle a common case. Setting
`$.seedfixfn` to `excludeBadseeds` will replace any seeds that are in the
hash's set of `$.badseeds` with that seed plus one. It does handle the case
where there are multiple consecutive bad seeds. For example, if `3` and `4`
are both bad seeds, then `excludeBadseeds` will return `5` if given a seed
of `3`.

Note that some SMHasher3 tests deliberately will not call this function when seeding,
so your hash may sometimes still be given seeds that would be excluded by it.

Variations on seeding
---------------------

Most non-cryptographic hashes simply use only a small amount of integer data for
cheaply seeding their state. For hashes that work like that, the `seed_t` parameter
passed to them can be cast to a `uint64_t` and then used as a seed integer. Hashes
that do this should probably have low-overhead seeding, since any time the hash is
invoked the seed might or might not be the different than last time.

Sometimes the hash implementation would like to be seeded some other way. Maybe the
hash has a global table of random data that is based off of the seed value and
generating this table is expensive enough that doing that for every hash computation
would make the hash too slow. Maybe the actual hash implementation already has an
init function and the hash call takes some sort of context pointer, and there is a
desire to keep the SMHasher3 code as close as possible to the original. Maybe the
user is testing out different ways of seeding the table, so they would like multiple
`REGISTER_HASH()` blocks with the same hash function but different seeding
functions. Whatever the reason, a hash implemention might want seeding to happen
outside of a call to the hash.

For hashes which do want these more complex or expensive seeding procedures, another
option is to supply a seed processing function, which is done by setting the
`$.seedfn` member in its metadata block. The function's signature must match
`HashSeedFn` in `include/common/Hashinfo.h`. Currently that looks like: `uintptr_t
MyHashSeedFn( const seed_t seed )`.

If a hash implementation has such a seeding function, then it will be called only
when the seed value changes and additionally once every time a block of tests
starts. It is not called during the timed parts of performance testing, so it is OK
for it to be relatively expensive. Some tests do vary the seed quite a lot, so a full
SMHasher3 run will need it called many times, but this framework minimizes extra
calls.

Note that this function does not return a `seed_t`, but instead a `uintptr_t`. If the
seeding function returns a value of zero, then the input seed value will be passed to
the hash function as its `seed_t` parameter, exactly as if there were no seedfn. If a
non-zero value is returned by the hash's seeding function, then _that_ returned value
will be supplied as the `seed_t` value when the hash itself is called. This allows
the seeding function to return an arbitrary pointer to whatever kind of initialized
data structure is needed for the hash implementation to compute the result based on
the seed. The `seed_t` type is guaranteed to be large enough to hold the integer
representation of a pointer, so the hash can cast the `seed_t` back to a `uintptr_t`
and then cast that to whatever kind of pointer that the seeding function used.

For example:
```cpp
typedef struct {
    uint64_t s64[16];
    uint32_t s32[128];
} myhash_seedtable_t;

static thread_local myhash_seedtable_t seedtable;

static uintptr_t init_seedtable( const seed_t seed ) {
    MyRNG r((uint64_t)seed);
    for (int i = 0; i < 16; i++)  { seedtable.s64[i] = r.rng64(); }
    for (int i = 0; i < 128; i++) { seedtable.s32[i] = r.rng32(); }

    return (uintptr_t)(&seedtable);
}

static void MyHash( const void * in, const size_t len, const seed_t seed, void * out ) {
    const myhash_seedtable_t * table = (const myhash_seedtable_t *)(uintptr_t)seed;
    .....
}
......
   $.seedfn          = init_seedtable,
```

The `init_seedtable()` function will be called by SMHasher3 as needed, and it will
return a pointer to `seedtable` in the form of an integer. This will be passed to
`MyHash()` as a `seed_t` and it can be safely converted back to a pointer.

If you are wondering why that global `seedtable` is marked as `thread_local`, or why
a pointer needs to be passed at all when it seems like `MyHash()` could just as
easily get the address of `seedtable` itself, then please read the next section.

Thread-safety and global variables
----------------------------------

Some SMHasher3 tests are threaded. This means that the testing effort is divided up
among some number of threads which each (hopefully) get scheduled by the OS onto
different CPUs, thus allowing for a speedup by having work be done in parallel.

Some hash implementations use global variables. Doing this can make a hash unsafe to
use in a threaded environment.

This is because global variables are shared across threads by default. When a thread
is created it will see all the existing data in that memory exactly the same as the
main process. For variables that are read-only during hashing, this is totally
fine. Their contents can be generated once, either statically or via an `$.initfn`,
and then the hash will simply work in every thread.

However, any value _written_ to a global variable will (eventually) be seen by the
other threads and main process. If this data depends on something like the input
bytes or seed value being hashed, then one thread could overwrite the state that
another thread wrote and is in the middle of reading, leading to incorrect hash
values being computed. A number of "failures" in SMHasher were reported due to this
implementation issue, and not because of any real problem in the hashes themselves.

C++11 provides the `thread_local` keyword, which can make a global variable be unique
to each thread, but there are two big caveats to using it.

First, when a thread starts up these variables are initialized to their default
values if they have been specified or zero-initialized if not. They do not get a copy
of their data from the parent. If the hash has a seeding function then it may not get
called in each thread, and a hash's initialization function assuredly won't. This
means that initialize-once-read-many global variables should almost certainly **not**
be `thread_local`, and probably _can_ just be directly referenced in the hash
implementations.

Second, accessing a `thread_local` variable can be much slower than you might
expect. When one particular hash was changed to have its global read/write table
changed from a simple global variable to a thread-local version, its execution time
increased by about 20 cycles per hash! When it was then converted to use a seedfn as
described in the previous section, the execution time increase over the first,
thread-unsafe version was about 0.1 cycles.

This is why, in the example in the previous section, the "solution" of just having
`MyHash()` use the global `seedtable` variable directly was unsatisfactory. By having
the seedfn essentially cache the per-thread pointer lookup, the overhead of using
thread-local storage was all but eliminated.

If the hash you are implementing has any sort of global variables which are written
to more than once, then you are urged to find some way of making it thread-safe, via
use of a seedfn or some other method.

SMHasher3 has two different Sanity tests which try to detect thread-safety
implementation problems. If a failure is detected, then it simply disables threaded
testing, so at least the hash results will be trustable. SMHasher3 also takes care to
make testing results be identical no matter the threading configuration.

Platform-specific implementations
---------------------------------

Often it is desirable to have hash implementations that take advantage of
machine-specific features to improve performance of hash calculations while leaving
the hash results unchanged. In SMHasher3, this is best done by having the
implementation use compile-time checks to determine which implementation is best for
the target platform and automatically use that one.

This could be done in a wide variety of ways. For example, an implementation might
use `#if defined()` preprocessor directives to choose the best implementation of one
or more core functions. This might look like:
```cpp
/* Process exactly 512 bytes of data */
static uint64_t wackyhash_full_block( const uint8_t * data, const myhash_seedtable_t * table) {
#if defined(HAVE_AVX2)
    __m256i         sum = _mm256_setzero_si256();
    const __m256i * xdata = (const __m256i *)data;
    const __m256i * xkey  = (const __m256i *)table->s32;

    for (int i = 0; i < (512/32); i++) {
        __m256i d = _mm256_loadu_si256(xdata);
        __m256i k = _mm256_loadu_si256(xkey);
        d = _mm256_mullo_epi32(d, k);
	sum = _mm256_add_epi64(sum, d);
	xdata++; xkey++;
    }
    return horiz_sum_256(&sum);
#elif defined(HAVE_SSE_4_1)
    __m128i         sum = _mm_setzero_si128();
    const __m128i * xdata = (const __m128i *)data;
    const __m128i * xkey  = (const __m128i *)table->s32;

    for (int i = 0; i < (512/16); i++) {
        __m128i d = _mm_loadu_si128(xdata);
        __m128i k = _mm_loadu_si128(xkey);
        d = _mm_mullo_epi32(d, k);
	sum = _mm128_add_epi64(sum, d);
	xdata++; xkey++;
    }
    return horiz_sum_128(&sum);
#else
    uint64_t sum = 0;

    for (int i = 0; i < (512/8); i++) {
         uint32_t a = GET_U32<false>(data, i * 8)     * table->s32[2 * i]
         uint32_t b = GET_U32<false>(data, i * 8 + 4) * table->s32[2 * i + 1];
         sum += (((uint64_t)a) << 32) + b;
    }
    return sum;
#endif
}
```

With this setup, the rest of the code can just call `wackyhash_full_block()` and not
care about platform specifics.

A similar approach would be to have wrappers for each version of the code:
```cpp
#if defined(HAVE_AVX2)
static uint64_t wackyhash_full_block_avx2( const uint8_t * data, const uint32_t * key ) {
.....
}
#endif

#if defined(HAVE_SSE_4_1)
static uint64_t wackyhash_full_block_sse41( const uint8_t * data, const uint32_t * key ) {
.....
}
#endif

static uint64_t wackyhash_full_block_portable( const uint8_t * data, const uint32_t * key ) {
.....
}

static uint64_t wackyhash_full_block( const uint8_t * data, const uint32_t * key ) {
#if defined(HAVE_AVX2)
    return wackyhash_full_block_avx2(data, key);
#elif defined(HAVE_SSE_4_1)
    return wackyhash_full_block_sse41(data, key);
#else
    return wackyhash_full_block_portable(data, key);
#endif
}
```

If the amount of platform-specific code is extensive, and it starts being bulky,
annoying, and confusing to have it all in the same .cpp file, then you can also split
it out into .h files, each containing their own implementations of the same
function(s), and then choose which one gets included:
```cpp
#if defined(HAVE_AVX2)
  #include "Intrinsics.h"
  #include "wacky/fullblock-avx2.h"
#elif defined(HAVE_SSE_4_1)
  #include "Intrinsics.h"
  #include "wacky/fullblock-sse41.h"
#else
  #include "wacky/fullblock-portable.h"
#endif
```

In this example, each of those .h files implements `static uint64_t
wackyhash_full_block( const uint8_t * data, const uint32_t * key )` in its own way.

**The critical points in all of the above methods are that all of the implementations
produce identical results, and that a portable, always-works implementation is
present and usable.**

Details on using those preprocessor checks as well as asm instructions and intrinsics
can be found below.

Platform feature availability detection
---------------------------------------

The `Platform.h` file, which is included as part of the boilerplate code all hashes
in SMHasher3 have to use, provides some preprocessor tokens which indicate which sets
of features are available on the platform being compiled for.

These are:
- `HAVE_32BIT_PLATFORM`
- `HAVE_X86_64_ASM`
- `HAVE_ARM_ASM`
- `HAVE_ARM64_ASM`
- `HAVE_PPC_ASM`

They are defined if the feature exists, and not defined if it doesn't. As with most
other preprocessor tokens, these are usually used by preprocessor directives such as
`#if defined(HAVE_PPC_ASM)`.

Intrinsics
----------

It is frequently desirable to use vector or other specialized data operations that
are available on particular platforms. The general name that seems to be used for
these operations is "intrinsics".

The `Platform.h` file, which is included as part of the boilerplate code all hashes
in SMHasher3 should use, also provides a number of preprocessor tokens which indicate
which sets of intrinsics are available.

Some examples of these tokens are:
- `HAVE_SSE_2`
- `HAVE_X86_64_CRC32C`
- `HAVE_AVX2`
- `HAVE_UMUL128`
- `HAVE_ARM_SHA1`
- `HAVE_PPC_VSX`

The complete list can be found at the bottom of either `build/include/Platform.h` if
you have built SMHasher3, or `platform/Platform.h.EXAMPLE`.

SMHasher3 provides an easy way for hash implementations to use intrinsics. All that
needs to be done is to `#include "Intrinsics.h"`, and the correct header file(s) for
x86, ARM, and PPC instrinsics all become included as the platform supports them.

To help reduce compile time, it is good practice to guard the inclusion of
`Intrinsics.h` with `#if` statments ensuring that at least one of the specific
instructions sets you wish to use is available.

In addition to whatever intrinsics the platform provides, SMHasher3 provides some
wrapper functions for byteswapping vector data. These are:

- For ARM NEON (`HAVE_ARM_NEON`)
   - `uint64x2_t Vbswap64_u64( const uint64x2_t v )`
   - `uint32x4_t Vbswap32_u32( const uint32x4_t v )`
- For AVX512-F or -BW (`HAVE_AVX512_F` or `HAVE_AVX512_BW`)
   - `__m512i mm512_bswap64( const __m512i v )`
   - `__m512i mm512_bswap32( const __m512i v )`
- For AVX2 (`HAVE_AVX2`)
   - `__m256i mm256_bswap64( const __m256i v )`
   - `__m256i mm256_bswap32( const __m256i v )`
- For SSE2 or SSSE3 (`HAVE_SSE_2` or `HAVE_SSSE_3`)
   - `__m128i mm_bswap64( const __m128i v )`
   - `__m128i mm_bswap32( const __m128i v )`

AES intrinsics
--------------

Some hashes might use components from AES (Advanced Encryption Standard)
[https://en.wikipedia.org/wiki/Advanced_Encryption_Standard], as it has common
support for hardware acceleration.

A goal in SMHasher3 is to have additional support functions for this which
automatically use any intrinsics or other platform support if available, and revert
to fast, portable implementations when it is not. While some progress on this has
been made, it is not very polished. Suggestions for API improvements would be very
welcome.

Importantly, only 128-bit AES is currently supported!!!

As things stand, a hash that wants to use AES components can just `#include "AES.h"`,
which provides access to the following APIs:
- `int AES_KeySetup_Enc( uint32_t rk[], const uint8_t cipherKey[], int keyBits )`
- `int AES_KeySetup_Dec( uint32_t rk[], const uint8_t cipherKey[], int keyBits )`
- `void AES_EncryptRound( const uint32_t rk[4], uint8_t block[16] )`
- `void AES_DecryptRound( const uint32_t rk[4], uint8_t block[16] )`
- `template <int Nr> void AES_Encrypt( const uint32_t rk[], const uint8_t pt[16], uint8_t ct[16] )`
- `template <int Nr> void AES_Decrypt( const uint32_t rk[], const uint8_t ct[16], uint8_t pt[16] )`

The `KeySetup` functions expand the given `cipherkey[]` bytes into the AES encryption
key schedule, and return the number of rounds for that size key. They write the keys
into storage you provide.

The `Round` functions do one round of encryption or decryption using one round's
worth of expanded key schedule data.

The `AES_Encrypt` function does a complete AES encryption on 16 bytes of plaintext
(`pt`) using the complete set of expanded key data (`rk`) and writes the result to
`ct`. `AES_Decrypt` does the reverse, decrypting `ct` and writing to `pt`. For both
of those, the number of rounds is a template parameter.

Extended integer multiplication and addition
--------------------------------------------

Some hashes are based around integer math which goes beyond the 32-bit and 64-bit
integers that are guaranteed to exist in SMHasher3. For example, a hash might want to
multiply two 32-bit numbers together and keep a 96-bit wide running sum of the 64-bit
results. Or a hash might want to multiply two 64-bit numbers together and get the
full 128-bit result.

SMHasher3 provides a number of optimized routines for these kinds of
operations, collectively referred to as `MathMult`. These routines are all
under the namespace `MathMult::`. Hash implementations should use these
instead of coding their own. If you find that a new routine needs to be
added to SMHasher3, or you have an alternate implementation for one that
exists, please feel free to update `MathMult`.

The current list of `MathMult::` functions is:
- `mult32_64()` multiplies two 32-bit numbers for a 64-bit result which is returned
  as two 32-bit numbers
- `mult32_64()` can also multiply two 32-bit numbers for a 64-bit result which is
  returned as a 64-bit number
- `add96()` adds one 96-bit number into another, with both stored as 3x 32-bit
  numbers
- `fma32_96()` multiplies two 32-bit numbers into a 64-bit result, and adds it to a
  96-bit number stored as 3x 32-bit numbers
- `mult64_128()` multiplies two 64-bit numbers into a 128-bit result which is
  returned as two 64-bit numbers
- `mult64_128_nocarry()` multiplies two 64-bit numbers excluding only the cross-lane
  carry bits into a 128-bit result which is returned as two 64-bit numbers
- `add128()` adds a 64-bit number into a 128-bit number which is stored as two 64-bit
  numbers
- `add128()` can also add a 128-bit number into another 128-bit number where both
  are stored as two 64-bit numbers
- `add192()` adds a 192-bit number into another 192-bit number where both are stored
  as 3x 64-bit numbers
- `fma64_128()` multiplies two 64-bit numbers into a 128-bit result, and adds it to a
  128-bit number stored as two 64-bit numbers
- `fma64_192()` multiplies two 64-bit numbers into a 128-bit result, and adds it to a
  192-bit number stored as 3x 64-bit numbers
- `mult128_128()` multiplies two 128-bit numbers into a 128-bit result, where all are
  stored as two 64-bit numbers

To use any of these, simply have your hash implementation `#include
"Mathmult.h"`. Full function details can be found in
`include/hashlib/Mathmult.h`. It is strongly preferable to use the
`MathMult::` namespace explicitly, instead of a catch-all `using namespace
MathMult` statement.

It is possible that the name of this collection of functions will change in future
releases, and it is likely that the function names themselves will have some sort of
prefix added.

(P)RNG use by hashes
--------------------

Some hashes need a source of random-ish numbers to work with. For SMHasher3, all
included hash implementations must supply their own (P)RNG code, and must not use
system calls like `srand()`, `rand()`, `random()`, `drand48()`, or
`getrandom()`. They also must not use the `Rand` class in the Testlib side of
SMHasher3. Hash results, and thus their verification codes, must be stable across
different systems, so care must be taken with (P)RNGs.

If a hash specifies use of any (P)RNG that doesn't explicitly produce identical
results on different systems, then that hash must set `FLAG_HASH_SYSTEM_SPECIFIC` in
its metadata block, even though it may use (P)RNG code in SMHasher3 that does produce
identical results. This might only be "specified" by the fact that the (perhaps
de-facto) "official" implementation does something like call `rand()`. This is a way
for users to be warned that if they try to compare against some other implementation
of the same hash that their results may not precisely match those in SMHasher3.
