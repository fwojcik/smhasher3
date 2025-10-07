This document covers things that generally only become needed when you are
done or almost done developing your hash, or when you are implementing an
existing hash. It starts with a crash course on templates, which you can
easily skip if you are already familiar with them.

[[_TOC_]]

C++ templates
=============

SMHasher3 makes entensive use of C++ templates. This is because it wants to support
having functions with variations that are right inline with the rest of the code, and
it also cares a lot about performance.

If you haven't worked with templates before, then I promise they are not that scary,
and I will give a short crash course on them here. I'm only going to cover function
templates, since that is all that hash implementors are likely to need.

That said, SMHasher3 doesn't require hash implementations to use templates. If you
want to write completely separate functions for computing a hash both with and
without byteswapping, for example, you could certainly do that. However, if you use a
runtime `if()` statement, then that could impact performance. If you don't, you might
end up duplicating a lot of code, and that can easily lead to diverging code
paths. Using templates solves both potential problems at once.

Intro tutorials on C++ templating very often tend to focus on the fact that
templating can happen on types, that you can use it to have the same implementation
that will work for different numeric or object types. As a systems programmer, that
feature never seemed especially compelling to me when presented that way. However,
templating can also be used on values! And that is generally how SMHasher3 uses it.

In C and C++, you could have a simple function that looks like:
```cpp
int adder4(int input) {
    return input + 4;
}
```

When that gets compiled into an object file, it typically will contain a machine-code
version of that function listed under its name "adder4". When you want to use that
function, you just call it:
```cpp
newnumber = adder4(number);
```

If we make that function a template instead:
```cpp
template <int value>
int adder(int input) {
    return input + value;
}
```

then it is no longer a function, but is instead a function template. When that block
of code gets compiled there will be no machine code for it, and no `adder` symbol to
link against.

The things between the chevrons (`<` and `>` symbols) are called the template
parameters. A _lot_ of fancy things can be done there, but all that matters right now
is that it can contain a list of variable declarations.

The way to create a function from the template is simply to invoke it using some
values as its template parameter(s):
```cpp
newnumber = adder<4>(number);
```

The process of turning a function template into an actual function is called
instantiation. By calling `adder`, the compiler will instantiate its template into a
callable function. Now when those blocks of code get compiled together, there will be
an `adder<4>` function which can be linked, and it will have the corresponding
machine code, and work just like any other function.

If other values were given as template parameters, a separate copy of `adder` would
be compiled for each different one. `adder<4>` and `adder<6>` would be completely
different functions.

This can be extended into other things, like byteswapping:
```cpp
template <bool bswap>
static uint64_t wordsum( const uint32_t * in, const size_t count ) {
    const uint32_t * const end = &in[count];
    uint64_t sum = 0;

    while (in < end) {
        uint32_t v = *in++;
        if (bswap) {
	    sum += BSWAP32(v);
	} else {
	    sum += v;
	}
    }

    return sum;
}

uint64_t sum1 = wordsum<false>(ptr, 128);
uint64_t sum2 = wordsum<true>(ptr, 128);
```

Now `wordsum` will be compiled twice, once with `bswap == true` and once with `bswap
== false`. For each of those, the compiler will almost certainly optimize out the
`if()` statement since its conditional will be a constant, making both
`wordsum<false>` and `wordsum<true>` be just as fast as if they were coded as
two separate functions. But this pattern keeps it easy to see that they only differ
in one way: whether or not the input words are byteswapped. And now if `wordsum` is
modified, perhaps to become a more sophisticated data mixing function, then both
copies will automatically change in sync.

Use of template parameters isn't limited to `if()` statements either. Imagine a
function with a template parameter controlling how many times a loop is unrolled, or
how many times to call a mixing function.

As you may have guessed, though, this means that any values used as template
parameters must be known at compile-time (the `constexpr` keyword is often used for
this). There is no C++-compiler being shipped inside your program's binary, so there
is no way to do something like:
```cpp
const int incr = foo();
newnumber = adder<incr>(number);
```

The closest you can get is something like:
```cpp
int wrapper(const int value, int input) {
     if (value == 2) { return adder<2>(input); }
     if (value == 11) { return adder<11>(input); }
     ....
}
```

The other limitation of function templates that is good to know about is that every
part of the function template must compile, even if it can never be used. This mostly
comes up when templating on types. For example:
```cpp
template <typename T>
static void function() {
    const T C1  = (sizeof(T) == 4) ? UINT32_C(2166136261) :
                                     UINT64_C(0xcbf29ce484222325);
.....
}
```

In the case where `T` is `uint32_t`, this will look like:
```cpp
    const uint32_t C1  = (sizeof(uint32_t) == 4) ? UINT32_C(2166136261) :
                                                   UINT64_C(0xcbf29ce484222325);
```

and so one branch of that conditional becomes assigning a 64-bit number to a 32-bit
variable. This works because that is a legal thing to do in C++, even if the results
may be surprising. But the critical point is that this whole statement will compile
for that value of `T`. The fact that "sizeof(uint32_t)" _is_ 4 and so the "else" side
of the conditionals will never fire in that case doesn't change anything.

Later versions of C++ have ways around this limitation (C++17's `constexpr if` being
the main one), but for the time being SMHasher3 will keep itself on C++11 for
increased portability.

Coding a hash function, the non-basics
======================================

Hash metadata
-------------

Every hash has a block of metadata associated with it. It can be found at the bottom
of the file, starting with `REGISTER_HASH(`. Without this call, the existence of the
hash function will not be made known to Hashlib, and thus the rest of the code will
be unable to run it.

Most pieces of this metadata block are currently used by SMHasher3, but some are not
yet active. This mostly applies to the various `FLAG` options, although some of those
are currently looked at. The goal is to allow SMHasher3 to eventually filter and
report on hashes based on that metadata.

The first item passed to `REGISTER_HASH()` is the hash name. See `hashes/README.md`
under "Hash naming scheme" for requirements.

The remaining user-settable parts of the metadata are all set via a comma-separated
list of `$.KEY = VALUE` statements. The last one of those must not have a
comma. The list of those metadata keys is:
- `desc`, a textual description of the hash, which should not exceed 60 characters
- `impl`, a textual description of the hash implementation chosen, if multiple are
  available (e.g. "portable", "AVX2", "arm-neon", etc.), which should not exceed 10
  characters. (optional; leave unset if no alternate implementations)
- `hash_flags`, which marks specific yes/no information about the hash itself
- `impl_flags`, which marks specific yes/no information about this particular
  implementation of the hash
- `bits`, the output hash-width in bits
- `verification_LE`, the verification code of the hash for little-endian mode
- `verification_BE`, the verification code of the hash for big-endian mode
- `hashfn_native`, the function called to compute the hash without byteswapping
- `hashfn_bswap`, the function called to compute the hash with byteswapping
- `initfn`, the hash's one-time initialization function _(optional)_
- `seedfn`, the hash's per-seed initialization function _(optional)_
- `seedfixfn`, the hash's function to filter out unusable seeds _(optional)_
- `badseeds`, a `std::set` of known "bad" seeds _(optional)_
- `badseeddesc`, a C string which uses English text to describe a pattern
  of "bad" seeds _(optional)_

Put all together, this looks something like:
```
REGISTER_HASH(ascon_XOFa_256,
   $.desc       = "ascon v1.2 (XOFa, 256 bits)",
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC          |
         FLAG_HASH_NO_SEED                |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_CANONICAL_BE           |
         FLAG_IMPL_VERY_SLOW              |
         FLAG_IMPL_ROTATE                 |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits = 256,
   $.verification_LE = 0x2ACF11FE,
   $.verification_BE = 0xE5CD2E9B,
   $.initfn          = ascon_xof_selftest,
   $.hashfn_native   = ascon_xof<256, true, false>,
   $.hashfn_bswap    = ascon_xof<256, true, true>
 );
```

This `$.` business is all a horrible hack because I wanted very human-readable sets
of metadata for hashes, and C++ doesn't support designated initializers until C++20!
And it didn't bother to provide any good equivalent in the meantime! This is
pants-on-head crazytown! C had them starting with C99!

I may eventually convert these blocks to the [C++ Named Parameter
Idiom](https://isocpp.org/wiki/faq/ctors#named-parameter-idiom), but I'm not sure
that will produce an acceptably readable result. We shall see.

Most of those fields are self-explanatory and/or covered in more detail elsewhere in
these READMEs. The verification codes and flags are covered next.

Hash verification codes
-----------------------

The verification codes should probably be kept at their default values of
zero for all but the final stages of developing a hash. When you are ready, you can
run (e.g.) `./SMHasher3 --test=VerifyAll --verbose | grep WackyHash` and see output
that looks like:
```
             WackyHash-64 - Verification value LE 0x35566AB2 ...... SKIP (unverifiable)
             WackyHash-64 - Verification value BE 0x5A890DE1 ...... SKIP (unverifiable)
            WackyHash-128 - Verification value LE 0xF0BA7B0D ...... SKIP (unverifiable)
            WackyHash-128 - Verification value BE 0xFDB0BF75 ...... SKIP (unverifiable)
```

You can then go back to your hashes' metadata blocks and fill in those values:
```
REGISTER_HASH(WackyHash_64,
....
   $.verification_LE = 0x35566AB2,
   $.verification_BE = 0x5A890DE1,
....

REGISTER_HASH(WackyHash_128,
....
   $.verification_LE = 0xF0BA7B0D,
   $.verification_BE = 0xFDB0BF75,
....
```

Then rebuild SMHasher3 and verify that you filled them in correctly:
```
$ ./SMHasher3 --test=VerifyAll --verbose | grep WackyHash
             WackyHash-64 - Verification value LE 0x35566AB2 ...... PASS
             WackyHash-64 - Verification value BE 0x5A890DE1 ...... PASS
            WackyHash-128 - Verification value LE 0xF0BA7B0D ...... PASS
            WackyHash-128 - Verification value BE 0xFDB0BF75 ...... PASS
```

In general, hashes should have different values emerge from the native and
byteswapped versions. The exception to this is hashes that are byte-oriented, like
the original Pearson hashes or CRC32. Those hashes basically operate identically on
big- and little-endian machines. It may not even make sense to refer to a
"byteswapped" version of an implementation. Because of this, the LE and BE
verification values are also going to be identical for those hashes. In this case,
you should make sure that the same function is specified for _both_ `$.hashfn_native`
and `$.hashfn_bswap`. If different functions are specified, even if their
implementations are identical, then a WARNING will be generated on startup.

If you are implementing a pre-existing hash, you might find it helpful to compute the
verification codes outside of SMHasher3 and fill them in before you start
implementing. To do this, you can use `misc/hashverify.c`, which is a separate
external stand-alone program, written in plain C99. It will compute the verification
code for the platform you compile and run it on, but not the opposite endianness.

Hash metadata flags
-------------------

The remaining metadata items to cover are `hash_flags` and `impl_flags`. The idea
with splitting up these sets of flags is that some hash aspects we care about are
inevitably tied to the hash itself, and other aspects may change if a new
implementation is made.

The vast majority of these are meant as informational to users. The plan is to
someday allow filtering and reporting based on these flags. Because of that, don't
worry too much about setting them unless you're readying your hash for submission to
the SMHasher3 repository.

A few flags alter testing operation somewhat, so the exceptions to that are:
- `SMALL_SEED`
- `ENDIAN_INDEPENDENT` and `CANONICAL_LE`/`CANONICAL_BE`/`CANONICAL_BOTH`
- `MOCK` and `CRYPTOGRAPHIC`, which only affect the order hashes are listed,
- `SANITY_FAILS`, which will only suppress a warning
- `SLOW` or `VERY_SLOW`, which will only abbreviate some testing


The complete list of `hash_flags` and their meanings (the `FLAG_HASH_` prefix is
omitted from all of these):
- `MOCK` marks hashes which are not intended to be used seriously. These include
  hashes which are deliberately bad, or illustrative, or just silly.
- `CRYPTOGRAPHIC` marks hashes which were designed to withstand cryptographic attacks.
- `CRYPTOGRAPHIC_WEAK` marks hashes which did not sufficiently withstand those
  attacks. These hashes should still be marked as `CRYPTOGRAPHIC` also.
- `CRC_BASED` means the hash uses CRC primitives, and could probably benefit from
  hardware CRC support.
- `AES_BASED` means the hash uses AES primitives, and could probably benefit from
  hardware AES support. This could be even only part of AES.
- `CLMUL_BASED` means the hash uses carryless-multiplication (CLMUL) primitives, and
  could probably benefit from hardware CLMUL support.
- `LOOKUP_TABLE` means the hash could only reasonably be implemented with a table
  lookup. The table could be read-only or read-write, and its contents could be
  specified at compile-time or generated on startup or per-hash. Tables from
  self-tests or small-ish tables of contants that are just iterated over and would
  typically just be inlined for a fixed seed do not count towards this flag.
- `XL_SEED` means the hash can take more than 64-bits of seed data.
- `SMALL_SEED` means the hash can only take 32-bits of seed data.
- `NO_SEED` means the hash does not officially have a seed. These hashes almost
  always have some sort of home-grown seeding algorithm in SMHasher3, and a seed of
  zero will always result in the same hashes as the official, unaltered algorithm.
- `SYSTEM_SPECIFIC` means that the hash may not give the same results for every
  implementation. This is almost always because the "official" implementation uses an
  under-specified (P)RNG (like `rand()`) as part of the hash.
- `ENDIAN_INDEPENDENT` means that the hash output bytes are defined to be the same
  across platforms with differing integer byte-orderings. This usually applies to
  cryptographic hashes, and usually not to others, but there are definitely some
  non-cryptographic hashes that specify a correct output byte-ordering.
- `FLOATING_POINT` means that the hash is defined to use floating-point operations.

The list of `impl_flags` and their meanings (the `FLAG_IMPL_` prefix is omitted from
all of these):
- `SANITY_FAILS` means that this implementation fails one or more Sanity tests
- `SLOW` means that the hash either a) takes 160 cycles/hash or more for the
  `Average` result for the "Small key speed test", or b) hashes less than 1.0
  byte/cycle for the `Average` result for either "Bulk speed test", or c) both,
  but is not classified as `VERY_SLOW`.
- `VERY_SLOW` means that the hash either a) takes 400 cycles/hash or more for the
  `Average` result for the "Small key speed test", or b) hashes less than 0.333
  byte/cycle for the `Average` result for either "Bulk speed test", or c) both.
- `READ_PAST_EOB` means the hash may read past the bounds of the designated input
  buffer. Note that this does NOT imply that the hash value is affected by bytes
  outside those specified.
- `TYPE_PUNNING` means the hash uses type manipulation to convert data values in ways
  that could be Undefined Behavior. It may or may not be based on a `union`. The goal
  is to fix all of these before release.
- `INCREMENTAL` means that the hash implementation supports incremental hashing. This
  may imply that the implementation is slower than necessary, because SMHasher will
  never compute hashes incrementally.
- `INCREMENTAL_DIFFERENT` means that the hash implementation supports incremental
  hashing AND that the hash results do not match that of the non-incremental version
  of the hash. This reflects intentional behavior by the hash author(s).
- `128BIT` currently means that the hash _requires_ 128-bit integer support
- `MULTIPLY` means that the hash uses multiplication with 32-bit inputs.
- `MULTIPLY_64_64` means that the hash uses multiplication with 64-bit inputs and
  only uses the low 64-bit result.
- `MULTIPLY_64_128` means that the hash uses multiplication with 64-bit inputs and
  uses the entire 128-bit result.
- `MULTIPLY_128_128` means that the hash uses multiplication with 128-bit inputs and
  only uses the low 128-bit result.
- `ROTATE` means the hash uses integer rotation by fixed amounts only
- `ROTATE_VARIABLE` means the hash uses integer rotation by data-dependent amounts
- `SHIFT_VARIABLE` means the hash uses integer bit shifts by data-dependent amounts
- `MODULUS` means the hash uses an integer modulus operation that is not by a power-of-2
- `ASM` means the hash uses assembly instructions
- `CANONICAL_LE` with `FLAG_HASH_ENDIAN_INDEPENDENT` means that the native hashfn
  produces the hash-specified results on little-endian systems
- `CANONICAL_BE` with `FLAG_HASH_ENDIAN_INDEPENDENT` means that the native hashfn
  produces the hash-specified results on big-endian systems
- `CANONICAL_BOTH` with `FLAG_HASH_ENDIAN_INDEPENDENT` means that the native hashfn
  produces the hash-specified results on both big-endian and little-endian systems
- `SEED_WITH_HINT` is for internal use only
- `LICENSE_PUBLIC_DOMAIN` means that the implementation is licensed with some
  public-domain-ish license (literally "public domain", The Unlicense, CC0, etc.)
- `LICENSE_BSD` means that the implementation is distributed under either the "modified
  BSD license" (aka "3-clause BSD license") or the "FreeBSD license" (aka "2-clause
  BSD license").
- `LICENSE_MIT` means that the implementation is distributed under the MIT license.
- `LICENSE_APACHE2` means that the implementation is distributed under the Apache-2.0 license.
- `LICENSE_ZLIB` means that the implementation is distributed under the Zlib license.
- `LICENSE_GPL3` means that the implementation is distributed under the GPL3 license.

"Slow" and "very slow" hashes have some test suites shorted to try to keep runtime
tolerable. Their thresholds are somewhat arbitrary and x86-specific, and might be
updated in time. They were chosen based off of a histogram of hash speeds, and were
the values around the two largest obvious gaps.

The particular choices of which mathematical features to call out were made according
to those which can be more expensive (sometimes **much** more expensive) on CPUs
which aren't the more popular general-computing platforms. Yes, even some
not-that-old embedded systems can have expensive rotation or non-constant shifts.

The licensing flags are not authoritative. This means that the license terms in the
file override the license flag. If they disagree, the license terms in the file take
precedence. The flags are only provided to assist users trying to filter hashes based
on licensing.

Cryptographic hashes
--------------------

The only thing that cryptographic hash implementations definitely must do is to set
`FLAG_HASH_CRYPTOGRAPHIC` in `$.hash_flags`. If there are plausible attacks on it,
then `FLAG_HASH_CRYPTOGRAPHIC_WEAK` should also be set.

That being said, cryptographic functions are often also in need of being marked
`FLAG_IMPL_SLOW` or `FLAG_IMPL_VERY_SLOW` in their `$.impl_flags`. They generally
have hash results that need to be the same no matter the system endianness, so the
discussion below on `FLAG_HASH_ENDIAN_INDEPENDENT` should be considered carefully.

Want your hash distributed with SMHasher3?
==========================================

If you would like your hash implementation(s) to be distributed with the
SMHasher3 project, please try to follow the guidelines in `CONTRIBUTING.md`
and the remaining steps in this document to the extent that you
can. Nothing there is needed to simply use SMHasher3 to locally test and
develop a hash.

That being said, just getting the basics working is enough for a pull
request. If you do address the topics discussed there and in this document,
then it will probably take less time for your code to be added, but don't
think about them as a necessity.

Worrying about endianness issues
================================

Being able to test how a hash behaves on both big- and little-endian machines can be
very valuable, and is an explicit goal of SMHasher3. The issue is how to make (e.g) a
hash implementation running on a little-endian system compute what the hash value
would be if the same code were running on a big-endian system. This sounds
complicated, but once your hash is complete or nearly so, it should be only a little
effort to make it handle that task.

The general idea
----------------

The key concept is that system endianness typically _only_ comes into play when the
hash is converting between bytes in memory and integer variables. Once variables are
populated with the same _values_ (which may have different bitwise representations),
the computations that take place on them should be identical no matter the
endianness.

To give a concrete example of this, here is some code, and its output on a
little-endian and big-endian system:
```cpp
// An arbitrary function that does some complicated math on an integer
uint32_t scramble(uint32_t var) {
    var *= 0xc0c2caeb;
    var <<= 5;
    var += 12090;
    var ^= 0x98bacea6;
    var >>= 12;
    var = ROTR32(var, 9);
    var *= 0xb0d8ecdf;
    return var;
}

const uint8_t bytes[8] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80 };

printf("Native mode\n");
for (int i = 0; i <= 4; i++) {
    uint32_t before = GET_U32<false>(bytes, i);
    uint32_t after  = scramble(before);
    printf("%10u (0x%08x) --> %10u (0x%08x)\n", before, before, after, after);
}
printf("\nByteswapped mode\n");
for (int i = 0; i <= 4; i++) {
    uint32_t before = GET_U32<true>(bytes, i);
    uint32_t after  = scramble(before);
    printf("%10u (0x%08x) --> %10u (0x%08x)\n", before, before, after, after);
}
```

Little-endian (x86):
```
Native mode
 134480385 (0x08040201) --> 1964494367 (0x7517ce1f)
 268960770 (0x10080402) --> 3084698036 (0xb7dcc1b4)
 537921540 (0x20100804) -->  920808265 (0x36e26b49)
1075843080 (0x40201008) --> 4077043488 (0xf302bf20)
2151686160 (0x80402010) --> 2799684753 (0xa6dfcc91)

Byteswapped mode
  16909320 (0x01020408) -->  508671619 (0x1e51b683)
  33818640 (0x02040810) --> 2711269739 (0xa19ab16b)
  67637280 (0x04081020) --> 4144244667 (0xf70427bb)
 135274560 (0x08102040) --> 3455065179 (0xcdf01c5b)
 270549120 (0x10204080) --> 1989686043 (0x7698331b)
```

Big-endian (PPC):
```
Native mode
  16909320 (0x01020408) -->  508671619 (0x1e51b683)
  33818640 (0x02040810) --> 2711269739 (0xa19ab16b)
  67637280 (0x04081020) --> 4144244667 (0xf70427bb)
 135274560 (0x08102040) --> 3455065179 (0xcdf01c5b)
 270549120 (0x10204080) --> 1989686043 (0x7698331b)

Byteswapped mode
 134480385 (0x08040201) --> 1964494367 (0x7517ce1f)
 268960770 (0x10080402) --> 3084698036 (0xb7dcc1b4)
 537921540 (0x20100804) -->  920808265 (0x36e26b49)
1075843080 (0x40201008) --> 4077043488 (0xf302bf20)
2151686160 (0x80402010) --> 2799684753 (0xa6dfcc91)
```

In both cases, the "byteswapped" mode computed exactly the same results as the
opposite-endianness system, and **all that needed to be done was alter the
byteswapping parameter of `GET_U32`; no other part of the "hash" had to change**.

Since the SMHasher3 API has hash implementations write out their hashes to a byte
stream, then **in the common case** where non-cryptographic hash implementations
simply want to write out the bytes of their hash in system-native byteorder (since
they care about speed and don't really care about endianness), that means that it is
almost always the case that **when reading input data from memory requires
byteswapping so will byteswapping need to happen when writing the output hash to
memory**.

Some exceptions to all of this are covered later.

Augmenting your hash to handle endianness
-----------------------------------------

If you've been using following the previous advice and using the `GET_U`* and
`PUT_U`* functions to convert between data in memory and integer variables, and just
using them in native-endianness mode, then about 90% of this task will be very
straightforward.

(If you see some confusing things in the code snippets in this section then you can
probably ignore them; details on all of them can be found in
`hashes/README.advancedtopics.md`)

Let's say you finished coding `WackyHash64` and your code looks something like this:
```cpp
static uint64_t wackyhash_full_block( const uint8_t * data, const myhash_seedtable_t * table ) {
......
    const __m256i * xdata = (const __m256i *)data;
    __m256i d = _mm256_loadu_si256(xdata);
......
    const __m128i * xdata = (const __m128i *)data;
    __m128i d = _mm_loadu_si128(xdata);
......
    uint32_t a = GET_U32<false>(data, i * 8)     * table->s32[2 * i]
    uint32_t b = GET_U32<false>(data, i * 8 + 4) * table->s32[2 * i + 1];
......
}

template <bool bswap>
static void WackyHash64( const void * in, const size_t len, const seed_t seed, void * out ) {
    const myhash_seedtable_t * table = (const myhash_seedtable_t *)(uintptr_t)seed;
    uint64_t hash = table->s64[0];

    const uint8_t * ptr = (const uint8_t *)in;
    const uint8_t * end = &ptr[len];

    // Process 512-byte chunks
    while ((end - ptr) >= 512) {
        hash = wackyhash_mix(hash, wackyhash_full_block(ptr, table));
	ptr += 512;
    }
    // Process remaining 8-byte chunks
    while ((end - ptr) >= 8) {
        hash = wackyhash_mix(hash, wackyhash_word(GET_U64<false>(ptr, 0), table));
	ptr += 8;
    }
    // Process remaining 1-byte chunks
    while (ptr < end) {
        hash = wackyhash_mix(hash, wackyhash_word(*ptr++, table));
    }

    PUT_U64<false>(hash, (uint8_t *)out, 0);
}
```

The next thing to do is to just find all of the places where you put `false` in the
`GET_U`* and `PUT_U`* function template parameters and put in the `bswap` template
parameter from your top-level function. You might have to carry that parameter
through your other intermediate functions, though.

Doing that looks like:
```cpp
template <bool bswap>
static uint64_t wackyhash_full_block( const uint8_t * data, const myhash_seedtable_t * table ) {
......
    const __m256i * xdata = (const __m256i *)data;
    __m256i d = _mm256_loadu_si256(xdata);
    if (bswap) { d = mm256_bswap32(d); }
......
    const __m128i * xdata = (const __m128i *)data;
    __m128i d = _mm_loadu_si128(xdata);
    if (bswap) { d = mm_bswap32(d); }
......
    uint32_t a = GET_U32<bswap>(data, i * 8)     * table->s32[2 * i]
    uint32_t b = GET_U32<bswap>(data, i * 8 + 4) * table->s32[2 * i + 1];
......
}

template <bool bswap>
static void WackyHash64( const void * in, const size_t len, const seed_t seed, void * out ) {
    const myhash_seedtable_t * table = (const myhash_seedtable_t *)(uintptr_t)seed;
    const uint8_t * ptr = (const uint8_t *)in;
    const uint8_t * end = &ptr[len];
    uint64_t hash = table->s64[0];

    // Process 512-byte chunks
    while ((end - ptr) >= 512) {
        hash = wackyhash_mix(hash, wackyhash_full_block<bswap>(ptr, table));
	ptr += 512;
    }
    // Process remaining 8-byte chunks
    while ((end - ptr) >= 8) {
        hash = wackyhash_mix(hash, wackyhash_word(GET_U64<bswap>(ptr, 0), table));
	ptr += 8;
    }
    // Process remaining 1-byte chunks
    while (ptr < end) {
        hash = wackyhash_mix(hash, wackyhash_word(*ptr++, table));
    }

    PUT_U64<bswap>(hash, (uint8_t *)out, 0);
}
```

Some important things to note:
- Because `wackyhash_full_block` read data through the input pointer, we could tell
  that it needed to handle byteswapping
- Because we are choosing to use templates, this means `wackyhash_full_block` became
  a template function
- Integers that were populated from memory via intrinsics still needed to be
  byteswapped
- Because `wackyhash_word` only takes a `uint64_t` it does not need to handle data
  conversion, and was not turned into a template function
- Data loaded from a table of integers that our implementation populated does not
  need to be byteswapped, because there is no conversion between "a stream of bytes"
  and integers
- Data that was loaded bytewise (the `*ptr++` line in `WackyHash64`) did not need to
  be converted
- Even though some of the input bytestream data was treated as 32-bit words and some
  as 64-bit words, that had no impact on when byteswapping happened. This is because
  this change-in-reading didn't depend on endianness or the data read, only the
  length of the input data.
- Since we kept the function declaration from the `EXAMPLE` file and already
  populated the `$.hashfn_native` and `$.hashfn_bswap` metadata fields correctly, we
  didn't have to do that for this step.
- The hash never has to decide whether or not to call its byteswapped version or the
  native version: the SMHasher3 framework handles that automatically.

This example code didn't do anything that needed more conversion than that, but your
code might.

Handling endianness yourself
----------------------------

If you want or need to do byteswapping more manually, SMHasher3 provides
`BSWAP16(x)`, `BSWAP32(x)`, and `BSWAP64(x)`, as well as a generic (templated)
function which wraps all 3 of those, which is simply `BSWAP(x)`. Vector
implementations are also available; see `hashes/README.advancedtopics.md`.

There is also a macro called `COND_BSWAP()` which provides a little syntactic sugar
for the somewhat common pattern of:
```cpp
if (some_condition) {
    output = BSWAP(input);
} else {
    output = input;
}
```
That code could become:
```cpp
output = COND_BSWAP(input, some_condition);
```

Just in case your code needs to know if it is running on a big-endian or
little-endian platform, SMHasher3 provides two utility functions for that: `isLE()`
and `isBE()`, which return `true` for little-endian or big-endian platforms
respectively, and `false` otherwise. Since run-time endianness detection is
explicitly supported, those functions' outputs cannot be known at compile-time, and
so cannot be used in `constexpr` expressions.

More complex endianness scenarios
---------------------------------

Here are some cases where trickier bytewswapping approaches might sneak in:

- Hashes which are not ENDIAN_INDEPENDENT and which use fancy ways to read
  the tail of the input which can be a less than a "block" of data. The
  original code might look like:
  ```cpp
  // Reads the last 1-7 bytes.
  // This deliberately reads beyond the end of the input buffer.
  lastblk = (*(uint64_t *)inptr) & ((1ULL << (len * 8)) - 1);
  ```
  This code stealthily assumes that the first byte of data at `inptr` will appear in
  the low byte of `(*(uint64_t *)inptr)`, which won't be true on big-endian
  systems. This code would then need to become something like:
  ```cpp
  // Reads the last 1-7 bytes.
  // This deliberately reads beyond the end of the input buffer.
  if (isLE() ^ bswap) {
      lastblk = GET_U64<bswap>(inptr, 0) & ((UINT64_C(1) << (len * 8)) - 1));
  } else {
      lastblk = GET_U64<bswap>(inptr, 0) >> (64 - (len * 8));
  }
  ```
  Other approaches are possible. See `hashes/fnv.cpp` or `hashes/t1ha.cpp`
  for other examples of varying extremity.

  If you test your hash with `--test=Sanity --endian=nonnative` and you
  start getting new failures due to "flipped bit NNN, got identical output"
  or "non-key byte altered hash", then this issue is a prime candidate for
  investigation.

  If your hash is ENDIAN_INDEPENDENT, then you should be fine ignoring this
  issue, since the implementation with "incorrect" endianness will basically
  never be called. That said, some user might be interested in how your hash
  function performs in an environment with the "wrong" endianness without
  needing to spend cycles byteswapping data, and if this issue is left
  unaddressed then they will not be able to test that.

- A hash that specifies that its output must always be given in a specific
  byte-ordering. That would need code which might look like:
  ```cpp
    // Always write in big-endian byte ordering
    if (isLE()) {
        PUT_U64<true>(h, (uint8_t *)out, 0);
    } else {
        PUT_U64<false>(h, (uint8_t *)out, 0);
    }
  ```
  or possibly
  ```cpp
    h = COND_BSWAP(h, isLE());
    PUT_U64<false>(h, (uint8_t *)out, 0);
  ```
  if you don't mind modifying `h`, or even:
  ```cpp
    PUT_U64<false>(COND_BSWAP(h, isLE()), (uint8_t *)out, 0);
  ```
  You can use whichever you find least confusing. Note that `isLE()` is NOT
  `constexpr`, so code like `PUT_U32<isLE()>(...)` would not be valid C++.

- A hash that specifically has endian-independent outputs, where it would be actively
  incorrect to return different output bytestreams. This mostly applies to
  cryptographic hashes, and is very likely for a subset of hashes to which the
  previous item applies.

  This is subtly different than the previous item. That one was only concerned with
  the byte ordering of data held in the integers being output, while those integers'
  contents may vary by more than just byte order. This item concerns hashes where the
  actual output bytes and their order have a specific, correct answer.

  For these hashes, the important additional step is to set the metadata flags
  correctly. The `$.hash_flags` item needs to include `FLAG_HASH_ENDIAN_INDEPENDENT`.

  If your hash's `native` implementation returns the correct result on little-endian
  systems only, then the `$.impl_flags` item needs to include `FLAG_IMPL_CANONICAL_LE`.

  If your hash's `native` implementation returns the correct result on big-endian
  systems only, then the `$.impl_flags` item needs to include `FLAG_IMPL_CANONICAL_BE`.

  If your hash's implementation automatically returns the correct result on both
  big-endian and little-endian systems, then the `$.impl_flags` item should include
  `FLAG_IMPL_CANONICAL_BOTH`, and you should verify that the `$.verification_LE` and
  `$.verification_BE` codes match, and that the same function is given for both
  `$.hashfn_native` and `$.hashfn_bswap`.

- A hash that writes a larger bit-width output composed of smaller bit-width
  chunks. For example, here is a 64-bit hash written from two 32-bit integers:
  ```cpp
  PUT_U32<bswap>(hash_hi, out, isBE() ^ bswap ? 0 : 4);
  PUT_U32<bswap>(hash_lo, out, isBE() ^ bswap ? 4 : 0);
  ```
  This construction does byteswapping of a 64-bit quantity which just happens to be
  held in two 32-bit integers.

  This may seem confusing, but remember that the goal is to get the same output
  bytestream on systems of either endianness. If this is run on a little-endian
  system looking for results that a little-endian system would give, then `isBE()`
  and `bswap` would both be `false`, so the byte written to `out[0]` would be the
  least-significant byte of `hash_lo`. If this is run on a big-endian system that is
  _also_ looking for results that a _little_-endian system would give, then `isBE()`
  and `bswap` would both be `true`, and so once again the byte written to `out[0]`
  would be the least-significant byte of `hash_lo`.

- Self-test or other data that is stored as integers but should be interpreted as a
  bytestream. The fixed code might look like:
  ```cpp
  uint64_t testresults[] = { UINT64_C(0xc87202ecbb28df5d), ..... };
  uint8_t expected[8];
  .....
  if (isLE()) {
      PUT_U64<false>(testresults[i], expected, 0);
  } else {
      PUT_U64<true>(testresults[i], expected, 0);
  }
  ```
