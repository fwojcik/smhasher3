[[_TOC_]]

Adding a hash function to SMHasher3
===================================

This document will walk you through the steps for adding a new hash function to
SMHasher3. It will start out with the basic steps needed if you are in the process of
developing or working on a hash function.

If the hash function you want to add is complete or nearly complete, then
there are some additional steps you should at least try to perform, and
those will be described in `hashes/README.latersteps.md`.

A number of specific issues are also discussed in `hashes/README.advancedtopics.md`.

For the purposes of this walkthrough, and additional examples in other hash-related
READMEs, let's say you're making a pair of hashes that you want to call WackyHash64
and WackyHash128, and that you plan on them being distributed with SMHasher3. To get
things moving quickly, you'll only start with the 64-bit version and add the 128-bit
version later.

Starting with the boilerplate
-----------------------------

To add a new hash function to be tested, first see if its hash family already exists
in `hashes/`. If it does, then just add it to that family's file. Since WackyHash
doesn't exist yet, and there is some boilerplate code that is needed to integrate
into SMHasher3, it is probably best to start with a copy of either the
`hashes/EXAMPLE-mit.cpp` file (if you want your code to be MIT-licensed, as is
common) or `hashes/EXAMPLE.cpp` file (for any licensing you wish).

Copy the `EXAMPLE` cpp file of your choosing to the name of your hash or hash family,
making sure that the new filename starts with a lower-case letter, doesn't refer to
any bit widths, and has a suffix of `.cpp`:
```
cd hashes
cp EXAMPLE.cpp wackyhash.cpp
```

Then add the filename to the list in `hashes/Hashsrc.cmake`:
```
....
  hashes/murmur_oaat.cpp
  hashes/x17.cpp
  hashes/wackyhash.cpp
)
```

Filling in basic info
---------------------

There are a few things in `wackyhash.cpp` to fill out, all of them marked with three
hash (`#`) symbols. If you don't know what license you want to use and/or don't know
what URL will be the home for WackyHash, then those things can be skipped for now.

SMHasher3's guidelines for hash names are found in `hashes/README.md`. Because you
read that, you know that your hashes are going to be named "WackyHash-64" and
"WackyHash-128" in SMHasher3, and that the `REGISTER_HASH()` calls will need to look
like `REGISTER_HASH(WackyHash_64, .....)` and `REGISTER_HASH(WackyHash_128, .....)`.

While adding a hash of any fixed output size will work without errors, the testing
side of SMHasher3 only supports an explicit list of hash output widths. The list can
be found as the HASHTYPELIST variable in `util/Instantiate.h`. Currently, the list of
testable bit widths is: 32, 64, 128, 160, 224, 256.

Choices for the `src_status` enum can be found in the `class HashFamilyInfo`
definition in `include/common/Hashinfo.h`. If you are not sure which one is best,
just choose `HashFamilyInfo::SRC_UNKNOWN`.

Here's what the file might look like after this step:
```cpp
/*
 * WackyHash
 * Copyright (C) 2022 Robin Smith
 *
 * ###YOURLICENSETEXT
 */
....
//------------------------------------------------------------
template <bool bswap>
static void WackyHash64( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t hash = 0;
    PUT_U64<bswap>(hash, (uint8_t *)out, 0);
}

//------------------------------------------------------------
REGISTER_FAMILY(WackyHash,
   $.src_url    = "###YOURREPOSITORYURL",
   $.src_status = HashFamilyInfo::SRC_ACTIVE
 );

REGISTER_HASH(WackyHash_64,
   $.desc            = "An example hash for demo purposes",
....
   $.bits            = 64,
....
   $.hashfn_native   = WackyHash64<false>,
   $.hashfn_bswap    = WackyHash64<true>
 );
```

Doing a test build
------------------

Now build or rebuild SMHasher3 and make sure your hash is listed:
```
$ cd ../build
$ make -j4
[  1%] Generating Hashrefs.cpp
[ 27%] Built target SMHasher3Tests
[ 27%] Built target SMHasher3Version
Scanning dependencies of target SMHasher3Hashlib
[ 28%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/Hashrefs.cpp.o
[ 29%] Building CXX object CMakeFiles/SMHasher3Hashlib.dir/hashes/wackyhash.cpp.o
[ 30%] Linking CXX static library libSMHasher3Hashlib.a
[ 97%] Built target SMHasher3Hashlib
[ 98%] Linking CXX executable SMHasher3
[100%] Built target SMHasher3
$ ./SMHasher3 --list | grep Wacky
WackyHash-64                64          An example hash for demo purposes
$
```

Yay, it worked! You can even see how well a hash of "always return 0" performs:

```
$ ./SMHasher3 wackyhash-64
-------------------------------------------------------------------------------
--- Testing WackyHash-64 "An example hash for demo purposes"

[[[ Sanity Tests ]]]

Verification value LE 0x00000000 ...... INSECURE (should not be 0)
Running sanity check 1       .......... PASS
Running sanity check 2       . flipped bit 0, got identical output: FAIL  !!!!!
Running append zeroes test   . FAIL  !!!!!
Running prepend zeroes test  . FAIL  !!!!!
Running thread-safety test 1 .......... PASS
Running thread-safety test 2 .......... PASS
^C
```

Unsurprisingly, it doesn't do well at all. You probably want your hash to be more
sophisticated than "just return a constant". `:)`  So how should you do that?

Coding a hash function, the basics (short version)
==================================================

If you are especially eager to just dive right in to coding your hash, I'll cover the
highlights in simple sentences. A normal-length version of this basic info can be
found below or in other README files in `hashes/`.

- All code will be compiled as C++11 only. ASM statements in them are OK.
- Fixed-width integer types are guaranteed to be available.
   - They **must** be used to hold input and output data as well as intermediate hash
     values.
   - They should be used generally.
- Hash implementations are passed the seed value as a `seed_t`.
   - The most common way of using that is to simply cast it to a `uint64_t` and treat
     it like any usual integer seed.
   - More complex seeding scenarios are covered in `README.advancedtopics.md`.
- Always use SMHasher3's `GET_U`* and `PUT_U`* functions to convert between data in
  memory and integers.
- Always use SMHasher3's integer-rotation, popcount, clz, and byteswapping functions.
   - They are documented below. Don't reimplement them for your hash. Do wrap them if
     you like.
   - Never pass invalid values to these functions.
- If your hash wants intrinsics, just `#include "Instrinsics.h"`. It handles x86-64,
  ARM, and PPC already.
   - Vector byteswapping routines are also made available.
   - If it doesn't meet your needs, please enhance it so it can be used for everyone.
   - For more on intrinsics, including AES intrinsics, see `README.advancedtopics.md`.
- If your hash wants extended-length integer multiplication and/or addition, use
  `#include "Mathmult.h"` and the functions inside it.
   - More details are in `README.advancedtopics.md`.
- Headers for `std::vector`, `std::set`, `printf()`, and `memcpy()` are already
  `#include`d.

Coding a hash function, the basics
==================================

Here is more detail on most of the above topics.

The SMHasher3-defined functions described below should be used instead of having the
hash implementation roll its own version of those functions. That said, it is totally
OK for your implementation to isolate use of the functions via wrapper
functions. This may make it easier to make a stand-alone version of your hash,
appropriate for publishing elsewhere. It is also fine to add to or optimize the
existing utility implementation collection.

C++11
-----

All code will be compiled as C++11 and must conform to that standard. A plain C
compiler will not be used. Hash implementaions that fully or partially use assembly
instructions are allowed, but only via `__asm__()` statements or the like; .asm files
or pre-compiled binaries are not allowed, and an assembler will not be directly
invoked by the build system.

If you would like your hash function to be distributed with the SMHasher3 project,
then there are further restrictions described in `CONTRIBUTING.md`. Importantly, it
means a portable, standard C++-only implementation must be available, with other
implementations being optional.

Use of intrinsic/vector instructions and routines for extended-length integer
operations are covered in `README.advancedtopics.md`.

Fixed-width integers
--------------------

Hashlib hashes are guaranteed to have the following fixed-width integer types
available to them:
- `int8_t`, `uint8_t`
- `int16_t`, `uint16_t`
- `int32_t`, `uint32_t`
- `int64_t`, `uint64_t`

If the compiler supports 128-bit integers, then `int128_t` and `uint128_t` will also
exist, and the preprocessor token `HAVE_INT128` will be defined.

These fixed-width types should be used generally, and **must** be used to hold input
and output data as well as intermediate hash values. This will avoid having
different hash results on different platforms, where things like `int` can have
different sizes and `char` may or may not be signed.

`ssize_t` and `size_t` are also guaranteed-to-exist types, but they are not
fixed-width. They should only be used for variables which refer to lengths of data.

Seeding
-------

`seed_t` is a another guaranteed-to-exist type that is at least 64-bits wide. It is
passed to hash implementations via SMHasher3's HashFn API, which you can see above in
the prototype for `WackyHash64()`.

SMHasher3 assumes that hashes take a seed value and use it to alter the mapping of
inputs to outputs. The most common way of using the seed value is to simply cast it
to a `uint64_t` and treat it like any other input integer.

If your hash can only act on 32 bits of seed value, then you need to inform SMHasher3
of this by setting `$.hash_flags = FLAG_HASH_SMALL_SEED` in your hash's metadata
block.

More complex seeding scenarios are covered in `README.advancedtopics.md`.

Tranferring between memory and integers
---------------------------------------

Most hashes are non-cryptographic, and generally don't really care about endianness
issues. If those statements are not correct for a hash you are implementing, then you
will need to also read the appropriate non-basic sections in
`hashes/README.latersteps.md`.

Either way, it's simplest and best to start with _always_ using SMHasher3's functions
to convert between data in memory and integer values, and use them only in
native-endianness mode (as shown, with the `false` template parameter) and don't
worry about any endianness issues or further use of C++ templates until later:
```cpp
uint64_t GET_U64<false>(const uint8_t * b, const uint32_t i);
uint32_t GET_U32<false>(const uint8_t * b, const uint32_t i);
uint16_t GET_U16<false>(const uint8_t * b, const uint32_t i);

void PUT_U64<false>(uint64_t n, uint8_t * b, const uint32_t i);
void PUT_U32<false>(uint32_t n, uint8_t * b, const uint32_t i);
void PUT_U16<false>(uint16_t n, uint8_t * b, const uint32_t i);
```

In all cases, `b` is the pointer to access, `i` is the *positive* offset from that
pointer, and `n` is the integer value to write. The offset parameter is there to help
you write clearer code, in case separating a base pointer from its offset helps with
that. You are perfectly free to move your base pointer and have the offset always be
0. In other words, the following code snippets are functionally identical:
```cpp
uint64_t result_1, result_2;
uint8_t * ptr;


PUT_U32<false>(result_1, ptr, 0);
PUT_U32<false>(result_2, ptr, 4);

/*  ^^^ is identical to vvv  */

PUT_U32<false>(result_1, ptr, 0);
PUT_U32<false>(result_2, ptr + 4, 0);
```

I was conflicted about making the offset parameter have a default value of 0 so it
can be omitted, but I decided it was clearer for it to always exist. Feedback on this
is welcome.

Much more info on byte-swapping and endianness can be found in
`hashes/README.latersteps.md`.

Integer rotation
----------------

The following functions are guaranteed to be defined:
- ROTL32(value, rotation_amount)
- ROTR32(value, rotation_amount)
- ROTL64(value, rotation_amount)
- ROTR64(value, rotation_amount)

Note that these functions are deliberately unsafe, to allow for not needing to include a
test and branch in cases where the hash implementor knows that invalid values cannot
be passed to them. If your code might pass rotation amounts that are either 0 or
greater-than-or-equal-to the value width (32 or 64), then your code must check for
and handle those invalid rotation amounts before calling any of those
functions. Passing invalid values to these functions may lead to Undefined Behavior.

Other integer functions
-----------------------

A function called `popcount4(value)` will return the number of bits set in a 32-bit
integer value (also known as the population count), and a function called
`popcount8(value)` will do the same for 64-bit integer values.

A function called `clz4(value)` will return the number of leading zero bits in a
non-zero 32-bit integer value, and a function called `clz8(value)` will do the same for
non-zero 64-bit integer values. Passing a zero to either `clz4()` or `clz8()` may
lead to Undefined Behavior.

A number of extended-length integer multiplication and/or addition functions are
available via `#include "Mathmult.h"`. More details are in
`README.advancedtopics.md`.

Other C/C++ functions
---------------------

The `<cstdio>` and `<cstring>` headers are already included, so that `printf()` and
`memcpy()` are both automatically available.

`<vector>` and `<set>` are also both already included.

That's all the basics!
----------------------

After that the rest of `wackyhash.cpp` (or whatever you named your file) is your
playground, and you can largely implement your hash as you like. That said, I am
going to reiterate the usual software development advice to first get your code
working, and only _then_ start worrying about performance.

The `hashes/README.latersteps.md` document can be covered after you are closer to the
polishing stages of devloping your hash function, if you like, or you can read it now
if you aren't overwhelmed. If you are porting an already-developed function to
SMHasher3, then it also probably is also good to cover sooner rather than later.

`hashes/README.advancedtopics.md` contains a bunch of different sections covering
other, more-complicated things that hash implementations might want or need to do,
often with examples. Again, feel free to read it now or wait until later. You can
always just refer to specific sections in there as you get stuck, or want to do
something specific, or run into mysterious errors or test failures.
