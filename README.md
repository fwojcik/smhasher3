```
   _____ __  __ _    _           _              ____
  / ____|  \/  | |  | |         | |            |___ \
 | (___ | \  / | |__| | __ _ ___| |__   ___ _ __ __) |
  \___ \| |\/| |  __  |/ _` / __| '_ \ / _ \ '__|__ <
  ____) | |  | | |  | | (_| \__ \ | | |  __/ |  ___) |
 |_____/|_|  |_|_|  |_|\__,_|___/_| |_|\___|_| |____/
=======================================================
```

Test Results
------------

If you are interested in the **[latest hash test results](results/README.md)**
(currently from SMHasher3 `SMHasher3 release-`), they are in the
`results/` directory.

Summary
-------

SMHasher3 is a tool for testing the quality of [hash
functions](https://en.wikipedia.org/wiki/Hash_function) in terms of their
distribution, collision, and performance properties. It constructs sets of hash keys,
passes them through the hash function to test, and analyzes their outputs in numerous
ways. It also does some performance testing of the hash function.

SMHasher3 is based on [the SMHasher fork maintained by Reini
Urban](https://github.com/rurban/smhasher), which is in turn based on
[the original SMHasher by Austin
Appleby](https://github.com/aappleby/smhasher/). The commit history of
both of those codebases up to their respective fork points is
contained in this repository.

The major differences from rurban's fork are:
- Fix several critical bugs
- Several new tests and test methods added
- Significant performance increases
- Report on p-values for all supported tests
- Detailed reporting on hashes when test failures occur
- Better statistical foundations for some tests
- Overhauled all hash implementations to be more consistent

Additional significant changes include:
- Many fixes to threaded testing and hashing
- More consistent testing across systems and configurations
- More consistent and human-friendlier reporting formats
- Common framework code explicitly sharable across all hashes
- Flexible metadata system for both hashes and their implementations
- Major progress towards full big-endian support
- Support of more hash seed methods (64-bit seeds and ctx pointers)
- Ability to supply a global seed value for testing
- Test of varying alignments and buffer tail sizes during speed tests
- Refactored code to improve maintainability and rebuild times
- Reorganized code layout to improve readability
- Compilation-based platform probing and configuration
- Consistent code formatting
- More explicit license handling
- Fully C++11-based implementation

Current status
--------------

As of 2025-10-16, I consider SMHasher3 to have been fully released.

From this point, the plan is to have two branches: "main" and "dev". The
main branch will have new hashes and updated hashes added to it as I am
able. The dev branch will have those changes added to it also. Feature
development will happen only on the dev branch, and those changes will
occasionally get added to main, when some chunk of functionality is
complete.

There won't be explicit release versioning. Instead, the version string has
been updated to include the commit date of the last commit.

This code is compiled and run successfully on Linux x64, arm, and powerpc
using gcc and clang quite often. Importantly, I do not have the ability to
test on Mac or Windows environments. It has been compiled successfully
using MSVC and clang-cl in the past; efforts are made to ensure this
remains the case, but some things may slip through. The goal is to support
all of the above, and while the CMake files Should Just Work(tm), MSVC in
particular has its own ideas about some corners of the various specs. So
reports of success or failure are appreciated, as are patches to make
things work.

How to build
------------

- `mkdir build`
- `cd build`
- `cmake ..` or `CC=mycc CXX=mycxx CXXFLAGS="-foo bar" cmake ..` as needed for your system
- `make -j4` or `make -j4 all test`

How to use
----------

- `./SMHasher3 --tests` will show all available test suites
- `./SMHasher3 --list` will show all available hashes and their descriptions
- `./SMHasher3 <hashname>` will test the given hash with the default set of test
  suites (which is called "All" and is most but not literally all of them)
- `./SMHasher3 <hashname> --extra --notest=Speed,Hashmap` will test the given hash
  with the default set of test suites excluding the Speed and Hashmap tests, with
  each run test suite using an extended set of tests
- `./SMHasher3 <hashname> --ncpu=1` will test the given hash with the default set of
  test suites, using only a single thread
- `./SMHasher3 --help` will show many other usage options

Note that a hashname specified on the command-line is looked up via
case-insensitive search, so you do not have to precisely match the names
given from the list of available hashes. Even fuzzier name matching is
planned for future releases.

If SMHasher3 found a usable threading implementation during the build, then
the default is to assume `--ncpu=4`, which uses up to 4 threads to speed up
testing. Not all test suites use threading. While all included hashes are
thread-safe as of this writing, if a non-thread safe hash is detected then
threading will be disabled and a warning will be given. If no usable
threading library was found, then a warning will be given if a `--ncpu=`
value above 1 was used.

Adding a new hash
-----------------

To add a new hash function to be tested, either add the implementation to an existing
file in `hashes/` (if related hashes are already there), or copy `hashes/EXAMPLE.cpp`
to a new filename and then add it to the list of files in `hashes/Hashsrc.cmake`.

Many more details can be found in `hashes/README.addinghashes.md`.

P-value reporting
-----------------

This section has been placed near the front of the README because it is the
most important and most visible new feature for existing SMHasher users.

The tests in the base SMHasher code had a variety of metrics for reporting
results, and those metrics often did not take the test parameters into
account well (or at all), leading to results that were questionable and hard
to interpret. For example, the Avalanche test reports on the worst result
over all test buckets, but tests with longer inputs have more buckets. This
was not part of the result calculation, and so longer inputs naturally get
higher percentage biases (on average) even with truly random hashes. In
other words, a bias of "0.75%" on a 32-bit input was not the same as a bias
of "0.75%" on a 1024-bit input. This is not to call out the Avalanche test
specifically; many tests exhibited some variation of this problem.

To address these issues, SMHasher3 tests compare aspects of the
distribution of hash values from the hash function against those from a
hypothetical true random number generator, and summarizes the result in the
form of a [p-value](https://en.wikipedia.org/wiki/P-value).

P-values are probabilities: they are numbers between 0 and 1. Their values
are approximately the probability of a true RNG producing a test result
that was at least as bad as the observed result from the hash
function. Smaller p-values would indicate worse hash results.

However, these p-values quite often end up being very small values near
zero, even in cases of good results. Reporting them in their decimal form,
or even in scientific notation, would probably not be very useful, and
could be very difficult to compare or interpret just by looking at them.

In SMhasher3, these p-values are reported by a caret symbol (^) followed by
the p-value expressed in negative powers of two. For example, if it is
determined that a true RNG would be expected to produce the same or a worse
result with a probability of 0.075, then SMHasher3 would compute that that
p-value is about 2^-3.737. It would then round the exponent towards zero,
simply discard the sign (since probabilities are never greater than 1, the
exponent is always negative), and finally report the p-value as "^ 3".

Therefore, *smaller* p-values (which indicate worse test results) result in
*larger* numbers when reported using caret notation. You can think of the
values in caret notation as indicating how *improbable*, and thus worse,
the test result was. For example, "^50" could be interpreted as "there is,
at best, only a 1 in 2^50 chance that an RNG would have produced a result
as bad as the hash did".

The p-value computations only care about the likelihood of *bad* results
(e.g. more collisions than an RNG would produce). Test results that are
*better* than a typical RNG result but would still be outliers from a
purely statistical point-of-view, such as seeing no or very few collisions
when at least some would be expected, do not produce extreme p-values. In
statistics terms, the p-values are one-tailed when appropriate, instead of
always being two-tailed.

The p-value computations also take into account how many tests are being
summarized, which can lead to unintuitive results. As an example, here are
some lines from a single batch of test keys:

```
Keyset 'Sparse' - 256-bit keys with up to 3 bits set - 2796417 keys

Testing all collisions (high  32-bit) - Expected      910.2, actual        989  (1.087x) (^ 7)

Testing all collisions (high 20..38 bits) - Worst is 32 bits: 989/910           (1.087x) (^ 3)
```

The middle line reports ^7 for seeing 989 collisions when 910 were
expected, and the last line reports ^3 for what seems like the same
result. This is due to the fact that the middle line is reporting that as
the result of a single test, and the last line is reporting that as the
worst result over 19 tests. It's much more likely to see a result at least
that bad if you have 19 tries to get it than if you just had 1 try, and so
the improbability is much lower. Indeed, 19 is around 2^4, and the first
reported result is about 4 powers of 2 worse than the second (7 - 3), as
expected.

A true RNG would generally have about twice as many ^4 results as ^5
results, and twice as many ^3 results as ^4 results, and so on. However,
many of the statistical formulas used by SMHasher3 only produce **bounds**
on the result probabilities, and sometimes those bounds are not very tight
and/or get significantly worse for higher-likelihood results. The formulas
used were typically chosen for greater accuracy in failure / long-tail
cases. Further, some tests are very unlikely to get even a single "hit",
and so a result of zero hits can't really give a precise p-value. For those
reasons and more, you should expect to see more lower numbers than the
power-of-2 relationship would imply, and you will see _many_ more ^0
results than you would expect mathematically.

All non-deprecated tests in SMHasher3 support p-value reporting. These
p-value results are the only numbers used by SMHasher3 to determine
pass/warn/fail status for tests. And since the really, truly most important
result of testing is "does a hash pass or fail", and perhaps noting how
close to the line it is, the precise p-value is not very important. The
reported values are always lower bounds on the actual p-value exponents
(the "true" result could be worse than reported but never better), so any
failures reported should be genuine.

The precise cutoffs for test warnings and failures can be found at the top
of [util/Reporting.cpp](util/Reporting.cpp), in the variables
`FAILURE_PBOUND` and `WARNING_PBOUND`. As of this writing, a warning is
given at ^16, and a failure is given at ^20. Those bounds might seem
surprisingly high, but that is because there are so many tests. Since a
typical full SMHasher3 test run consists of about 16,000 tests, even
testing a cryptographic-quality hash function is expected to produce a ^14
event every run on average (-log2(1/16,000) =~ 13.966) (this calculation
overstates things because test failures are far from independent). The
failure threshold was chosen to correspond to be less than a 1% chance of
false test failure, and the warning threshold was arbitrarily chosen to
make them about 16 times as likely as failures.

For the statistics folks, this is a correction for the [Multiple
comparisons
problem](https://en.wikipedia.org/wiki/Multiple_comparisons_problem), and
the correction used is slightly weaker than what the [Bonferroni
correction](https://en.wikipedia.org/wiki/Bonferroni_correction) would call
for. This should be OK since SMHasher3 uses a large number of tests, and
failures are positively correlated. Maybe the Harmonic mean p-value
procedure will be used in the future.

A final summary table of p-values in caret notation is currently produced
after a full run. This table can be useful to see a summary of how close to
the pass/fail line a particular hash is, or to see if some suspicious
patterns (e.g. many warning values) exist. It is important to remember that
this table should **NOT** be used to compare hashes. SMHasher3 focuses on
*broad* testing to find classes of bad behavior in hashes. It doesn't do
nearly the depth of testing to fairly compare the quality of hash outputs
across candidate functions, regardless of any particular definition of
"quality", which may also vary across perspectives.

Performance
-----------

A number of significant performance improvements have been made over the base
SMHasher code. Here are some runtime comparisons on my system (AMD Ryzen 9 3950X, 1
or 4 isolated CPUs, all with boost disabled and pinned to 3500 MHz for timing
consistency, gcc 9.3, Slackware 14.2, SMHasher3 beta1, smhasher-rurban b116571):

| Test Name   | SMHasher  | SMHasher3 | Delta | SMHasher  | SMHasher3 | Delta |
|:------------|----------:|----------:|:-----:|----------:|----------:|:-----:|
| BadSeeds    |      996s |      311s |  -69% |     1194s |       78s |  -93% |
| Window      |      935s |      341s |  -64% ||||
| Avalanche   |      720s |       92s |  -87% |      810s |       23s |  -97% |
| Sparse      |      478s |      151s |  -68% ||||
| TwoBytes    |      292s |       79s |  -73% ||||
| Diff        |      263s |      171s |  -34% |      263s |       43s |  -84% |
| Permutation |      256s |       98s |  -62% ||||
| Popcount    |      163s |       20s |  -87% |       90s |        5s |  -94% |
| BIC         |      152s |        9s |  -94% |      152s |        3s |  -98% |
| Text        |       65s |       20s |  -69% ||||
| PerlinNoise |       47s |       30s |  -36% ||||
| Prng        |       33s |        8s |  -76% ||||
| DiffDist    |       11s |       14s |  +27% ||||
| Cyclic      |        8s |        2s |  -75% ||||
| Zeroes      |        5s |        5s |    0% ||||
| Seed        |        5s |        7s |  +40% ||||
| Sanity      |        3s |       <1s |  -90% ||||

Since Gitlab's flavor of markdown only supports one header row, the first 3 columns
of numbers are for 1 CPU, and the last 3 columns are for 4 CPUs on tests which
support threading in SMHasher3.

The SMHasher results are somewhat confusing. The BadSeeds test is threaded but takes
more wall clock time than the unthreaded version. I attribute this to a large amount
of system CPU time that the threaded version takes that the unthreaded version
doesn't. I don't see any obvious synchronization primitives being used or intentional
data sharing across threads, so I am unsure of its source. The Avalanche test is not
threaded in SMHasher, but it takes more wall clock time than the unthreaded version
regardless, which I have no good hypothesis about. Both of these results are
repeatable and consistent, though, so I am keeping them in the table.

After beta1, the test methodology in SMHasher3 diverges quite a lot from
SMHasher, and so direct performance comparisons are less meaningful. But to
give one data point, on the above system a complete run of SMHasher3 beta2
on a fast hash function (wyhash) with --extra but without BadSeed testing
takes 1578 seconds and finds 40 failing tests, while smhasher-rurban takes
2860 seconds and finds 2 failing tests.

In the future, I plan on publishing some explicit data from performance
profiling, to show the places that I think are the best to look for more
performance gains, or at least would have the highest impact.

A number of additional tests could be augmented to use threads.

It would also be theoretically possible to change testing to use a work
queue and then have a thread pool of workers. However, I think that this
would require some way of wrapping all of the `printf()` calls in the
tests, since stdout is a global object and doesn't exist per-thread, and
this would almost certainly require a lot more memory at runtime, since
tests could not generally share memory structures (such as bucket counts)
across threads. I don't like either of those things, so I'm not sure that
thread pools are a good approach. I'd be very open to suggestions for
working around those issues!

Goals and non-goals
-------------------

The priority of SMHasher3 is to be the best black-box test utility for hash
function quality. Other important goals are:

- Support as many platforms as practical
- Have identical results on those platforms
- Test all valid variations on a hash function
- Be as fast as possible, given those constraints
- Allow for comparisons between hash function cores, both within and across hash
  function families, to facilitate learning about hash internals
- Provide tools for more quickly iterating on hash functions
- Be easily expandable, both for tests and hash function infrastructure
- Have a consistent, readable code base
- Be explicit about code licensing
- Have human-friendly reporting

SMHasher3 also does performance testing, and this is expected to be worked on and
expanded in the future. However, performance testing fidelity will always come second
to functional testing. The goal of the performance testing in SMHasher3 will be to
provide effective relative comparisons of hash functions, not absolute performance
ratings or measurements.

There are some other things that SMHasher3 is explicitly NOT trying to do:

- Be an authoritative or complete repository of hash implementations
- Use hash authors' implementation code with as few changes as possible
- Provide a numeric score for overall hash quality
- Be a final arbiter of which hash functions are "best"

Changes from base SMhasher
--------------------------

See `Changelog.md` for a detailed list of the differences going from the
forked copy of SMHasher to SMHasher3.

Endianness support and terminology
----------------------------------

One of the long-term goals for SMHasher3 is full support of both big- and
little-endian systems. Currently this is, in some sense, a little bit more
than half complete. Every hash implementation computes results for both
endiannesses, regardless of system endianness. Most of the testing code is
not yet endian-independent, however, and so test results will currently vary
greatly depending on the system.

For hash authors, this represents a tiny bit of extra work, but it can be put off
until late in hash development, and is not very difficult to add.

Hashes which have explicit specifications of endian-independent hash values (mostly
cryptographic hashes; e.g. SHA-1 needs to return the same result for the same inputs
no matter the system) have either what is referred to in SMHasher3 as their
"canonical" endianness (aka "CE", which matches their spec) and their "non-canonical"
endianness (aka "NE", which doesn't).

Most non-cryptographic hashes have no such requirement, and are more interested in
the speed of not having to do byteswapping on their input and output data than they
are in hash result consistency across platforms. These hashes have what SMHasher3
refers to as "little-endian" and "big-endian" results.

The user can request that hashes compute results for big- or little-endianness
explicitly, or they can request system-native or system-nonnative endianness, or they
can request the "default" endianness (which is "canonical" if that exists or
"system-native" if not) or "nondefault" (whichever one "default" isn't). This is done
through the `--endian` command-line option.

Each hash itself is usually not concerned with this, though! It is only concerned
with "do inputs and outputs have to byteswapped, or not?", and the SMHasher3
framework will use the appropriate implementation based on a combination of the
user's request, the hash's metadata, and the detected endianness of the system.

While I am very happy with this goal, and mostly happy with the hash-side
implementation of things, I'm less sure that the user-side is good enough. Please let
me know if you find something confusing.

Hash verification codes
-----------------------

Currently, the algorithm for computing hash verification codes is unchanged from
the base SMHasher. Many hashes' verification codes are also unchanged, but a number
have changed for various reasons, and some have been added or removed; see `Changelog.md`
for specifics. This should help verify that the hash implementations didn't change
unexpectedly when they were ported.

Since SMHasher3 supports 64-bit seeds and the current algorithm for computing
verification codes does not exercise even all of the low 32 seed bits, I expect that
the algorithm will change in the future. There are a number of complications to that,
and it will likely require coordination with the larger community.

A stand-alone vanilla C99 program for computing hash verification codes outside of
SMHasher3 is in `misc/hashverify.c`. To the extent possible, I use this to verify that
any hash (re-)implementation in SMHasher3 produces the same results as the published
reference implementation.

VCodes
------

The original SMHasher code base had some infrastructure for what it called VCodes,
although they were not implemented. The intention seemed to be that they would be
short signatures of all of the hash inputs and outputs as well as the test
results. SMHasher3 has implemented this, though it uses a somewhat different
framework internally.

I've kept the name "VCode", but it is important not to confuse these with the
"verification codes" from the previous section. They are unrelated features, except
for the fact that they both are intended for human use to quickly verify that
SMHasher3 is functioning the same way in different configurations.

If the `--vcode` command-line option is used, then these signatures are computed and
reported on. A final summary "verification value" is computed from these 3 component
VCode signatures, and is reported on the last line of output. They are an easy way to
compare complete operation across runs and/or platforms, without having to compare
result-by-result. There is a small but noticeable performance hit when this is
enabled. If it is not enabled, then the VCode component output line is no longer
emitted, but the final summary code is (with a value of 1 to indicate it was not
computed), to keep output lengths consistent.

The performance-oriented tests do not contribute to VCode calculations. Note that
even input VCodes will vary by hash width.

Global seeds
------------

Most of the tests in SMHasher3 don't vary the hash seed values, and so use a global
seed value which defaults to 0. A different value can be specified via the `--seed=`
command-line option. This allows for a single hash to be tested multiple times, which
can show things like if a given result is a fluke or is consistent across runs.

Tests which do vary the seed values generally ignore this global seed value.

If a hash implementation only takes a 32-bit seed and the given global seed value
exceeds 32-bit representable values, then the seed value is truncated and a warning
is emitted.

Code organization
-----------------

There are 2 main parts of the codebase, and they are largely independent of each
other.

The first is Hashlib, which is a collection of hash function implementations and
their metadata, some shared routines for things which hash functions frequently do,
as well as some code for querying and managing the collection.

The second is Testlib, which is a collection of code and utility functions to
generate sets of keys to be hashed and to analyze the lists of hash results.

There is also main.cpp, which is the main SMHasher3 program and ties the whole thing
together.

Hashlib hash implementations are under hashes/. There is one .cpp file, starting with
a lowercase letter, per family of hash functions. There may also be a directory with
the same name as the base name of the .cpp file it belongs to
(e.g. `hashes/blake2.cpp` has a `hashes/blake2/` directory). This directory can
contain whatever other data or code that hash family needs. The most common use of
that directory is to contain a set of .h files which each contain a
separately-optimized version of the same core hash routines (e.g. a generic version,
an SSE2+ version, an AVX+ version, and an ARM version) which are included as needed
in the .cpp file.. More details about hash naming and reasoning on certain
implementation aspects can be found in `hashes/README.md`.

The rest of the Hashlib code is under `lib/`, and the interface header files are
under `include/`. `include/hashlib/` files are only exposed to the hash functions,
and `include/common/` files are exposed globally.

Testlib code lives under `tests/`, where each test suite has one .cpp file starting
with an uppercase letter. Common testing code lives under `util/`, where each group
of routines has one .h file and possibly one .cpp file, both also starting with an
uppercase letter.

There is some build-related code in `hashes/` in files starting with uppercase
letters, and quite a lot in the `platform/` directory. The `misc/` directory contains
other code which is related to SMHasher3 but is not part of the main program.

It is very common in C++ to have considerable amounts of code in header (.h)
files. While there can be good reasons for this, I strongly prefer having most code
in .cpp files where it will be compiled only once. SMHasher3's test code is generally
templated based on the output width of the hash function being tested. Ordinarily
this would mean that the code would need to be in header files, so that it can be
instantiated based on the way it is called. However, since the complete list of hash
output types is known a priori, SMHasher3 can keep the code in .cpp files by
explicitly instantiating the appropriate versions there. See `util/Instantiate.h` for
the gory details.

Build system
------------

While SMHasher3 keeps the CMake foundation, the build system is very different from
the base SMHasher code. The short version is that feature detection is done during
the CMake configuration step by attempting to compile possible implementations of
platform-specific features and then caching the results. Header files containing the
detection results are generated in the build directory, and these are included by the
rest of the code.

The primary file generated this way is `build/include/Platform.h`. You can see an
example of what a rendered `Platform.h` file might look like in
`platform/Platform.h.EXAMPLE`. `build/include/Timing.h` is the other generated header
file, and similarly you can see an example of what a rendered `Timing.h` file might
look like in `platform/Timing.h.EXAMPLE`.

In the worst case, since all data is kept in CMake's cache, detection state can be
reset by removing the build directory contents, or by building in a new, clean
directory.

More technical details and some discussion of the rationale behind this are in
`platform/README.md`.

Notes on licensing
------------------

Files under hashes/, include/, lib/, and misc/ may have a variety of
different different licenses, such as BSD 2, zlib, GPL3, public
domain/unlicense/CC0, or MIT. Each file should have its license terms
clearly stated at the top.

Files under results/ have the Creative Commons Attribution 4.0
International license (CC BY 4.0).

Files under util/parallel_hashmap/ have the Apache 2 license.

All other files in this distribution (including, but not limited to,
main.cpp and files in platform/, tests/, and util/) are licensed under
the terms of the GNU General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your
option) any later version.

I would prefer to have the above information in LICENSE, but Gitlab
offers no way to manually set an advertised license, and so I need
to rely on its auto-detection to find "GPL3" (which is at least
closest to reality), so it lives here instead. `:-/`

The original SMHasher's README says:

> SMHasher is released under the MIT license.

although there is no LICENSE file, nor are there any per-file license
or copyright notices in the test code.

rurban's SMHasher's LICENSE file says:

> smhasher itself is MIT licensed.
>
> Plus copyright by the individual contributors.
> Note that the individual hash function all have different licenses,
> from Apache 2, BSD 2, zlib, SSL, GPL, public domain, ... to MIT.

and again there are no per-file license or copyright notices in the
test code.

One of the goals of this fork is to be much more clear and explicit
about code licensing. This proved to be trickier than expected. After
considering several options and consulting with an attorney, I decided
that the best option was to explicitly distribute the SMHasher3
testing code under the GPL.

Since some of the code linked in (at least 5 different hash
implementations) to SMHasher in rurban's fork is under the GPL, the
whole of the project must also be distributable under the
GPL. Further, the MIT license explicitly allows sublicensing. Having
the test code be explicitly under the GPL also should increase the
odds that any new hash implementation being added to this project
would not require any relicensing of the test code.

This decision was not taken lightly, as I would prefer to keep the
original authors' license when possible, as was done with the
modifications made to the hash implementations. I believe this to have
been the least bad option to get the improvements in SMHasher3 out to
the world.

The LICENSE file of this project has been updated to reflect these terms. I have
added the GPL license text to many of the files that are covered by it, and I have
added the text of the original MIT license, as well as a list of contibutor
copyrights, explicitly to much code that is being distributed here under the GPL, in
order to comply with the MIT license terms of the originals. If I have somehow missed
an attribution for some of the forked code, please do not hesitate to reach out so I
can fix it!

Some code in SMHasher which seemed to be incompatible with GPL3 was not
forked. Finally, other code files which are being distributed under non-GPL licenses
will have their license added to them, to help remove confusion.

Links to cool software, used to develop SMHasher3
-------------------------------------------------

* Bit Twiddling Hacks [https://graphics.stanford.edu/~seander/bithacks.html]
* GNU parallel [https://www.gnu.org/software/parallel/]
* Hedley [https://nemequ.github.io/hedley/]
* Portable snippets [https://github.com/nemequ/portable-snippets]
* FFT [https://github.com/NFFT/nfft]
* Uncrustify [https://github.com/uncrustify/uncrustify]
* Valgrind [https://valgrind.org/]
* kcachegrind [https://github.com/KDE/kcachegrind]
* Parallel Hashmap [https://github.com/greg7mdp/parallel-hashmap/]
* MPFR (Multiple Precision Floating-Point Reliable Library) [https://www.mpfr.org/]
* MPFI (Multiple Precision Floating-Point Interval Library) [https://directory.fsf.org/wiki/MPFI]
* YAWL (Yet Another Word List) [https://github.com/elasticdog/yawl]
* Slackware Linux [http://www.slackware.com/]
* RMSBolt [https://gitlab.com/jgkamat/rmsbolt]
