[[_TOC_]]

Differences from beta2 to beta3
===============================

General changes
---------------
- Fixed some compilation problems on non-Linux platforms
- Fixed build consistency issue when removing hashes
- Fixed some UB and other problems on 32-bit platforms
- Many performance increases and memory-use reductions
- More testing aspects now support threading/using multiple CPUs
- RNG has been updated to Threefry, and RNG API has been completely rewritten
- External RNG test utility has been added
- Some code has been made more self-documenting
- Code is now compiled with "-Wall" on non-MSVC compilers
- Additional compiler warnings enabled
- Numerous small changes based on compiler warnings
- "make test" improved, and enabled on all platforms
- "C" locale is now explicitly set internally
- Many code cleanups and readability improvements
- Raw result .txt files moved to results/raw/

Testing changes
---------------
- Tests now display colliding and/or partially colliding hash inputs when
  failures are detected and --verbose is given on the command-line
   - This includes hash seed and key inputs, as well as hash value results
   - This also includes tests which test XORs of two hash results
   - This also includes lists of never-seen hash slice values
   - Some tests don't support this, as it wouldn't make sense to do so,
     such as Avalanche-based and BIC-based tests
- DiffDist test renamed to Bitflip
   - This is to more properly label all the so-called hash delta anaysis as
     "differential distribution
- BIC and SeedBIC tests have been reorganized
   - The same input data is now used for each input bit, to reduce
     memory usage and be consistent with other test suites
   - This may be altered again in the future
- Avalanche and SeedAvalanche tests use better p-value algorithm
   - The previous bound was not very tight in practice, so a better
     Binomial approximation was added
- Intra-test overlap due to random chance has been eliminated
   - This is via the new RNG API for generating random sequences
   - This also allows for better DiffDist and SeedDiffDist testing
- A new Text test has been added
   - It hashes the string representation of numbers from 0 to 9,999,999,
     both with and without commas
- SeedSparse test is now separated out from the Seed test
- Reporting code is now separated out from Analysis code
   - There will likely be more minor changes like this in the future
- BadSeeds reporting has been improved significantly
- SanityTest error messages have been improved
- SpeedTest fidelity has been improved
- Sparse test now reports set bit count in summaries
- HashMap test now acts more like the purely performance test that it is
- Test warning and failure thresholds have been tweaked to account for the
  added numbers of tests
- Expected collision estimation has been improved
- Layout of lines in --verbose mode has been improved
- Plots of per-bit results have been improved and made consistent
   - This includes bias graphs in Avalanche-based and BIC-based tests, as
     well as hash bucket distribution graphs in Keyset-based tests
- Some progress indicators have been made more granular
- Some display errors have been fixed

General hash changes
--------------------
- Mathmult functions now in their own MathMult:: namespace
- Mathmult implementations improved and made consistent
   - Should produce faster code in hashes which use them
   - Clang ASM workarounds now exist for all Mathmult functions
     which need them
- Add enum for HashInfo::Seed() to better self-document the API
- Handled hashes with SeedFixFns more consistently in some tests

Specific hash changes
---------------------
- abseil-lowlevel, abseil32, abseil64-llh, abseil64-city
   - Added
- aesnihash
   - Renamed to aesnihash-majek
- aesnihash-peterrk
   - Added
- aesrng
   - Simplified somewhat, and fixed some threading issues
- beamsplitter
   - Made byteswapping changes be clearer
- blake2
   - Fixed compilation for SSE2 implementation
- chaskey
   - Improved readability of implementation
- cityhash
   - Updated to 1.1.1
- discohash
   - Many updates from hash author
- farsh
   - Fixed compilation on 32-bit platforms
- floppsyhash
   - Fixed compilation on non-UNIX platforms
- fnv-1a-128
   - Added
- fnv-mulvey
   - Added
- hasshe2
   - Altered tweaked version to be streamable
- highwayhash
   - Added
- jodyhash
   - Updated to 7.3
- khashv
   - Updated to latest revision
   - Fixed compilation on 32-bit platforms
- komihash
   - Updated to 5.7
- multiply_shift
   - Fixed operation on 32-bit platforms
- nmhash
   - Fixed operation on 32-bit platforms
- pearson
   - Fixed operation on 32-bit platforms
- pengyhash
   - Updated to 0.3
- perl-stadtx
   - Added
- perl-zaphod32, perl-zaphod32.sbox96, perl-zaphod32.sbox128.old, perl-zaphod32.sbox128
   - Added
- prvhash
   - Updated to 4.3.7
- pmp_multilinear
   - Hash has been temporarily disabled
- poly-mersenne
   - Replaced RNG with less buggy one
   - Added "degree 0" version for completeness
- polymurhash, polymurhash-tweakseed
   - Added
- rainbow
   - Added
- rainstorm
   - Added
- rust-ahash, rust-ahash.noshuf, rust-ahash-fb, rust-ahash-fb.nofold
   - Added
- rust-fxhash32, rust-fxhash64
   - Added
- siphash-2-4.folded, siphash-1-3.folded
   - Added
- tabulation
   - Replaced RNG with less buggy one
- t1ha
   - Fixed bug on ARM platforms
- wyhash
   - Updated to 4.2
   - Fixed endian issues
- xxh3
   - Fixed bug in AVX-512 implementation
   - Updated to 0.8.2

Differences from beta1 to beta2
===============================

Testing changes
---------------
- Many tests now also analyze the deltas (XORs) between hash values.
- Several test suites are now deprecated, and are no longer invoked by default.
- Reporting on peak collision count for 12- and 8-bit values has been
  disabled. Analysis shows that this added far more (reporting) noise than
  signal (new problems found).
- The BadSeeds test has been thoroughly reworked. It remains off by default.
- The BIC (Bit Independence Criteria) test now runs by default. It also can
  take advantage of threading, if available.
- The Sanity test now checks that changing the seed value changes the hash.
- The Text test now includes more variants of "FooXXXXBar" and testing of
  long strings with changes at either end.
- The TwoBytes test now checks more lengths.
- The DiffDist test now checks more lengths, and has had its reporting
  changed to only report the total number of failing bits and gives details
  on the single worst failing bit. All bits get a full report when
  --verbose is given
- Many other tests had their specific parameters tweaked.
- The following new tests have been added:
   - SeedAvalanche
   - SeedBIC
   - SeedBlockLen
   - SeedBlockOffset
   - SeedDiffDist
   - SeedZeroes
- Tweaked warning and failure p-value thresholds based on new number of tests.
- Test suites have been reordered, to group similar tests together and to
  try to have tests which are more likely to find unusual problems run
  earlier than they did before.

General hash changes
--------------------
- Added textual bad seed descriptions to hashes which have patterns of bad
  seeds that are not simple lists of specific ones.
- Added strings to hashes for describing which implementation was chosen at
  compile-time.

Specific hash changes
---------------------
- aquahash
   - Added.
- farsh
   - Added a tweaked version which changes what seems to be a bug. It
     appears that the author's intent was to include the hash length into
     a calculation, but a value of 0 was always used instead.
- khashv
   - Added.
- lookup3
   - Added a seedfix function.
- mx3
   - Updated to v3.
- murmurhash2
   - Added a seedfix function for MurmurHash2-64.int32.
- poly_mersenne
   - Fixed to be thread-safe.
- tabulation
   - Fixed to be thread-safe.
- xxh
   - Made XXH32 and XXH64 hashes output in canonical endianness.

Other changes
-------------
- Failures during platform detection now cause all the compiler errors to
  be displayed, to allow for troubleshooting more easily.
- Several GCC and CMake bugs are now worked around.


Differences from base SMhasher to SMHasher3 beta1
=================================================

Specific enhancements
---------------------
- P-values are generally used for reporting and pass/warn/fail detection
- Many performance enhancements
- Made significant strides towards full endianness support
- Made thread count a runtime-variable and command-line flag
- Added a significantly improved collision estimation function
- Made Permutation tests be data-driven, so new tests can be added easily
- Allowed hashes to take 64-bit seed values (API can be extended to larger widths if needed)
- Changed to a more-consistent hash naming scheme
- Made command-line hash naming more flexible
- Added extensible hash metadata system, to allow for future new per-hash data
- Refactored all hashes to use consistent APIs for:
   - fixed-width integer types
   - moving data between memory and integer variables
   - byteswapping
   - larger-than-64-bit math operations
   - seeding and initialization
   - producing results for both big- and little-endian systems
   - intrinsic includes
   - feature detection
- Added AES-based RNG "hash", to show what the results look like for high-quality
  random hash values
- Made test reporting and progress reporting more consistently fixed-width and
  human-friendly
- Added test and failure summary reporting when complete quality testing is done
- Reported keycounts consistently for all tests
- Reorganized code base so hashes and tests are separate, and chunks of functionality
  each have their own file
- Code has been reformatted to use a consistent coding style
- Made all code be C++11
- Removed hash implementation using binary object file!
- Ported ASM-only hash to C++
- Reworked #include file paradigm
- Overhauled build system completely
- Significantly improved rebuilding time
- Stopped compiling as Position-Independent Code
- Removed git submodule use
- Added some optional init-time unit testing
- Added support for a global seed value, so a hash can be repeatedly tested with
  varying results
- Added `SanityAll` test to summarize hash sanity
- Added `SpeedAll` test to summarize hash speed
- Added `--notest=` command-line option for excluding tests
- Added `--vcode` command-line option to verify testing across systems and across hashes
- Added `--endian=` command-line flag to specify which hash endianness(es) should be tested
- Added '--version' option

Specific test changes
---------------------
- Made small bit-width collision tests be useful by testing peak collisions instead
  of sum of collisions
- Distribution is tested on more bit-widths
- Changed some test bit-width bounds to reflect mathematical foundations of tests
- RMSE is used instead of RMS when testing hash distribution shape
- Made the Differential test be thread-enabled
- Added some Permutation tests
- Added SparseSeed test
- Added a large internal word list, so Text testing can be consistent across machines
- Improved basic Sanity testing and failure reporting
- Added PrependedZeroes test to Sanity testing
- Added thread-safety tests to Sanity testng
- Varying alignments and buffer tail sizes are used during speed tests
- Tried to make perf testing more consistent
- BadSeed test is excluded on 32-bit hashes for the time being
- Made BadSeed test distinguish reports on known bad seeds from new ones
- Removed BadSeed test from default test set
- Renamed MomentChi2 to Popcount
- Performance tests currently display stddev information; this is likely to be
  removed or at least altered post-beta

General hash changes (compared to SMHasher base)
-------------------------------------------------
All (or nearly all) hashes now:
- Have had their reference names redone with a more consistent scheme
   - Details can be found in `hashes/README.md`
   - Any name change is definitely subject to future revision at this point
- Use shared code for:
   - Fixed-width integer definitions
   - Transferring bytes to/from memory
   - Byteswapping
   - Integer rotation
   - Bit counting (popcount/clz)
   - Compiler hints
   - Large-integer math
   - Endianness detection/handling
- Should have / are expected to have consistent verification codes across all
   systems!
   - I've tried to remove all 32-bit/64-bit issues, but have yet to verify this
   - I also cannot test on Apple and Microsoft platforms
- Properly compute their big- and little-endian hashes on BOTH big- and
   little-endian platforms
- Updated to use 64-bit or larger seed values
- If a number of different hashes were really the same or very similar core hash with
  a series of small alterations, then I generally merged the implementations and used
  template variables or similar to handle the differences.
   - I'm _mostly_ happy with how that turned out, as it certainly acheived its goals of
     making those differences jump out, and makes comparing those different hashes
     rather easier than them being wholly separate implementations.
   - However... I _may_ have gone a little overboard with it. I'm worried that even
     hash authors might be confused by what I did, and it definitely can make it harder
     to read for a new-comer to the hash.
   - I don't really know how to resolve this, yet
- Most truncated output hash variants have been removed
   - The rest are likely to be removed in the future
   - This is because testing will be enhanced to test the hash width subsets
     automatically, making those hash variants redundant
- A number of hashes have not had their list of "bad seeds" ported over. This is due
  to a number of bugs and limitations with the BadSeed test, making those results
  unreliable. This will be addressed in the future in some fashion.

Specific hash changes (compared to SMHasher base)
-------------------------------------------------
- ahash
   - Removed, as it was an external library dependency
   - I hope to re-add this in source form in the future
- ascon
   - Brought up to latest revision
   - Added XOF and XOFa variants
   - Uses different homegrown seeding
   - Self-tests added
- beamsplitter
   - Brought up to latest revision
   - Altered to make its state buffer be on the stack
   - Fixed to be thread-safe
   - Fixed erroneous reports of bad seeds
   - Removed some Undefined Behavior
- blake2
   - Removed tomcrypt code/dependency
   - Added full suite of 2{s,b}{256,224,160,128} variants
- chaskey
   - Brought up to latest revision
   - Fixed to be thread-safe
   - Made number of rounds be a template variable
   - Uses different homegrown seeding
   - Added full suite of {8,12}-round {32,64,128}-bit variants
- cityhash
   - Removed "no seed" variant
   - Added 128-bit seed-high-64-bits variants
   - Added 128-bit CRC-based seed-high-64-bits variants
   - Added 256-bit CRC-based variant, with modified seeding
   - Added CityMurmur variants
- clhash
   - Fixed to be thread-safe
   - Uses different homegrown seeding
   - Made "with -DBITMIX" and "without" be separate variants
- crap
   - Added CrapWow and CrapWow64 hashes
- crc
   - Unified HW and SW implementations
   - Removed pclmul implementation
- discohash
   - Brought up to latest revision
   - A likely-unintentional behavior change was turned into a hash variant
   - Added 128-bit versions
   - Altered to make its state buffer be on the stack
   - Fixed to be thread-safe
   - Fixed erroneous reports of bad seeds
- falkhash
   - Reimplemented version 1 in C++
   - Removed hardcoded 0-len hash result
   - Removed 64-bit truncation
   - Added version 2
- farmhash
   - Removed redundant C99 version of the code
   - Made namespaced function variants be explicitly named
   - Added all function variants (see hashes/README.md for why)
- farsh
   - Removed some Undefined Behavior
- fletcher
   - Added full 128-bit output variants
   - Added actual 32- and 64-bit Fletcher's checksum implementations, not ZFS' variant
- fletcher4
   - Made this actually be fletcher4 (in SMHasher it was a copy of fletcher2)
- floppsyhash
   - Refactored to give stable results under most GCC optimizations
   - Probably also stable under Clang, icc, and MSVC
   - This could be extensible (to at least some degree) to other compilers/platforms
- fnv
   - Added explicitly 32- and 64-bit variants
   - Added wordwise FNV1-a variants
   - Removed some Undefined Behavior
- halftimehash
   - Removed some Undefined Behavior
   - Fixed to be thread-safe
   - Uses romu seeding, as specified by its design paper
- hasshe2
   - Added a variant tweaked to add in the length to the initial state, so it passes
     AppendZeroes tests
   - Fixed to not read past end-of-buffer
   - Removed hardcoded 0-len hash result
   - Uses different homegrown seeding
- highwayhash
   - Removed, as it was an external library dependency
   - I hope to re-add this in source form in the future
- khash
   - Changed implementation to not hash bytes past end-of-buffer
- komihash
   - Added a local copy
   - Brought up to latest revision
- lookup3
   - Added non-truncated 64-bit variant
- md5
   - Uses most-mixed output bits for 32- and 64-bit truncated variants
   - Uses different homegrown seeding
- meowhash
   - Uses different seeding, I think the original/author-specified version
- metrohash
   - All variants were combined into one file, to allow for much more direct
     comparison between variants
   - Two redundant variants were only ported once each
   - The "short-key-optimized" variants were not ported, since they only differ in
   performance
- multiply-shift
   - Made the random-value table be read-only after initialization
   - Uses a separate PRNG instead of a "system" PRNG, for consistency across systems
   - Uses different homegrown seeding
- mum-hash / mir-hash
   - Added version 3
   - Added explicit variants for all mum version{1,2,3} + {exact,inexact}mult +
     unroll2^{1,2,3,4} combos, and both mir {exact,inexact}mult variants
      - exact is what SMHasher3 calls strict, and inexact is the other option
   - This is because they all have different hash results; they aren't
    performance-only changes
      - All 64-bit mum/mir verification codes in SMHasher's main.cpp correspond to one of
        these variants
   - Removed "realign" variants, as I suspect these are a bug
- murmurhash3
   - Cleaned up some pointer handling
- mx3
   - Added a local copy
   - Added v2 and v3
- nmhash
   - Added a local copy
   - Fixed to not use type-punning
- o1hash
   - Uses different homegrown seeding
- pearson
   - Removed hardcoded 0-len hash result
   - Cleaned up some pointer handling
- perl hashes (djb2/bernstein, sdbm, jenkinsOOAT)
   - Fixed these to use original scheme of including len in IV
- pmp-multilinear
   - This hash is probably not completely ported!
   - Uses different homegrown seeding
- pmurhash
   - Dropped because it produces the same values as murmurhash3
   - It may be re-added as a performance variant someday
- poly_mersenne
   - Uses a separate PRNG instead of a "system" PRNG, for consistency across systems
- prvhash
   - Added a local copy
   - Brought up to latest revision
   - Modified the "streaming version" of the code to give the same results, but always
     in a single call, for performance
   - Uses different homegrown seeding
- ripemd
   - Uses different homegrown seeding
   - Added self-tests
- sha1
   - Uses different homegrown seeding
   - Added self-tests
- sha2
   - Uses different homegrown seeding
   - Added self-tests
- sha3
   - Uses different homegrown seeding
- siphash
   - Removed hardcoded 0-len hash result
- superfasthash
   - Fixed this to use original scheme of including len in IV
   - Removed some Undefined Behavior
- t1ha
   - Turned macro usage into templated functions
   - Enabled the "avx2" hash on AVX platforms, because it only uses AVX intrinsics
   - Brought the BE/LE versions into SMHasher3 endianness paradigm
   - Added self-tests
   - Renamed some functions
   - Fixed behavior under ASAN builds
- tabulation
   - Uses a separate PRNG instead of a "system" PRNG, for consistency across systems
- umash
   - Brought up to latest revision
   - Fixed to be thread-safe
   - Fixed to not use type-punning
   - Added full-seeding variants
   - Removed dependency on GCC
- vhash
   - Fixed to not read past end-of-buffer
   - Made to use SMHasher3's AES common wrapper
   - Uses different homegrown seeding
- wyhash
   - Added explicit strict/non-strict (aka "condom"/not) variants
   - Added self-tests
- xxhash / xxh3
   - Brought up to latest revision (0.8.1 at time of coding)
   - Disabled "use -O2 on GCC+AVX2" hack, as that slows it down greatly for me

Specific bug fixes
------------------
This is only bugs in testing code. Bugs in hash functions are addressed above.

- Fixed bug where threading use on Linux could cause a crash
- Fixed bug where hashes were not initialized before verification
- Fixed bug where AppendZeroes Sanity test could miss failures
- Fixed bugs where hashes were inconsistently initialized across tests
- Fixed bug where single collisions would not cause test failure when they should
- Fixed bug in BadSeed test where running in threaded mode would not test the
  complete hash space (the last thread would always test no seeds and report
  success)
- Fixed bug in BadSeed test where "add new seeds" message would printed even when no
  new seeds were found
- Fixed bug in BadSeed test where 64-bit seeds were tested for hashes that could not
  accept them
- Fixed bug in BadSeed test where severe failures cause all testing to stop
- Fixed bug in Differential test where some failures would not be reported
- Fixed bug in Differential test where donothing hashes produced bad results
- Fixed bug in Differential test where some tests were not enabled without '--verbose'
- Fixed bug in Differential test where hashes were initialized too often
- Fixed bug in Popcount (aka MomentChi2) test where hashes were not initialized
  correctly, leading to invalid results
- Fixed bug in Popcount (aka MomentChi2) test where "previous" hash value was not
  computed
- Fixed bug in Windowed test where the window starting at bit 0 was tested twice
- Fixed bugs where progress dots were not printed out
- Fixed bug where reported elapsed time was wildly incorrect
- Fixed bug in timing code on some ARM platforms
- Fixed bug where lack of failures could cause odd reporting
- Fixed bug where reporting could get visually corrupted when not using '--verbose'
- Fixed bug where 32-bit hashes would not have their collisions printed when
  requested
<
