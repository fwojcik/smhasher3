[[_TOC_]]

Why do pre-build header generation?
===================================

It is a sad fact that a good deal of very valuable functionality in
C++ is not (yet?) usable in any standard way, but instead is put
behind some compiler-dependent API. One traditional way of handling
this is to have some wrapper function or macro that has different
definitions, with the "correct" one chosen by some "#if" preprocessor
conditional.

This approach has some downsides. The conditions that go into the test
are often complicated, and can become outdated in both the positive
direction (e.g. a later version of some compiler may start supporting
an API) as well as the negative (e.g. a later compiler may start
claiming it is GCC-compatible even though some used __builtin() is not
actually supported, leading to compilation failure). The "#if" tests
generally will only have support for compilers that the developer
specifically added, so new compilers which support those features
won't have them used. It also means that for every .cpp file compiled,
a whole chain of preprocessor directives must be re-calculated,
leading to longer build times. And finally, it can sometimes be very
difficult for a developer to know which alternative for a given
feature was chosen by the compiler.

So instead of doing that, this project does pre-build detection of
compiler-specific APIs by just trying all the possibilities we know of
and seeing what works, and then generating a Platform.h file that
contains the working ones, without any "#if" directives.

This approach also has some downsides. It is more complicated for
someone just looking at the codebase to figure out what is going on,
as a series of "#if" tests in a header is a much more familiar
paradigm. It can also be very difficult to see the general shape of
what the final generated Platform.h file might look like just from
looking at the source tree. All of the different implementations of a
given wrapper function are no longer viewable in a single file. It
ties this project slightly more to CMake, as all the generation logic
is done in that language. In the rare case where there are two
different variants that both work with different compilers, but one
variant is sometimes preferred and the other variant is also sometimes
preferred, the logic to implement that is either complicated or
impossible under the current scheme, and is at best widely separated
from the variants' implementation details, as it would be implemented
in the .cmake file. Fortunately, this last case does not yet occur in
this project.

But even given all of that, I've decided on balance that this is the
better approach for this project. It was already fairly tied to CMake,
and that is a popular cross-platform tool, with a good history of
backwards compatibility, so depending on it even more seems
low-risk. The complexity can be mitigated by good documentation, and
an example post-generation Platform.h file can be provided so a new
user can see what it might look like. All of the different variant
implementations are all in the same directory and have the same
filename pattern, so it is not so difficult to see them all. But if
some showstopping problem or incompatibility with it crops up, then I
won't reject the option of some other approach.


How does pre-build header generation work?
==========================================

findVariant() is the CMake function that actually performs this
logic. It tests a series of possible implementations of some given
functionality to see which implementation works in the current
environment. Each possible implementation is called a "variant", and
is stored in a separate .h file. findVariant() will try each one in
turn, using try_compile() calls, and stop when it finds the first one
which compiles successfully.

Nearly everything that is tested also has a "fallback" implementation,
which is intended to work regardless of the compiler. For the few
things which don't have a fallback, it is a fatal error if no working
variant is found. Since some of the things being tested for are hints
to the compiler or otherwise optional functionality that doesn't
affect the actual results of the code, it is very possible that a
fallback implementation will be non-functional in some regard. For
example, a fallback could be "#define assume(x)", which just removes
anything in "assume(...)".

A `findVariant()` example walkthrough
-------------------------------------

To explain how findVariant() works, the example of "findVariant(FOO)"
will be used.

findVariant() takes a string that is used to refer to a series of
variables. The input to findVariant(FOO) will come from FOO_VARIANTS,
and the outputs will go to FOO_IMPL and FOO_FALLBACK.

FOO_IMPL will be set to the variant which was found to work; that is,
it will contain the actual code as a string. FOO_FALLBACK will be set
to TRUE if that implementation was the fallback one, and FALSE
otherwise.

FOO_VARIANTS is expected to be a list containing, in order:

  1) A textual description of what is being looked for, intended for
     humans, and typically used in messages.
  2) The prefix that the test .cpp file and the variant .h files all
     share in the platform/ directory.
  3) A string containing any text or code needed to test for FOO,
     perhaps the contents of some BAR_IMPL variable from a previous
     findVariant() invocation. This string should end with a
     newline, and must contain "\n" at the least; an empty string
     confuses CMake's list processing.
  4) The number of different variants to test, *including* 1 for the
     fallback variant, *even if there is no fallback*. This is to
     avoid having to do any directory/file lookups to determine if
     input dependencies have changed.
  5) (optional) The numbers of any variants which should be
     skipped, in ascending numeric order. These are often set as a
     result of previous findVariant() calls.

Again for example, assume that for #2 above the string "foo" was
supplied, and for #4 the number 4 was supplied.

In the platform/ directory, there will be:

  - a foo_test.cpp file, which should `#include "curvariant.h"` and
    then have some code to test the variant (static_assert() may or
    may not be helpful here),
  - foo_variant1.h, foo_variant2.h, and foo_variant3.h, each of
    which should contain a different possible way to implement the
    same functionality, and very likely
  - foo_fallback.h, which should contain a compiler-agnostic way of
    implementing the feature. As explained above, this could simply
    be some form of "do nothing", or it could be a small utility
    function (see "bswap_fallback.h" for a good example of
    this). However, if the feature is so critical to compilation
    that some compiler-specific implementation is _absolutely
    required_ and no generic implementation is possible, then this
    fallback file won't exist. That should be very rare, though.

Since we use try_compile(), the foo_test.cpp file needs to go through
the link step also, which means it needs to be a complete program
including a main() function. Since cross-compiling is supported, the
resulting binary is never executed, since it might not be able to
run. It is still considered good practice to add at least some
run-time testing, since it may be that in the future we add the
requirement that the resulting binary return success on the native
platform iff cross-compilation is not being done.

Where did the variants come from?
=================================

All of the non-trivial code in the platform/*.h files is based on code
from one of three places:

  - Hedley [https://nemequ.github.io/hedley/]
  - Portable snippets [https://github.com/nemequ/portable-snippets]
  - FFT [https://github.com/NFFT/nfft]

Why and how are the detection results cached?
=============================================

It can take a non-trivial amount of time for all the detection test compilations to
complete, long enough that waiting for them often is annoying to a maintainer or to
someone who is iterating on a hash implementation. This is compounded by the fact
that many changes require altering the CMake configuration (such as the list of files
to be compiled), which causes a reconfiguration step to be performed, so even tying
platform detections to the configure step does not alleviate this problem. While
CMake does allow the user to specify that changes in any of a list of files will
trigger a reconfiguration, it seems to have no way of letting its script know *why* a
reconfiguration step was started, nor does it have a way of marking dependencies of
variables' contents on input files. So there is no clean, built-in way to know during
reconfiguration if platform detection needs to be re-performed.

The only solution I've found is to create my own caching system. Yay. That always
goes smoothly, and is sure to be completely reliable and free of edge cases. `:-{`

The way it works is that the .cmake files in `platform/` associate a list of files
with a list of variables, such that if *any* file in the given list changes, then
*all* of the variables in the given list are cleared and removed from CMake's cache
as well as current memory. CMake's cache is empty during the initial configuration
and so the full platform detection takes place, and those results are cached.

During a future reconfiguration, the variable containing the list of files is read
from CMake's cache. There is also a variable containing the SHA-256 hash of each of
those files, and they are recomputed and compared against the cached copy. If any
difference is detected, then the list of variable names (again, from CMake's cache)
is iterated over and each one is cleared. Otherwise, the only thing that happens is
re-informing CMake that its configuration depends on those input files.

From the perspective of each group of platform-specific code, this means it will
first call checkCachedVarsDepend() to clear the cache if needed. Then every call to
findVariant() will append each filename it touches to a list of files, as well as
appending the name of each variable it sets to a different list. Then the .cmake file
itself will be added to the list of files, and both variables will be passed to
setCachedVarsDepend(), which will record the file hashes and register the
configuration dependencies with CMake. In this way, if any of the inputs to a group
of platform detections change, the whole group of detections will be rerun.