[[_TOC_]]

Submitting bugs or feature requests
===================================

If you have a Gitlab account or are OK registering for one, the please file any bug
reports or feature requests on [SMHasher3's issue
page](https://gitlab.com/fwojcik/smhasher3/-/issues).

If you are not OK with registering for an account, please feel free to email me at
fwojcik@uw.edu with any issues, questions, requests, bug reports, patches, or
pull-requests that you might have. Please make sure that your subject line contains
the word "SMHasher3". Also note that any and all information you send may end up in a
Gitlab issue that is created on your behalf.

In all cases, the most important things to include with any sort of problem
report are:
- A description of the existing behavior, preferably with an example copy/pasted into
  the report, especially if compiler error/warning messages are involved
- A description of the behavior you would like to see
- The output of `SMHasher3 --version`
- Your contact information

Most-wanted list
================

The top four things that would be appreciated most from external contributors are,
in descending order of importance:
- Any patch or detailed error report about build failures in MSVC or Apple
  environments.
- A faster implementation of the histogram code in `TestDistribution()` in
  `util/Analyze.cpp`.
- More unit tests, either external or internal to Hashlib or Testlib.
- More or better hash implementations.

For other issues, please examine [SMHasher3's issue
page](https://gitlab.com/fwojcik/smhasher3/-/issues) to see if an item already
exists, as it may already be planned or there may be some useful discussion of it
there.

All code submissions
====================

All code submissions must be in source form only. No binary-only additions are
allowed.

If you are adding a new file, please test the time taken to rebuild SMHasher3. To do
this, build SMHasher3 fully, alter only the timestamp on the file you added, and run
`make` or the build command again, seeing how long the full operation takes. If a
rebuild takes a significant amount of time compared to a full build, then it may need
to be refactored.

Organizing patches for submission
---------------------------------

The Most Important Rule when submitting any kind of patch or pull-request to
SMHasher3 is that they absolutely **must not** alter both the Hashlib side of the
codebase _and_ the Testlib side at the same time. Every kind of code submission may
only alter one or the other (or neither). For more clarity on which files comprise
which side, see the "Code organization" section in `README.md`.

Bug fixes and small enhancements can be based directly off of the `main`
branch. Larger code submissions are encouraged to use a branch of their own
off of the `main` branch.

Each commit in any pull-request should reflect a single logical change. In general,
err on the side of too many commits and not too few. This means that you should
probably not `squash` your change down to a single commit. This makes future `git
blame` and `git bisect` operations much more useful.

You can use the same branch to submit multiple bug fixes and features as long as you:
- split up the work such that each commit doesn't deal with more than one issue
- try to have the commits be ordered in a logical way (bug fixes first as possible,
  followed by small features, and then by larger features)
- ensure that each commit clearly describes what it does
- ensure that each commit will still compile correctly
This will also make rebasing onto a later branch head easier for everyone.

The Most Important Rule must still be followed, though. If your feature submission
adds something to Hashlib which is then acted upon in Testlib, then you must submit
two different requests.

All built source code must be available in the SMHasher3 source tree. Git submodules
are not allowed. Hash implementations that live in external libraries are not allowed.

Coding style
------------

For code style, the ideal would be to use the
[uncrustify](https://github.com/uncrustify/uncrustify) tool on your source tree as
you stage commits. The current `.uncrustify` file for SMHasher3 refers to a number of
settings that only exist in my private branch (until I polish them up for submission
to that project), so you will get errors about them which should be ignorable.

Since that would be something of a large ask, it is definitely not a requirement for
submitting code. However, please follow the following basic code style tenets if possible:

- Use the One True Brace Style (1TBS)[https://en.wikipedia.org/wiki/Indent_style#Variant:\_1TBS\_\(OTBS\)]
- Use spaces for indentation, not tabs, and use 4 spaces per indent level
- Continued lines should use a double-indent of 8 characters
- Code should not exceed 120 characters per line, and should use utf-8 and UNIX line-endings (`\n`)
- One-line statements are usually fine
- When using `*` or `&` as part of a type in a declaration, it should have spaces before and after
- Generally add spaces between binary operators and after commas
- Continued lines should end with an open paren, comma, or binary operator
- Do not use extra parens for `return` statements
- All constants going in to 64-bit variables should be enclosed in `UINT64_C()`
  macros or the like. This is optional for 32-bit variables. `ULL` or other constant
  suffixes should not be used.
- Multi-line C-style comments should have opening `/*` and closing `*/` text on their
  own lines, and should have a `*` for each line
- C++-style comments should have a space after the opening `//`
- Align things when it makes obvious sense to do so
- Preprocessor directives should indent 2 spaces per level
- Preprocessor directives should use `#if defined()` in preference to `#ifdef`

I won't reject a submission for not following this, but I will most likely
reformat the submitted code shortly after inclusion.

I want to have consistent rules for things like casing of variable and function names
and similar, but I haven't done that yet. Maybe someday.

Origin of patch submissions
---------------------------

Contributions to SMHasher3 are all subject to the Developer's Certificate of Origin:

```
Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

If you cannot agree to that, then you should not send the contribution to SMHasher3.

Changes to Hashlib
==================

Changes to existing files in Hashlib must conform to the licensing terms in
those files. New files in Hashlib must have some GPL3-compatible license,
such as BSD, MIT, CC0, zlib, GPL3, or similar (see
[https://www.gnu.org/licenses/license-list.html] for more information on
licence compatibility with GPL3). You will also need to include the license
text at the top of the file, and mark the license used in the hash's
metadata. If an enum for your license does not already exist, you will need
to add one to `include/common/Hashinfo.h`.

If you are submitting a new hash, then at least one version of its implementations
must work portably (implemented only standard C++-11, no intrinsics, no ASM). It may
make use of SMHasher3's `Mathmult` or `AES` functions, as they already have portable
versions internally. Hashes don't have to have _only_ portable implementations.

If you can, it would be appreciated if you made some effort at handling
endian issues in Hashlib submissions. I will handle testing on different
platforms, but failures there may delay new hashes from being added.

Make sure to follow the guidelines in `hashes/README.md` for naming new hashes.

Changes to Testlib
==================

Changes to new or existing files in Testlib must use GPL3 for licensing, and the
files need to have that license text at the top.

When adding new tests, please consider how long it could take with slower hashes or
hashes with longer outputs. It may make sense to only do some longer testing if
`--extra` testing was requested and/or for hashes not labeled as "slow" or "very
slow".

Please keep new tests to the general pattern of existing tests:
- common or reusable code should be in `util`
- all of the test-specific code should be in one .cpp file
- the new test probably should be templated by the hashtype and this use the
  `INSTANTIATE()` macro
- the .h file only contains the interface to be called by `main.cpp`
- add a new `g_test` variable for the test and a matching entry in `g_testopts` in
  main.cpp, as well as a new section for the test in the `test()` function similar to
  the existing ones

If at all possible, ensure new tests produce idential results regardless of system
endianness.

If unit tests are added, they can simply always run every startup if they are fast
enough, or can be set to only run in DEBUG mode if they are a little slower than
that, or they could be set to run only by explcit request if they are even slower or
if they have visible output.

It is difficult to give general rules for enhancing the build system. Certainly,
making it work with a larger variety of compilers is desirable. Adding new
implementations of primitives which are faster or more useful also seems good, and
these changes should probably follow the existing patterns and use the existing CMake
functions. Changes to that CMake infrastructure can also make sense.
