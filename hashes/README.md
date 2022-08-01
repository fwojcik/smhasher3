[[_TOC_]]

Some notes on hashes
====================

Terminology
-----------

SMHasher3 makes an important distinction between hashes and their implementations.

What SMHasher3 refers to as a **hash** is a defined mapping of inputs, which are an
arbitrary-length series of bytes and (optionally) other "seed" data of either
variable or fixed length, to outputs, which are a fixed-length series of bytes. A
hash is therefore a sort of abstract, mathematical specification, unrelated to
code. A "hash" that has variable-length outputs is considered by SMHasher3 to be a
series of closely-related hashes, each with a different fixed-length output.

A hash may or may not have a formal specification. It may be that a hash is only
specified by the code that was used to implement it.

A **hash implementation** is a particular set of code that calculates the hash. A
hash can have many different implementations, as long as they all produce the same
results for the same inputs. A given hash implementation can also have a variety of
code paths for different systems, as long as it always produces the same results.

A **hash family** is simply a group of similar hashes, whose implementations may or
may not have been written by the same author(s).

Hash naming scheme
------------------

I've attempted to give the hashes in SMHasher3 a more uniform naming scheme. It tries
to strike a balance between human-friendliness, descriptiveness, consistency, and
what the author(s) actually called their hashes.

For SMHasher3, a hash name must not exceed 25 characters, and should follow the
scheme described below. When a user refers to a hash it is looked-up in a
case-agnostic manner, so two hash names must differ by more than just letter case.

A hash name will consist of up to 3 different parts.

The first part always exists, and is the name of the hash, capitalized as the author
publishes it, or as close as is reasonable. This name must start with a letter, and
must consist of only letters, numbers, and dashes. If a whole version number is part
of the name, then it should not be separted from the textual part of the name by a
dash or a "v" prefix. It is also OK to simply omit the version number, if
desired. Any numeric description of the hash output width should also generally be
elided from this part. Some hashes have a numeric description of their processing
chunk size, or similar parameterization, in their name. It is OK to either have that
in the first part of the name, or as a variant in the third part (see below).

If a given hash name has different hash output widths, then the second part is the
width in bits. This is separated from the first part by a dash. If the author refers
to a "primary" bit-width version of the hash without its width and refers to other
versions with their widths, then it is OK to mirror that here and omit the second
part from that primary hash's name. For example, the 32-bit version of one hash is
referred to as "wyhash32" in its documentation and the 64-bit version is referred to
simply as "wyhash", so SMHasher3 uses that instead of "wyhash-64".

If a given hash with a given output size has more than one variant, then the third
part is a description of the variant aspect(s). Multiple independent variant
descriptions can appear in the same hash name. Each variant description is separated
from the previous part(s) by a period/dot.

There are two classes of variants. If the variant is only a truncation of the hash
output, then that variant part of the name consists only of the truncated width in
bits. If there is a truncated variant, then an untruncated (full-width) version of
the hash must exist; this naturally will not have a dot with a width specified.

Note that it is expected in future SMHasher3 releases that most or all truncated
versions of hashes will be removed, as it is planned to enhance testing such that
they will become redundant.

Otherwise, the variant string must start with a letter, though it can contain letters
and numbers, and should very briefly describe what varies. For example, a version of
a hash which is designed to handle incremental inputs might have a variant string of
".incr". For these other variants, there may or may not be a version of a hash
without a variant description; you should do whatever makes the most sense to you.

These naming guidelines should be followed as much as possible, but it some cases you
may not be able to or it may make sense to create an exception to them.

Here are some concrete examples of sets of hash names:
- MD5, MD5.32, MD5.64
   - "MD5" is the official name of the hash, so that is the first part.
   - There is only 1 valid bit-width output, so there is no second part.
   - There are two different variants which only truncate the ouput; for those, they
     keep the same name as the full-width hash, followed by a dot and then their
     truncated width in bits.
- RIPEMD-128, RIPEMD-160, RIPEMD-256
   - "RIPEMD" is the official name of the hash, so that is the first part.
   - It has 3 different possible output widths, so the second part is a dash followed
     by the particular width for that hash
   - There are no variants of these hashes, so no name has a dot.
- CLhash, CLhash.bitmix
   - "CLhash" is the way the author writes the hash name, so that is the first part.
   - It only comes in one output width, so there is no second part.
   - There is a "BITMIX" #define option that can be enabled. It seems that the version
     without this enabled is the more default/official version, so the implementation
     with that enabled has a dot followed by the name of variation.
- prvhash-64. prvhash-64.incr, prvhash-128, prvhash-128.incr
   - "prvhash" and "PRVHASH" are both how the author writes the hash name; I chose the
     lower-case version.
   - The specific hash version (v4.3) is not a whole number, and so is not reflected in
     the first part. It is mentioned in the description string.
   - It has two possible output widths, 64 and 128 bits. These are placed after the
     first part and are preceeded by a dash.
   - Each of those also has two variations: the one-shot hash function and the
     streaming/incremental version. Since these produce different hash results, both
     must be testable. The one-shot versions of hashes are more commonly used, so
     that has no third part suffix, as it can be considered the "default"
     version. The incremental version has a suffix of ".incr".
- mum1.exact.unroll1, mum1.exact.unroll2, mum1.exact.unroll3, mum1.exact.unroll4,
  mum1.inexact.unroll1, mum1.inexact.unroll2, mum1.inexact.unroll3, mum1.inexact.unroll4
   - "mum" and "mum-hash" are both ways the author writes the hash name; I chose the
     shorter one due to hash name length limits.
   - There are 3 different versions of mum-hash. These version numbers could be part of
     the hash name, or could be considered variants. As the author refers to them like
     "MUM_V1", I chose to make it part of the hash name. As above, the "v" is dropped,
     so the first part just becomes "mum1".
   - The hash only comes in one bit width, so there is no second part.
   - There are two independent variations on the hash. The first is a choice of either
     exact or inexact 64x64->128 integer multiplication. The code refers to this as
     "strict" or not. I chose the "exact" terminology because it describes the
     difference somewhat better, because there didn't seem to be a more correct or
     default version, and because the author did not use a term to describe the
     non-"strict" variant. So either ".exact" or ".inexact" is appended to the first
     part of the name.
   - The second variation is how many times a core loop is unrolled. Changes like that
     which are done only for performance would not have separately testable
     variants. In this unusual case, mum-hash actually gives different hash results
     depending on the choice of unroll factor, so this choice must be given to the
     user. Since this is totally orthogonal to the choice of exact/inexact, it is
     further appended to name with a dot.
- mx3.v1, mx3.v2
   - "mx3" is how the author refers to this hash.
   - The version numbers are strictly whole numbers. Ordinarily, this would mean they
     should be included in the first part of the name. However, because the "v" prefix
     should be dropped, this would make the names look like "mx31" and "mx32", which
     would be extremely confusing. So the versions were made into variants instead. The
     "v" prefix makes sense to include here because it fundamentally does describe the
     nature of the variation, and it must begin with a letter in this case anyway.
   - This reflects that these naming conventions are not totally strict. Exceptions can
     be made as human-friendliness requires.

Names are registered with SMHasher3 via calls to `REGISTER_HASH(hashname, ....)`. The
hash names provided to `REGISTER_HASH()` and `REGISTER_FAMILY()` must be valid C++
identifer names. Because of that, C++ reserved words cannot be used as the name of
hashes or families. To handle special characters that are needed in names, any dash
characters (`-`) in the hash name are replaced with single underscores (`_`), and any
dots (`.`) are replaced with double underscores (`__`). Hash family names may only
contain letters and numbers, and must start with a letter.

As SMHasher is currently in its first beta release, feedback on this scheme is
welcome. Any name change here is definitely subject to future revision!

Hashes with multiple backends
-----------------------------

Sometimes a hash function API is presented to the consumer (outside of SMHasher3) in
a way where a single API call can hide what are really multiple hash functions behind
it, where the most appropriate one might be chosen based off of run-time or
compile-time detection of system capabilities.

If the hash implementations differ only in performance, then SMHasher3 considers all
those hash functions to be different implementations of the same hash, as no matter
which one is used the same output will be given for the same inputs. When
implementing that in SMHasher3, only one hash should be added, and internally it can
have any number of those different implementations for performance. That said, it is
strongly preferable to have implementation selection be compile-time only. Examples
of this are blake3 and xxhash. More details for this scenario can be found under
"Platform-specific implementations" in `hashes/README.advancedtopics.md`.

However, if those hash functions can differ in hash results, then SMHasher3 considers
all those possibilites to be _different hashes_. In this case, SMHasher3 considers
that top-level API call as not implementing only one hash, and so it should not be
directly implemented here. Instead, every individual hash (mapping of inputs to
outputs) behind that API call should be implemented separately in SMHasher3, even if
they are never intended for direct consumption. SMHasher3 refers to those hashes as
**hash components**. Examples of this are in MUM-hash, and some FarmHash and t1ha
hashes.

Another example where this matters is in hashes with separate functions for
"incremental" or "streaming" applications, where the data to be hashed can be
supplied in pieces instead of all at once. If the incremental version of a hash
exists and it produces the same hash results as the regular, all-at-once version,
then SMHasher3 considers those hashes to be the same. In that case, it doesn't make
sense to include the incremental version in SMHasher3 at all. If the incremental
version ever produces different results, then that is considered a different hash,
and so it should be implemented, most likely as a variant of the regular version. It
may also make sense to optimize the incremental implementation around the fact that
SMHasher3 will only ever provide data all-at-once.
