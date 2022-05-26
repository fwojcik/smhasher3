   _____ __  __ _    _           _              ____  
  / ____|  \/  | |  | |         | |            |___ \ 
 | (___ | \  / | |__| | __ _ ___| |__   ___ _ __ __) |
  \___ \| |\/| |  __  |/ _` / __| '_ \ / _ \ '__|__ < 
  ____) | |  | | |  | | (_| \__ \ | | |  __/ |  ___) |
 |_____/|_|  |_|_|  |_|\__,_|___/_| |_|\___|_| |____/ 
=======================================================

Summary
-------

SMHasher3 is based on [the SMHasher fork maintained by Reini
Urban](https://github.com/rurban/smhasher), which is in turn based on
[the original SMHasher by Austin
Appleby](https://github.com/aappleby/smhasher/). The commit history of
both of those codebases up to their respective fork points is
contained in this repository.

The major differences from rurban's fork are:
*) Fix several critical bugs
*) Significant performance increases
*) Better statistical foundations for some tests
*) Report on p-values for almost all tests
*) Better handling of threaded testing
*) More consistent testing across systems and configurations
*) More consistent and human-friendlier reporting formats
*) Common framework code explicitly sharable across all hashes
*) Flexible metadata system for both hashes and their implementations
*) Support of more hash seed methods (64-bit seeds and ctx pointers)
*) Ability to supply a global seed value for testing
*) Test of varying alignments and buffer tail sizes during speed tests
*) Refactored code to improve maintainability and rebuild times
*) Reorganized code layout to improve readability
*) Compilation-based platform probing and configuration
*) Consistent code formatting
*) More explicit license handling
*) Fully C++11-based implementation

Notes on licensing
------------------

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
modifications made to the hash implmentations. I believe this to have
been the least bad option to get the improvements in SMHasher3 out to
the world.

The LICENSE file of this project has been updated to reflect these
terms. I have added the GPL license text to many of the files that are
covered by it, and I have added the text of the original MIT license,
as well as a list of contibutor copyrights, explicitly to much code
that is being distributed here under the GPL, in order to comply with
the MIT license terms of the originals. Finally, other code files
which are being distributed under non-GPL licenses will have their
license added to them, to help remove confusion.

Other
-----

* http://nohatcoder.dk/2019-05-19-1.html gives a new, useful hash level classification 1-5.
* [http://www.strchr.com/hash_functions](http://www.strchr.com/hash_functions) lists other benchmarks and quality of most simple and fast hash functions.
* [http://bench.cr.yp.to/primitives-hash.html](http://bench.cr.yp.to/primitives-hash.html) lists the benchmarks of all currently tested secure hashes.
* http://valerieaurora.org/hash.html Lifetimes of cryptographic hash functions
