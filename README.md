```
   _____ __  __ _    _           _              ____  
  / ____|  \/  | |  | |         | |            |___ \ 
 | (___ | \  / | |__| | __ _ ___| |__   ___ _ __ __) |
  \___ \| |\/| |  __  |/ _` / __| '_ \ / _ \ '__|__ < 
  ____) | |  | | |  | | (_| \__ \ | | |  __/ |  ___) |
 |_____/|_|  |_|_|  |_|\__,_|___/_| |_|\___|_| |____/ 
=======================================================
```

Summary
-------

SMHasher3 is based on [the SMHasher fork maintained by Reini
Urban](https://github.com/rurban/smhasher), which is in turn based on
[the original SMHasher by Austin
Appleby](https://github.com/aappleby/smhasher/). The commit history of
both of those codebases up to their respective fork points is
contained in this repository.

The major differences from rurban's fork are:
- Fix several critical bugs
- Significant performance increases
- Better statistical foundations for some tests
- Report on p-values for almost all tests

Additional significant changes include:
- Better handling of threaded testing
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

As of 2022-07-20, SMHasher3 is pre-beta. A beta1 release is expected by the end of
the month. There is also planned a beta2 release at the least.

This code has compiled and run successfully on Linux x64, arm, and powerpc
using gcc and clang. Importantly, I do not have the ability to test on Mac
or Windows environments. The goal is to support both, and the CMake files
Should(tm) work in both environments, I feel the odds that I got
everything perfect on the first go to be... small. So reports of success
or failure are appreciated, as are patches to make things work.


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
closest to reality), so it lives here instead. :-/

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
