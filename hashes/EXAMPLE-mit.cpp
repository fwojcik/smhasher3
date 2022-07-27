/*
 * ###YOURHASHNAME
 * Copyright (C) 2022 ###YOURNAME
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */
#include "Platform.h"
#include "Hashlib.h"

// XXX Your hash filename MUST end in .cpp, and it MUST start with a
// lowercase letter!
//
// XXX Don't forget to add your new filename to the list in
// hashes/Hashsrc.cmake, keeping the list sorted by size!

//------------------------------------------------------------
// ###YOURHASHCODE

//------------------------------------------------------------
template <bool bswap>
static void ###YOURHASHNAMEHash( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint32_t hash = 0;
    PUT_U32<bswap>(hash, (uint8_t *)out, 0);
}

//------------------------------------------------------------
REGISTER_FAMILY(###YOURHASHFAMILYNAME,
   $.src_url    = "###YOURREPOSITORYURL",
   $.src_status = HashFamilyInfo::SRC_###YOURSRCSTATUS
 );

REGISTER_HASH(###YOURHASHNAME,
   $.desc            = "###YOURHASHDESCRIPTION",
   $.hash_flags      =
         0,
   $.impl_flags      =
         FLAG_IMPL_LICENSE_MIT,
   $.bits            = 32,
   $.verification_LE = 0x0,
   $.verification_BE = 0x0,
   $.hashfn_native   = ###YOURHASHNAMEHash<false>,
   $.hashfn_bswap    = ###YOURHASHNAMEHash<true>
 );
