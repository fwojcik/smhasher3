/*
 * ###YOURHASHNAME
 * Copyright (C) 2022 ###YOURNAME
 *
 * ###YOURLICENSETEXT
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
         0,
   $.bits            = 32,
   $.verification_LE = 0x0,
   $.verification_BE = 0x0,
   $.hashfn_native   = ###YOURHASHNAMEHash<false>,
   $.hashfn_bswap    = ###YOURHASHNAMEHash<true>
 );
