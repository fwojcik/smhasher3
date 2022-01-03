/*
 * SMHasher3
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see
 * <https://www.gnu.org/licenses/>.
 *
 * This file incorporates work covered by the following copyright and
 * permission notice:
 *
 *     Copyright (c) 2010-2012 Austin Appleby
 *     Copyright (c) 2014-2021 Reini Urban
 *     Copyright (c) 2019      Yann Collet
 *     Copyright (c) 2020      Thomas Dybdahl Ahle
 *
 *     Permission is hereby granted, free of charge, to any person
 *     obtaining a copy of this software and associated documentation
 *     files (the "Software"), to deal in the Software without
 *     restriction, including without limitation the rights to use,
 *     copy, modify, merge, publish, distribute, sublicense, and/or
 *     sell copies of the Software, and to permit persons to whom the
 *     Software is furnished to do so, subject to the following
 *     conditions:
 *
 *     The above copyright notice and this permission notice shall be
 *     included in all copies or substantial portions of the Software.
 *
 *     THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *     EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 *     OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *     NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 *     HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 *     WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 *     FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 *     OTHER DEALINGS IN THE SOFTWARE.
 */
#include "Platform.h"
#include "Random.h"
#include "VCode.h"

#include "HashSanityTest.h"

#include <vector>

//-----------------------------------------------------------------------------
// This should hopefully be a thorough and uambiguous test of whether a hash
// is correctly implemented on a given platform.
// Note that some newer hash are self-seeded (using the randomized address of the key),
// denoted by expected = 0.

bool VerificationTest ( HashInfo* info, bool verbose )
{
  const pfHash hash = info->hash;
  const int hashbits = info->hashbits;
  const uint32_t expected = info->verification;
  const int hashbytes = hashbits / 8;

  uint8_t * key    = new uint8_t[256];
  uint8_t * hashes = new uint8_t[hashbytes * 256];
  uint8_t * final  = new uint8_t[hashbytes];

  memset (key,0,256);
  memset (hashes,0,hashbytes*256);
  memset (final,0,hashbytes);

  // Hash keys of the form {0}, {0,1}, {0,1,2}... up to N=255,using 256-N as
  // the seed
  for(int i = 0; i < 256; i++)
  {
    key[i] = (uint8_t)i;
    Hash_Seed_init (hash, 256-i);
    hash (key,i,256-i,&hashes[i*hashbytes]);
    addVCodeInput(key, i);
  }

  // Then hash the result array
  Hash_Seed_init (hash, 0);
  hash (hashes,hashbytes*256,0,final);

  // The first four bytes of that hash, interpreted as a little-endian integer, is our
  // verification value
  uint32_t verification =
      (final[0] << 0) | (final[1] << 8) | (final[2] << 16) | (final[3] << 24);

  addVCodeInput(hashes, 256*hashbytes);
  addVCodeOutput(hashes, 256*hashbytes);
  addVCodeOutput(final, hashbytes);
  addVCodeResult(expected);
  addVCodeResult(verification);

  delete [] final;
  delete [] hashes;
  delete [] key;

  //----------

  if (expected != verification) {
    if (!expected) {
      if (verbose)
        printf("Verification value 0x%08X ........ SKIP (self- or unseeded)\n",
               verification);
      return true;
    } else {
      if (verbose)
        printf("Verification value 0x%08X ........ FAIL! (Expected 0x%08x)\n",
               verification, expected);
      return false;
    }
  } else {
    if (!expected) {
      if (verbose)
        printf("Verification value 0x%08X ........ INSECURE (should not be 0)\n",
               verification);
      return true;
    } else {
      if (verbose)
        printf("Verification value 0x%08X ........ PASS\n", verification);
    }
    return true;
  }
}

//----------------------------------------------------------------------------
// Basic sanity checks -

// A hash function should not be reading outside the bounds of the key.

// Flipping a bit of a key should, with overwhelmingly high probability,
// result in a different hash.

// Hashing the same key twice should always produce the same result.

// The memory alignment of the key should not affect the hash result.

// Assumes Hash_Seed_init(0) is already called.

bool SanityTest ( pfHash hash, const int hashbits )
{
  printf("Running sanity check 1      ");

  Rand r(883743);

  bool result = true;

  const int hashbytes = hashbits/8;
  const int reps = 10;
  const int keymax = 256;
  const int pad = 16;
  const int buflen = keymax + pad*3;
  const uint32_t seed = 0;

  uint8_t * buffer1 = new uint8_t[buflen];
  uint8_t * buffer2 = new uint8_t[buflen];

  uint8_t * hash1 = new uint8_t[hashbytes];
  uint8_t * hash2 = new uint8_t[hashbytes];

  //----------
  memset(hash1, 1, hashbytes);
  memset(hash2, 2, hashbytes);

  for(int irep = 0; irep < reps; irep++)
  {
    if(irep % (reps/10) == 0) printf(".");

    for(int len = 4; len <= keymax; len++)
    {
      for(int offset = pad; offset < pad*2; offset++)
      {
        uint8_t * key1 = &buffer1[pad];
        uint8_t * key2 = &buffer2[pad+offset];

        r.rand_p(buffer1,buflen);
        r.rand_p(buffer2,buflen);

        memcpy(key2,key1,len);

        hash (key1,len,seed,hash1);
        addVCodeInput(key1, len);
        addVCodeOutput(hash1, hashbytes);

        for(int bit = 0; bit < (len * 8); bit++)
        {
          // Flip a bit, hash the key -> we should get a different result.

          flipbit(key2,len,bit);
          hash(key2,len,seed,hash2);
          addVCodeOutput(hash1, hashbytes);

          if(memcmp(hash1,hash2,hashbytes) == 0)
            {
              for(int i=0; i < hashbytes; i++){
                if (hash1[i] == hash2[i]) {
                  printf(" %d: 0x%02X == 0x%02X ", i, hash1[i], hash2[i]);
                  break;
                }
              }
              result = false;
              goto end_sanity;
            }

          // Flip it back, hash again -> we should get the original result.

          flipbit(key2,len,bit);

          hash(key2,len,seed,hash2);

          if(memcmp(hash1,hash2,hashbytes) != 0)
            {
              for(int i=0; i < hashbytes; i++){
                if (hash1[i] != hash2[i]) {
                  printf(" %d: 0x%02X != 0x%02X ", i, hash1[i], hash2[i]);
                  break;
                }
              }
              result = false;
              goto end_sanity;
            }
        }
      }
    }
  }

 end_sanity:
  addVCodeResult(result);

  if(result == false)
  {
    printf(" FAIL  !!!!!\n");
  }
  else
  {
    printf(" PASS\n");
  }

  delete [] buffer1;
  delete [] buffer2;

  delete [] hash1;
  delete [] hash2;

  return result;
}

//----------------------------------------------------------------------------
// Appending zero bytes to a key should always cause it to produce a different
// hash value

// Assumes Hash_Seed_init(0) is already called.

bool AppendedZeroesTest ( pfHash hash, const int hashbits )
{
//printf("Verification value 0x%08X ....... PASS\n",verification);
//printf("Running sanity check 1     ");
  printf("Running AppendedZeroesTest  ");

  Rand r(173994);

  const int hashbytes = hashbits/8;
  const uint32_t seed = 0;

  for(int rep = 0; rep < 100; rep++)
  {
    if(rep % 10 == 0) printf(".");

    unsigned char key[256];
    memset(key,0,sizeof(key));

    r.rand_p(key,32);

    addVCodeInput(key, sizeof(key));

    std::vector<std::vector<uint8_t>> hashes;

    for(int i = 0; i < 32; i++) {
      std::vector<uint8_t> h(hashbytes);
      hash(key,32+i,seed,&h[0]);
      hashes.push_back(h);
      addVCodeOutput(&h[0], hashbytes);
    }

    // Sort in little-endian order, for human friendliness
    std::sort(hashes.begin(), hashes.end(),
            [](const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
                for (int i = a.size(); i >= 0; i--) {
                    if (a[i] != b[i]) {
                        return a[i] < b[i];
                    }
                }
                return false;
            } );

    for(int i = 1; i < 32; i++) {
        if (memcmp(&hashes[i][0], &hashes[i-1][0], hashbytes) == 0) {
            printf(" FAIL !!!!!\n");
            addVCodeResult(false);
            return false;
        }
    }

  }

  printf(" PASS\n");
  addVCodeResult(true);
  return true;
}

//----------------------------------------------------------------------------
// Prepending zero bytes to a key should also always cause it to
// produce a different hash value

// Assumes Hash_Seed_init(0) is already called.

bool PrependedZeroesTest ( pfHash hash, const int hashbits )
{
  printf("Running PrependedZeroesTest ");

  Rand r(534281);

  const int hashbytes = hashbits/8;
  const uint32_t seed = 0;

  for(int rep = 0; rep < 100; rep++)
  {
    if(rep % 10 == 0) printf(".");

    unsigned char key[256];
    memset(key,0,sizeof(key));

    r.rand_p(key+32,32);

    addVCodeInput(key, sizeof(key));

    std::vector<std::vector<uint8_t>> hashes;

    for(int i = 0; i < 32; i++) {
      std::vector<uint8_t> h(hashbytes);
      hash(key+32-i,32+i,seed,&h[0]);
      hashes.push_back(h);
      addVCodeOutput(&h[0], hashbytes);
    }

    // Sort in little-endian order, for human friendliness
    std::sort(hashes.begin(), hashes.end(),
            [](const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
                for (int i = a.size(); i >= 0; i--) {
                    if (a[i] != b[i]) {
                        return a[i] < b[i];
                    }
                }
                return false;
            } );

    for(int i = 1; i < 32; i++) {
        if (memcmp(&hashes[i][0], &hashes[i-1][0], hashbytes) == 0) {
            printf(" FAIL !!!!!\n");
            addVCodeResult(false);
            return false;
        }
    }

  }

  printf(" PASS\n");
  addVCodeResult(true);
  return true;
}
