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
 *     Copyright (c) 2015      Ivan Kruglov
 *     Copyright (c) 2015      Paul G
 *     Copyright (c) 2016      Jason Schulz
 *     Copyright (c) 2016-2018 Leonid Yuriev
 *     Copyright (c) 2016      Sokolov Yura aka funny_falcon
 *     Copyright (c) 2016      Vlad Egorov
 *     Copyright (c) 2018      Jody Bruchon
 *     Copyright (c) 2019      Niko Rebenich
 *     Copyright (c) 2019-2020 Yann Collet
 *     Copyright (c) 2019-2021 data-man
 *     Copyright (c) 2019      王一 WangYi
 *     Copyright (c) 2020      Cris Stringfellow
 *     Copyright (c) 2020      HashTang
 *     Copyright (c) 2020      Jim Apple
 *     Copyright (c) 2020      Thomas Dybdahl Ahle
 *     Copyright (c) 2020      Tom Kaitchuck
 *     Copyright (c) 2021      Logan oos Even
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
size_t numHashes(void);
HashInfo * numHash(size_t num);
HashInfo * findHash ( const char * name );

void Hash_init (HashInfo* info);
bool Hash_Seed_init (pfHash hash, size_t seed, size_t hint);
void Bad_Seed_init (pfHash hash, uint32_t &seed);

void HashSelfTestAll(bool verbose);


void md5_32(const void *key, int len, uint32_t seed, void *out);
void md5_64(const void *key, int len, uint32_t seed, void *out);
void md5_128(const void *key, int len, uint32_t seed, void *out);

void sha1_32(const void *key, int len, uint32_t seed, void *out);
void sha1_64(const void *key, int len, uint32_t seed, void *out);
void sha1_160(const void *key, int len, uint32_t seed, void *out);

void sha2_224(const void *key, int len, uint32_t seed, void *out);
void sha2_224_64(const void *key, int len, uint32_t seed, void *out);
void sha2_256(const void *key, int len, uint32_t seed, void *out);
void sha2_256_64(const void *key, int len, uint32_t seed, void *out);

void rmd128(const void *key, int len, uint32_t seed, void *out);
void rmd160(const void *key, int len, uint32_t seed, void *out);
void rmd256(const void *key, int len, uint32_t seed, void *out);

void blake2s128_test(const void *key, int len, uint32_t seed, void *out);
void blake2s160_test(const void *key, int len, uint32_t seed, void *out);
void blake2s224_test(const void *key, int len, uint32_t seed, void *out);
void blake2s256_test(const void *key, int len, uint32_t seed, void *out);
void blake2s256_64(const void *key, int len, uint32_t seed, void *out);
void blake2b160_test(const void *key, int len, uint32_t seed, void *out);
void blake2b224_test(const void *key, int len, uint32_t seed, void *out);
void blake2b256_test(const void *key, int len, uint32_t seed, void *out);
void blake2b256_64(const void *key, int len, uint32_t seed, void *out);

void sha3_256(const void *key, int len, uint32_t seed, void *out);
void sha3_256_64(const void *key, int len, uint32_t seed, void *out);

void tifuhash_64(const void * key, int len, uint32_t seed, void * out);
void floppsyhash_64(const void * key, int len, uint32_t seed, void * out);
void beamsplitter_64(const void * key, int len, uint32_t seed, void * out);

void o1hash_test (const void * key, int len, uint32_t seed, void * out);
void halftime_hash_style64_test(const void *key, int len, uint32_t seed, void *out);
void halftime_hash_style128_test(const void *key, int len, uint32_t seed, void *out);
void halftime_hash_style256_test(const void *key, int len, uint32_t seed, void *out);
void halftime_hash_style512_test(const void *key, int len, uint32_t seed, void *out);
