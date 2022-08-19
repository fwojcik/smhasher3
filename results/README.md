SMHasher3 results summary
=========================

[[_TOC_]]

Passing hashes
--------------

Hashes that currently pass all tests, sorted by average short input speed.

| Hash name | output width | test count | Avg. cycles (1-32 bytes) | Avg. bytes/cycle (bulk) |
|:----------|-------------:|-----------:|-------------------------:|------------------------:|
| [wyhash.strict](wyhash.strict.txt) | 64 | 204 |  37.29 |   5.74|
| [komihash](komihash.txt) | 64 | 204 |  38.86 |   6.45|
| [t1ha0.aesB](t1ha0.aesB.txt) | 64 | 204 |  46.79 |  19.62|
| [t1ha2-64](t1ha2-64.txt) | 64 | 204 |  46.85 |   4.56|
| [TinySipHash](TinySipHash.txt) | 64 | 204 |  47.70 |   1.50|
| [mum1.inexact.unroll2](mum1.inexact.unroll2.txt) | 64 | 204 |  52.68 |   1.26|
| [mum1.inexact.unroll4](mum1.inexact.unroll4.txt) | 64 | 204 |  52.81 |   1.86|
| [mum1.inexact.unroll3](mum1.inexact.unroll3.txt) | 64 | 204 |  53.38 |   1.26|
| [mir.inexact](mir.inexact.txt) | 64 | 204 |  54.69 |   1.33|
| [mx3.v1](mx3.v1.txt) | 64 | 204 |  55.87 |   3.15|
| [prvhash-64](prvhash-64.txt) | 64 | 204 |  56.33 |   0.93|
| [mum1.inexact.unroll1](mum1.inexact.unroll1.txt) | 64 | 204 |  56.76 |   1.19|
| [mx3.v2](mx3.v2.txt) | 64 | 204 |  57.45 |   3.18|
| [FarmHash-32.NT](FarmHash-32.NT.txt) | 32 | 243 |  57.46 |   7.74|
| [XXH-64](XXH-64.txt) | 64 | 204 |  58.78 |   3.99|
| [CityMurmur.seed3](CityMurmur.seed3.txt) | 128 | 205 |  63.03 |   2.53|
| [CityMurmur.seed2](CityMurmur.seed2.txt) | 128 | 205 |  63.06 |   2.53|
| [CityMurmur.seed1](CityMurmur.seed1.txt) | 128 | 205 |  63.10 |   2.53|
| [FarmHash-128.CM.seed1](FarmHash-128.CM.seed1.txt) | 128 | 205 |  63.20 |   2.66|
| [FarmHash-128.CM.seed2](FarmHash-128.CM.seed2.txt) | 128 | 205 |  63.42 |   2.63|
| [FarmHash-128.CM.seed3](FarmHash-128.CM.seed3.txt) | 128 | 205 |  63.91 |   2.66|
| [SpookyHash1-32](SpookyHash1-32.txt) | 32 | 243 |  64.72 |   4.38|
| [SpookyHash1-64](SpookyHash1-64.txt) | 64 | 204 |  64.72 |   4.38|
| [SpookyHash2-64](SpookyHash2-64.txt) | 64 | 204 |  66.38 |   4.38|
| [SpookyHash2-32](SpookyHash2-32.txt) | 32 | 243 |  66.39 |   4.38|
| [SpookyHash1-128](SpookyHash1-128.txt) | 128 | 205 |  69.38 |   4.38|
| [SpookyHash2-128](SpookyHash2-128.txt) | 128 | 205 |  70.64 |   4.38|
| [MeowHash](MeowHash.txt) | 128 | 205 |  77.01 |  11.79|
| [MeowHash.32](MeowHash.32.txt) | 32 | 243 |  77.01 |  11.79|
| [MeowHash.64](MeowHash.64.txt) | 64 | 204 |  77.01 |  11.79|
| [prvhash-128](prvhash-128.txt) | 128 | 205 |  86.09 |   0.93|
| [HalfSipHash](HalfSipHash.txt) | 32 | 243 |  87.19 |   0.34|
| [GoodOAAT](GoodOAAT.txt) | 32 | 243 |  90.33 |   0.24|
| [chaskey-8.32](chaskey-8.32.txt) | 32 | 243 | 100.00 |   0.37|
| [chaskey-8.64](chaskey-8.64.txt) | 64 | 204 | 101.05 |   0.37|
| [PearsonBlock-64](PearsonBlock-64.txt) | 64 | 204 | 108.34 |   0.57|
| [hasshe2.tweaked](hasshe2.tweaked.txt) | 256 | 205 | 111.40 |   0.76|
| [PearsonBlock-128](PearsonBlock-128.txt) | 128 | 205 | 117.34 |   0.53|
| [chaskey-8](chaskey-8.txt) | 128 | 205 | 127.81 |   0.38|
| [chaskey-12.32](chaskey-12.32.txt) | 32 | 243 | 129.10 |   0.25|
| [HalftimeHash-512](HalftimeHash-512.txt) | 64 | 204 | 131.12 |   9.32|
| [PearsonBlock-256](PearsonBlock-256.txt) | 256 | 205 | 146.42 |   0.46|
| [SipHash-1-3](SipHash-1-3.txt) | 64 | 204 | 165.15 |   0.38|
| [prvhash-64.incr](prvhash-64.incr.txt) | 64 | 204 | 189.92 |   2.36|
| [CityHashCrc-256](CityHashCrc-256.txt) | 256 | 205 | 191.87 |   5.31|
| [Discohash.old](Discohash.old.txt) | 64 | 204 | 217.33 |   1.34|
| [SipHash-2-4](SipHash-2-4.txt) | 64 | 204 | 224.07 |   0.19|
| [ascon-XOFa-32](ascon-XOFa-32.txt) | 32 | 243 | 396.40 |   0.07|
| [ascon-XOFa-64](ascon-XOFa-64.txt) | 64 | 204 | 408.23 |   0.07|
| [SHA-2-224.64](SHA-2-224.64.txt) | 64 | 204 | 415.13 |   0.45|
| [SHA-2-256.64](SHA-2-256.64.txt) | 64 | 204 | 415.63 |   0.45|
| [SHA-2-224](SHA-2-224.txt) | 224 | 205 | \*\* 420.04 |   0.45|
| [SHA-2-256](SHA-2-256.txt) | 256 | 205 | \*\* 436.61 |   0.45|
| [blake3](blake3.txt) | 256 | 205 | 483.81 |   0.35|
| [ascon-XOF-32](ascon-XOF-32.txt) | 32 | 243 | 492.70 |   0.05|
| [ascon-XOF-64](ascon-XOF-64.txt) | 64 | 204 | 493.33 |   0.05|
| [SHA-1.64](SHA-1.64.txt) | 64 | 204 | \*\* 503.67 |   0.47|
| [RIPEMD-128](RIPEMD-128.txt) | 128 | 205 | 506.47 |   0.15|
| [SHA-1](SHA-1.txt) | 128 | 205 | \*\* 507.04 |   0.47|
| [SHA-1.32](SHA-1.32.txt) | 32 | 243 | \*\* 511.44 |   0.47|
| [ascon-XOFa-128](ascon-XOFa-128.txt) | 128 | 205 | \*\* 514.68 |   0.07|
| [MD5.32](MD5.32.txt) | 32 | 243 | 545.52 |   0.14|
| [MD5](MD5.txt) | 128 | 205 | 549.97 |   0.14|
| [MD5.64](MD5.64.txt) | 64 | 204 | 550.33 |   0.14|
| [RIPEMD-256](RIPEMD-256.txt) | 256 | 205 | 593.60 |   0.12|
| [ascon-XOFa-160](ascon-XOFa-160.txt) | 160 | 205 | \*\* 642.23 |   0.07|
| [blake2s-256.64](blake2s-256.64.txt) | 64 | 204 | 660.79 |   0.11|
| [blake2s-256](blake2s-256.txt) | 256 | 205 | 661.34 |   0.11|
| [blake2s-128](blake2s-128.txt) | 128 | 205 | 662.11 |   0.11|
| [blake2s-160](blake2s-160.txt) | 160 | 205 | 662.24 |   0.11|
| [blake2s-224](blake2s-224.txt) | 224 | 205 | 667.02 |   0.11|
| [ascon-XOF-128](ascon-XOF-128.txt) | 128 | 205 | 679.13 |   0.05|
| [RIPEMD-160](RIPEMD-160.txt) | 160 | 205 | \*\* 760.60 |   0.09|
| [ascon-XOFa-256](ascon-XOFa-256.txt) | 256 | 205 | 768.95 |   0.07|
| [ascon-XOFa-224](ascon-XOFa-224.txt) | 224 | 205 | 788.13 |   0.07|
| [blake2b-256.64](blake2b-256.64.txt) | 64 | 204 | 793.01 |   0.18|
| [blake2b-160](blake2b-160.txt) | 160 | 205 | 794.98 |   0.18|
| [blake2b-128](blake2b-128.txt) | 128 | 205 | 796.59 |   0.18|
| [blake2b-256](blake2b-256.txt) | 256 | 205 | 822.07 |   0.18|
| [blake2b-224](blake2b-224.txt) | 224 | 205 | 824.04 |   0.18|
| [ascon-XOF-160](ascon-XOF-160.txt) | 160 | 205 | 845.54 |   0.05|
| [beamsplitter](beamsplitter.txt) | 64 | 204 | 971.12 |   0.21|
| [ascon-XOF-224](ascon-XOF-224.txt) | 224 | 205 | 1027.89 |   0.05|
| [ascon-XOF-256](ascon-XOF-256.txt) | 256 | 205 | 1038.11 |   0.05|
| [SHA-3-256.64](SHA-3-256.64.txt) | 64 | 204 | 3025.25 |   0.04|
| [SHA-3](SHA-3.txt) | 256 | 205 | 3036.27 |   0.04|


Failing hashes
--------------

Hashes that pass Sanity tests, but fail others, sorted by failing tests and then average short input speed.

| Hash name | output width | tests failed | test count | Avg. cycles (1-32 bytes) | Avg. bytes/cycle (bulk) |
|:----------|-------------:|-------------:|-----------:|-------------------------:|------------------------:|
| [mum3.exact.unroll2](mum3.exact.unroll2.txt) | 64 | 1 | 204 |  33.24 |   5.06|
| [mum3.exact.unroll4](mum3.exact.unroll4.txt) | 64 | 1 | 204 |  33.39 |   5.69|
| [mum3.exact.unroll3](mum3.exact.unroll3.txt) | 64 | 1 | 204 |  33.76 |   5.39|
| [wyhash](wyhash.txt) | 64 | 1 | 204 |  34.77 |   6.93|
| [mum3.exact.unroll1](mum3.exact.unroll1.txt) | 64 | 1 | 204 |  35.44 |   2.56|
| [wyhash-32](wyhash-32.txt) | 32 | 1 | 243 |  36.91 |   1.33|
| [mum1.exact.unroll4](mum1.exact.unroll4.txt) | 64 | 1 | 204 |  39.99 |   3.77|
| [mum1.exact.unroll2](mum1.exact.unroll2.txt) | 64 | 1 | 204 |  40.28 |   4.04|
| [mum1.exact.unroll1](mum1.exact.unroll1.txt) | 64 | 1 | 204 |  42.79 |   2.56|
| [mir.exact](mir.exact.txt) | 64 | 1 | 204 |  43.94 |   2.05|
| [t1ha0.aesA](t1ha0.aesA.txt) | 64 | 1 | 204 |  46.74 |   7.90|
| [fasthash-32](fasthash-32.txt) | 32 | 1 | 243 |  47.39 |   2.00|
| [UMASH-64.reseed](UMASH-64.reseed.txt) | 64 | 1 | 204 |  49.13 |   5.93|
| [FarmHash-64.TE](FarmHash-64.TE.txt) | 64 | 1 | 204 |  57.46 |   7.74|
| [CityHash-64](CityHash-64.txt) | 64 | 1 | 204 |  57.72 |   4.79|
| [FarmHash-64.UO](FarmHash-64.UO.txt) | 64 | 1 | 204 |  58.09 |   5.23|
| [FarmHash-64.NA](FarmHash-64.NA.txt) | 64 | 1 | 204 |  58.28 |   4.88|
| [MetroHash-128](MetroHash-128.txt) | 128 | 1 | 205 |  58.97 |   5.22|
| [t1ha2-128](t1ha2-128.txt) | 128 | 1 | 205 |  63.01 |   4.86|
| [pengyhash](pengyhash.txt) | 64 | 1 | 204 |  74.44 |   4.54|
| [CLhash.bitmix](CLhash.bitmix.txt) | 64 | 1 | 204 |  74.51 |   7.31|
| [VHASH.32](VHASH.32.txt) | 32 | 1 | 243 | 101.37 |   4.95|
| [HalftimeHash-128](HalftimeHash-128.txt) | 64 | 1 | 204 | 102.37 |   6.76|
| [HalftimeHash-64](HalftimeHash-64.txt) | 64 | 1 | 204 | 103.42 |   2.11|
| [HalftimeHash-256](HalftimeHash-256.txt) | 64 | 1 | 204 | 107.31 |  11.59|
| [chaskey-12.64](chaskey-12.64.txt) | 64 | 1 | 204 | 131.48 |   0.25|
| [chaskey-12](chaskey-12.txt) | 128 | 1 | 205 | 157.93 |   0.25|
| [XXH3-64](XXH3-64.txt) | 64 | 2 | 204 |  36.45 |  12.31|
| [mum1.exact.unroll3](mum1.exact.unroll3.txt) | 64 | 2 | 204 |  40.42 |   4.04|
| [fasthash-64](fasthash-64.txt) | 64 | 2 | 204 |  45.63 |   2.00|
| [XXH3-128](XXH3-128.txt) | 128 | 2 | 205 |  45.92 |  12.31|
| [MetroHash-64.var2](MetroHash-64.var2.txt) | 64 | 2 | 204 |  48.67 |   4.96|
| [MetroHash-128.var1](MetroHash-128.var1.txt) | 128 | 2 | 205 |  59.51 |   5.05|
| [UMASH-128.reseed](UMASH-128.reseed.txt) | 128 | 2 | 205 |  61.38 |   3.70|
| [CityHash-128.seed2](CityHash-128.seed2.txt) | 128 | 2 | 205 |  62.94 |   4.49|
| [CityHash-128.seed3](CityHash-128.seed3.txt) | 128 | 2 | 205 |  62.96 |   4.49|
| [CityHash-128.seed1](CityHash-128.seed1.txt) | 128 | 2 | 205 |  63.07 |   4.49|
| [CityHashCrc-128.seed3](CityHashCrc-128.seed3.txt) | 128 | 2 | 205 |  63.10 |   5.31|
| [CityHashCrc-128.seed1](CityHashCrc-128.seed1.txt) | 128 | 2 | 205 |  63.14 |   5.31|
| [CityHashCrc-128.seed2](CityHashCrc-128.seed2.txt) | 128 | 2 | 205 |  63.16 |   5.31|
| [FarmHash-128.CC.seed1](FarmHash-128.CC.seed1.txt) | 128 | 2 | 205 |  63.35 |   4.82|
| [FarmHash-128.CC.seed2](FarmHash-128.CC.seed2.txt) | 128 | 2 | 205 |  63.70 |   4.68|
| [FarmHash-128.CC.seed3](FarmHash-128.CC.seed3.txt) | 128 | 2 | 205 |  63.93 |   4.68|
| [prvhash-128.incr](prvhash-128.incr.txt) | 128 | 2 | 205 | 284.73 |   1.98|
| [floppsyhash](floppsyhash.txt) | 64 | 2 | 204 | \*\* 744.99 |   0.05|
| [MetroHash-64](MetroHash-64.txt) | 64 | 3 | 204 |  48.56 |   5.08|
| [MurmurHash3-128](MurmurHash3-128.txt) | 128 | 3 | 205 |  49.42 |   2.17|
| [MurmurHash3-32](MurmurHash3-32.txt) | 32 | 3 | 243 |  50.61 |   0.99|
| [seahash](seahash.txt) | 64 | 3 | 204 |  61.49 |   2.71|
| [VHASH](VHASH.txt) | 64 | 4 | 204 | 101.48 |   4.96|
| [floppsyhash.old](floppsyhash.old.txt) | 64 | 4 | 204 | \*\* 711.12 |   0.04|
| [mum2.inexact.unroll1](mum2.inexact.unroll1.txt) | 64 | 6 | 204 |  48.18 |   1.19|
| [UMASH-64](UMASH-64.txt) | 64 | 6 | 204 |  48.19 |   5.93|
| [FarmHash-32.SA](FarmHash-32.SA.txt) | 32 | 6 | 243 |  48.49 |   4.48|
| [t1ha0](t1ha0.txt) | 64 | 6 | 204 |  51.57 |   2.40|
| [MetroHashCrc-128.var1](MetroHashCrc-128.var1.txt) | 128 | 6 | 205 |  64.88 |   7.80|
| [MetroHashCrc-128.var2](MetroHashCrc-128.var2.txt) | 128 | 6 | 205 |  64.90 |   7.80|
| [falkhash1](falkhash1.txt) | 128 | 6 | 205 |  89.05 |  18.82|
| [mum2.exact.unroll1](mum2.exact.unroll1.txt) | 64 | 7 | 204 |  38.59 |   2.62|
| [mum2.inexact.unroll2](mum2.inexact.unroll2.txt) | 64 | 7 | 204 |  44.06 |   1.26|
| [MetroHash-128.var2](MetroHash-128.var2.txt) | 128 | 7 | 205 |  59.01 |   5.05|
| [UMASH-128](UMASH-128.txt) | 128 | 7 | 205 |  61.49 |   3.70|
| [falkhash2](falkhash2.txt) | 128 | 7 | 205 |  93.08 |  16.86|
| [mum2.exact.unroll2](mum2.exact.unroll2.txt) | 64 | 8 | 204 |  36.95 |   4.04|
| [MetroHash-64.var1](MetroHash-64.var1.txt) | 64 | 8 | 204 |  48.52 |   4.96|
| [FarmHash-32.SU](FarmHash-32.SU.txt) | 32 | 8 | 243 |  48.77 |   5.27|
| [mum2.exact.unroll3](mum2.exact.unroll3.txt) | 64 | 9 | 204 |  36.30 |   4.05|
| [mum2.inexact.unroll3](mum2.inexact.unroll3.txt) | 64 | 9 | 204 |  44.36 |   1.26|
| [NMHASH](NMHASH.txt) | 32 | 9 | 243 |  71.39 |   7.37|
| [NMHASHX](NMHASHX.txt) | 32 | 10 | 243 |  45.71 |   7.38|
| [FarmHash-32.CC](FarmHash-32.CC.txt) | 32 | 10 | 243 |  48.89 |   1.89|
| [FarmHash-32.MK](FarmHash-32.MK.txt) | 32 | 10 | 243 |  49.42 |   1.64|
| [t1ha1](t1ha1.txt) | 64 | 11 | 204 |  36.37 |   4.48|
| [mum2.exact.unroll4](mum2.exact.unroll4.txt) | 64 | 11 | 204 |  36.39 |   3.76|
| [mum2.inexact.unroll4](mum2.inexact.unroll4.txt) | 64 | 11 | 204 |  44.09 |   1.86|
| [Discohash](Discohash.txt) | 64 | 11 | 204 | 236.19 |   1.34|
| [CityHash-32](CityHash-32.txt) | 32 | 14 | 243 |  52.14 |   1.85|
| [MetroHashCrc-64.var1](MetroHashCrc-64.var1.txt) | 64 | 14 | 204 |  52.33 |   7.80|
| [t1ha2-64.incr](t1ha2-64.incr.txt) | 64 | 20 | 204 |  84.74 |   4.58|
| [MetroHashCrc-64.var2](MetroHashCrc-64.var2.txt) | 64 | 22 | 204 |  52.23 |   7.80|
| [t1ha2-128.incr](t1ha2-128.incr.txt) | 128 | 23 | 205 | 103.10 |   4.58|
| [MurmurHash2a](MurmurHash2a.txt) | 32 | 24 | 243 |  49.78 |   1.00|
| [PMP-Multilinear-64](PMP-Multilinear-64.txt) | 64 | 29 | 204 |  56.93 |   4.15|
| [lookup3.32](lookup3.32.txt) | 32 | 37 | 243 |  42.28 |   0.80|
| [MurmurHash2-32](MurmurHash2-32.txt) | 32 | 48 | 243 |  44.98 |   1.00|
| [MurmurHash2-64](MurmurHash2-64.txt) | 64 | 51 | 204 |  46.05 |   2.00|
| [Discohash-128.old](Discohash-128.old.txt) | 128 | 51 | 205 | 217.37 |   1.34|
| [Discohash-128](Discohash-128.txt) | 128 | 51 | 205 | 227.40 |   1.34|
| [perl-jenkins-hard](perl-jenkins-hard.txt) | 32 | 55 | 243 | 121.01 |   0.20|
| [Crap8](Crap8.txt) | 32 | 57 | 243 |  39.84 |   1.00|
| [MurmurHash1](MurmurHash1.txt) | 32 | 79 | 243 |  52.37 |   0.67|
| [mum3.inexact.unroll2](mum3.inexact.unroll2.txt) | 64 | 82 | 204 |  39.69 |   1.75|
| [mum3.inexact.unroll3](mum3.inexact.unroll3.txt) | 64 | 82 | 204 |  40.93 |   1.91|
| [mum3.inexact.unroll4](mum3.inexact.unroll4.txt) | 64 | 82 | 204 |  41.59 |   1.97|
| [mum3.inexact.unroll1](mum3.inexact.unroll1.txt) | 64 | 82 | 204 |  44.75 |   1.40|
| [XXH-32](XXH-32.txt) | 32 | 83 | 243 |  50.53 |   2.00|
| [perl-jenkins](perl-jenkins.txt) | 32 | 85 | 243 | 101.00 |   0.20|
| [MurmurHash2-64.int32](MurmurHash2-64.int32.txt) | 64 | 97 | 204 |  47.62 |   1.33|
| [lookup3](lookup3.txt) | 64 | 101 | 204 |  42.42 |   0.80|
| [PMP-Multilinear-32](PMP-Multilinear-32.txt) | 32 | 116 | 243 |  46.96 |   0.84|
| [MurmurHash3-128.int32](MurmurHash3-128.int32.txt) | 128 | 118 | 205 |  53.02 |   1.61|
| [CLhash](CLhash.txt) | 64 | 144 | 204 |  58.37 |   6.24|
| [Pearson-128](Pearson-128.txt) | 128 | 179 | 205 | 158.07 |   0.11|
| [Pearson-256](Pearson-256.txt) | 256 | 182 | 205 | 162.06 |   0.11|
| [Pearson-64](Pearson-64.txt) | 64 | 182 | 204 | 162.10 |   0.11|
| [multiply-shift](multiply-shift.txt) | 64 | 187 | 204 |  30.03 |   1.96|
| [pair-multiply-shift](pair-multiply-shift.txt) | 64 | 187 | 204 |  31.36 |   1.82|
| [FNV-1a-64](FNV-1a-64.txt) | 64 | 193 | 204 |  79.01 |   0.25|
| [Fletcher-64](Fletcher-64.txt) | 64 | 195 | 204 |  39.20 |   2.00|
| [FNV-YoshimitsuTRIAD](FNV-YoshimitsuTRIAD.txt) | 32 | 200 | 243 |  32.25 |   5.12|
| [FNV-1a-32](FNV-1a-32.txt) | 32 | 206 | 243 |  79.03 |   0.25|
| [pair-multiply-shift-32](pair-multiply-shift-32.txt) | 32 | 207 | 243 |  29.00 |   2.65|
| [multiply-shift-32](multiply-shift-32.txt) | 32 | 215 | 243 |  24.04 |   2.16|
| [CRC-32C](CRC-32C.txt) | 32 | 222 | 243 |  36.74 |   7.63|
| [MicroOAAT](MicroOAAT.txt) | 32 | 226 | 243 |  82.49 |   0.24|
| [jodyhash-32](jodyhash-32.txt) | 32 | 230 | 243 |  46.01 |   0.57|
| [SuperFastHash](SuperFastHash.txt) | 32 | 232 | 243 |  54.05 |   0.67|
| [perl-sdbm](perl-sdbm.txt) | 32 | 233 | 243 |  76.00 |   0.25|
| [Fletcher-32](Fletcher-32.txt) | 32 | 235 | 243 |  39.50 |   0.97|
| [perl-djb2](perl-djb2.txt) | 32 | 237 | 243 |  62.08 |   0.33|
| [x17](x17.txt) | 32 | 238 | 243 |  78.10 |   0.25|


Unusable hashes
---------------

Hashes that fail Sanity tests, sorted by failing tests and then average short input speed.

| Hash name | output width | tests failed | test count | Avg. cycles (1-32 bytes) | Avg. bytes/cycle (bulk) |
|:----------|-------------:|-------------:|-----------:|-------------------------:|------------------------:|
| [tabulation-64](tabulation-64.txt) | 64 | 1 | 204 |  43.77 |   3.00|
| [aesrng-32](aesrng-32.txt) | 32 | 2 | 243 |  \*\* 17.49 | 2509.84|
| [aesrng-64](aesrng-64.txt) | 64 | 2 | 204 |  \*\* 19.48 | 2507.47|
| [aesrng-128](aesrng-128.txt) | 128 | 2 | 205 |  \*\* 22.88 | 2168.29|
| [aesrng-160](aesrng-160.txt) | 160 | 2 | 205 |  \*\* 27.94 | 2102.37|
| [aesrng-224](aesrng-224.txt) | 224 | 2 | 205 |  35.78 | 1993.52|
| [aesrng-256](aesrng-256.txt) | 256 | 2 | 205 |  35.78 | 1996.32|
| [poly-mersenne.deg3](poly-mersenne.deg3.txt) | 32 | 2 | 243 |  78.62 |   0.50|
| [poly-mersenne.deg4](poly-mersenne.deg4.txt) | 32 | 2 | 243 |  87.79 |   0.50|
| [hasshe2](hasshe2.txt) | 256 | 15 | 205 | 111.30 |   0.76|
| [FARSH-32](FARSH-32.txt) | 32 | 17 | 243 |  68.65 |  15.29|
| [FARSH-64](FARSH-64.txt) | 64 | 17 | 204 | 117.03 |   7.78|
| [FARSH-256](FARSH-256.txt) | 256 | 17 | 205 | \*\* 456.72 |   1.97|
| [aesnihash](aesnihash.txt) | 64 | 18 | 204 |  68.18 |   1.45|
| [FARSH-128](FARSH-128.txt) | 128 | 18 | 205 | 236.21 |   3.87|
| [poly-mersenne.deg2](poly-mersenne.deg2.txt) | 32 | 19 | 243 |  69.52 |   0.50|
| [CrapWow-64](CrapWow-64.txt) | 64 | 53 | 204 |  36.29 |   4.59|
| [CrapWow](CrapWow.txt) | 32 | 58 | 243 |  31.95 |   2.31|
| [khash-64](khash-64.txt) | 64 | 64 | 204 |  48.04 |   1.55|
| [MurmurOAAT](MurmurOAAT.txt) | 32 | 75 | 243 | 111.01 |   0.17|
| [tabulation-32](tabulation-32.txt) | 32 | 109 | 243 |  34.59 |   2.20|
| [perl-jenkins-old](perl-jenkins-old.txt) | 32 | 112 | 243 | 101.02 |   0.20|
| [FNV-PippipYurii](FNV-PippipYurii.txt) | 32 | 153 | 243 |  37.49 |   2.00|
| [khash-32](khash-32.txt) | 32 | 153 | 243 |  55.53 |   1.39|
| [jodyhash-64](jodyhash-64.txt) | 64 | 192 | 204 |  39.22 |   1.14|
| [FNV-1a-64.wordwise](FNV-1a-64.wordwise.txt) | 64 | 196 | 204 |  40.83 |   2.00|
| [fletcher2.64](fletcher2.64.txt) | 64 | 198 | 204 |  27.25 |   4.88|
| [fletcher4](fletcher4.txt) | 256 | 199 | 205 |  33.99 |   1.91|
| [fibonacci-64](fibonacci-64.txt) | 64 | 200 | 204 |  28.56 |   9.35|
| [fletcher2](fletcher2.txt) | 128 | 200 | 205 |  30.27 |   4.88|
| [o1hash](o1hash.txt) | 64 | 201 | 204 |  20.83 | 3744.01|
| [fletcher4.64](fletcher4.64.txt) | 64 | 201 | 204 |  27.46 |   1.91|
| [donothing-64](donothing-64.txt) | 64 | 203 | 204 |   5.00 | 3744.01|
| [donothingOAAT-64](donothingOAAT-64.txt) | 64 | 203 | 204 |  40.34 |   0.87|
| [donothing-128](donothing-128.txt) | 128 | 204 | 205 |   5.00 | 3744.01|
| [donothingOAAT-128](donothingOAAT-128.txt) | 128 | 204 | 205 |  40.12 |   0.88|
| [FNV-Totenschiff](FNV-Totenschiff.txt) | 32 | 207 | 243 |  35.97 |   2.00|
| [poly-mersenne.deg1](poly-mersenne.deg1.txt) | 32 | 217 | 243 |  61.02 |   0.49|
| [FNV-1a-32.wordwise](FNV-1a-32.wordwise.txt) | 32 | 233 | 243 |  35.68 |   1.00|
| [badhash](badhash.txt) | 32 | 233 | 243 |  \*\* 81.04 |   0.23|
| [fibonacci-32](fibonacci-32.txt) | 32 | 239 | 243 |  23.69 |  15.17|
| [sum32hash](sum32hash.txt) | 32 | 240 | 243 |  20.80 |  25.11|
| [sum8hash](sum8hash.txt) | 32 | 240 | 243 |  30.04 |   3.35|
| [donothing-32](donothing-32.txt) | 32 | 242 | 243 |   5.00 | 3744.01|
| [donothingOAAT-32](donothingOAAT-32.txt) | 32 | 242 | 243 |  39.98 |   0.88|

All results were generated using: SMHasher3 beta1-9080935e

[\*\*]: this result had >= 1% std. deviation in >=25% of tests, and so may not be reliable
