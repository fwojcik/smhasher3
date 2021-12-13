Collect interesting hashes
===

`NMHASH32`/`NMHASH32X`
---

32bit hash, the core loop is constructed of invertible operations, and the multiplications are limited to `16x16->16`. For better speed on short keys, the limitation is loosen to `32x32->32` multiplication in the `NMHASH32X` variant when hashing the short keys or avalanching the final result of the core loop.

### integer bijections in `NMHASH32`/`NMHASH32X`


except common [operations](https://marc-b-reynolds.github.io/math/2017/10/13/IntegerBijections.html), some compound ones are used:

```c
x ^= x << a | x << b; // a != b
x ^= x >> a | x >> b; // a != b
x ^= x << a | x >> b; // a != b && a + b != 32 && a % b != 0 && b % a != 0

// dot_prod_16
x = ((x >> 16) * M1) << 16 | (x * M2 & 0xFFFF); // M1, M2 are odd
```

### Quality

Both hashes are the same high quality, and pass the checking:

- [rurban/smhasher](https://github.com/rurban/smhasher), including LongNeighbors and BadSeeds
- [demerphq/smhasher](https://github.com/demerphq/smhasher/)
- [massive collision tester](https://github.com/Cyan4973/xxHash/tree/dev/tests/collisions), 1G, len=8,16,256


### Speed

For large keys, the hash is optmized for SSE2/AVX2/AVX512, and archive about 60% speed of `XXH3` in `Gb/s`. For short keys, `NMHASH32X` is a little faster than `xxhash32`.
