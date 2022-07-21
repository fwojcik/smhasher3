#define G(r,i,a,b,c,d)                     \
  do {                                     \
    a = a + b + m[blake2_sigma[r][2*i+0]]; \
    d = ROTR64(d ^ a, 32);                 \
    c = c + d;                             \
    b = ROTR64(b ^ c, 24);                 \
    a = a + b + m[blake2_sigma[r][2*i+1]]; \
    d = ROTR64(d ^ a, 16);                 \
    c = c + d;                             \
    b = ROTR64(b ^ c, 63);                 \
  } while(0)

#define ROUND(r)                    \
  do {                              \
    G(r,0,v[ 0],v[ 4],v[ 8],v[12]); \
    G(r,1,v[ 1],v[ 5],v[ 9],v[13]); \
    G(r,2,v[ 2],v[ 6],v[10],v[14]); \
    G(r,3,v[ 3],v[ 7],v[11],v[15]); \
    G(r,4,v[ 0],v[ 5],v[10],v[15]); \
    G(r,5,v[ 1],v[ 6],v[11],v[12]); \
    G(r,6,v[ 2],v[ 7],v[ 8],v[13]); \
    G(r,7,v[ 3],v[ 4],v[ 9],v[14]); \
} while(0)

template <bool bswap>
static void blake2_compress( blake2b_context * ctx, const uint8_t * in ) {
    uint64_t m[16];
    uint64_t v[16];
    size_t   i;

    for (i = 0; i < 16; ++i) {
        m[i] = GET_U64<bswap>(in, i * sizeof(m[i]));
    }

    for (i = 0; i < 8; ++i) {
        v[i] = ctx->h[i];
    }

    v[ 8] = blake2b_IV[0];
    v[ 9] = blake2b_IV[1];
    v[10] = blake2b_IV[2];
    v[11] = blake2b_IV[3];
    v[12] = blake2b_IV[4] ^ ctx->t[0];
    v[13] = blake2b_IV[5] ^ ctx->t[1];
    v[14] = blake2b_IV[6] ^ ctx->f[0];
    v[15] = blake2b_IV[7] ^ ctx->f[1];

    ROUND( 0);
    ROUND( 1);
    ROUND( 2);
    ROUND( 3);
    ROUND( 4);
    ROUND( 5);
    ROUND( 6);
    ROUND( 7);
    ROUND( 8);
    ROUND( 9);
    ROUND(10);
    ROUND(11);

    for (i = 0; i < 8; ++i) {
        ctx->h[i] = ctx->h[i] ^ v[i] ^ v[i + 8];
    }
}

#undef G

#define G(r,i,a,b,c,d)                     \
  do {                                     \
    a = a + b + m[blake2_sigma[r][2*i+0]]; \
    d = ROTR32(d ^ a, 16);                 \
    c = c + d;                             \
    b = ROTR32(b ^ c, 12);                 \
    a = a + b + m[blake2_sigma[r][2*i+1]]; \
    d = ROTR32(d ^ a,  8);                 \
    c = c + d;                             \
    b = ROTR32(b ^ c,  7);                 \
  } while(0)

template <bool bswap>
static void blake2_compress( blake2s_context * ctx, const uint8_t * in ) {
    uint32_t m[16];
    uint32_t v[16];
    size_t   i;

    for (i = 0; i < 16; ++i) {
        m[i] = GET_U32<bswap>(in, i * sizeof(m[i]));
    }

    for (i = 0; i < 8; ++i) {
        v[i] = ctx->h[i];
    }

    v[ 8] = blake2s_IV[0];
    v[ 9] = blake2s_IV[1];
    v[10] = blake2s_IV[2];
    v[11] = blake2s_IV[3];
    v[12] = blake2s_IV[4] ^ ctx->t[0];
    v[13] = blake2s_IV[5] ^ ctx->t[1];
    v[14] = blake2s_IV[6] ^ ctx->f[0];
    v[15] = blake2s_IV[7] ^ ctx->f[1];

    ROUND(0);
    ROUND(1);
    ROUND(2);
    ROUND(3);
    ROUND(4);
    ROUND(5);
    ROUND(6);
    ROUND(7);
    ROUND(8);
    ROUND(9);

    for (i = 0; i < 8; ++i) {
        ctx->h[i] = ctx->h[i] ^ v[i] ^ v[i + 8];
    }
}

#undef G
#undef ROUND
