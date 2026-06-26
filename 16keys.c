/*
FINAL IMPLEMENTATION WITH CA ENCRYPTION
*/

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

#define NUM_KEYS 16
#define KEY_SIZE 64
#define MAX_BITS 1024

// ================= ROTATE =================

uint64_t ROTR(uint64_t x,int n)
{
    return (x>>n)|(x<<(64-n));
}

// ================= SHA512 CONSTANTS =================

static const uint64_t K[80] = {
0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,
0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,
0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
0xd807aa98a3030242ULL,0x12835b0145706fbeULL,
0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,
0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,
0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,
0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,
0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,
0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,
0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,
0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,
0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
0xd192e819d6ef5218ULL,0xd69906245565a910ULL,
0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,
0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,
0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,
0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,
0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
0xca273eceea26619cULL,0xd186b8c721c0c207ULL,
0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,
0x113f9804bef90daeULL,0x1b710b35131c471bULL,
0x28db77f523047d84ULL,0x32caab7b40c72493ULL,
0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,
0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL
};

// ================= SHA512 =================

void sha512(const uint8_t *msg,size_t len,uint8_t hash[64])
{
    uint64_t H[8]={
    0x6a09e667f3bcc908ULL,0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL,0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL,0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL,0x5be0cd19137e2179ULL};

    uint8_t block[128]={0};
    memcpy(block,msg,len);
    block[len]=0x80;

    uint64_t bitlen=len*8;
    memcpy(block+120,&bitlen,8);

    uint64_t W[80];

    for(int i=0;i<16;i++)
        memcpy(&W[i],block+i*8,8);

    for(int i=16;i<80;i++)
    {
        uint64_t s0=ROTR(W[i-15],1)^ROTR(W[i-15],8)^(W[i-15]>>7);
        uint64_t s1=ROTR(W[i-2],19)^ROTR(W[i-2],61)^(W[i-2]>>6);
        W[i]=W[i-16]+s0+W[i-7]+s1;
    }

    uint64_t a=H[0],b=H[1],c=H[2],d=H[3];
    uint64_t e=H[4],f=H[5],g=H[6],h=H[7];

    for(int i=0;i<80;i++)
    {
        uint64_t S1=ROTR(e,14)^ROTR(e,18)^ROTR(e,41);
        uint64_t ch=(e&f)^((~e)&g);
        uint64_t temp1=h+S1+ch+K[i]+W[i];

        uint64_t S0=ROTR(a,28)^ROTR(a,34)^ROTR(a,39);
        uint64_t maj=(a&b)^(a&c)^(b&c);
        uint64_t temp2=S0+maj;

        h=g; g=f; f=e;
        e=d+temp1;
        d=c; c=b; b=a;
        a=temp1+temp2;
    }

    H[0]+=a; H[1]+=b; H[2]+=c; H[3]+=d;
    H[4]+=e; H[5]+=f; H[6]+=g; H[7]+=h;

    memcpy(hash,H,64);
}

// ================= LOGISTIC MAP =================

double logistic(double x)
{
    return 3.99*x*(1-x);
}

// ================= XOR FOLD =================

void xor_fold(uint8_t key[64], uint8_t folded[8])
{
    memset(folded,0,8);

    for(int block=0;block<8;block++)
        for(int i=0;i<8;i++)
            folded[i]^=key[block*8+i];
}

uint32_t xor_fold_4bytes(uint8_t folded8[8])
{
    uint32_t forward=0;

    for(int i=0;i<4;i++)
    {
        uint8_t value=folded8[i]^folded8[i+4];
        forward=(forward<<8)|value;
    }

    return forward;
}

// ================= CA STEP =================

void ca_step(uint8_t state[],int size,uint32_t rule)
{
    uint8_t next[MAX_BITS];
    uint8_t ca_rule = rule & 0xFF;

    for(int i=0;i<size;i++)
    {
        int left   = state[(i-1+size)%size];
        int center = state[i];
        int right  = state[(i+1)%size];

        int index=(left<<2)|(center<<1)|right;
        next[i]=(ca_rule>>index)&1;
    }

    for(int i=0;i<size;i++)
        state[i]=next[i];
}
// ================= CA MIX (FORWARD + BACKWARD + PLAINTEXT) =================

void ca_mix(uint8_t state[], uint8_t input[], int size,
            uint32_t ruleF, uint32_t ruleB)
{
    uint8_t next[MAX_BITS];

    uint8_t ruleF8 = ruleF & 0xFF;
    uint8_t ruleB8 = ruleB & 0xFF;

    for(int i=0;i<size;i++)
    {
        int left   = state[(i-1+size)%size];
        int center = state[i];
        int right  = state[(i+1)%size];

        int index = (left<<2)|(center<<1)|right;

        int f = (ruleF8 >> index) & 1;
        int b = (ruleB8 >> index) & 1;

        next[i] = f ^ b ^ input[i];
    }

    for(int i=0;i<size;i++)
        state[i] = next[i];
}

// ================= RANDOM FRACTION GENERATOR =================

uint64_t generate_random_fraction_bits_from_result(const uint8_t hash[32])
{
    const double denom = 2097152.0; // 2^21
    double total_sum = 0.0;

    printf("\n--- Random Fraction Bit Generation (64-bit Binary of Fraction Only) ---\n");

    for (int i = 0; i < 32; ++i)
    {
        double Bi = (double)hash[i];
        double term = ((223.0 + Bi) * Bi) / denom;

        if (!isfinite(term) || term < 0.0)
            term = 0.0;

        printf("B[%2d] = 0x%02X (%3d) -> term = ((223 + %3.0f) * %3.0f) / 2^21 = %.18f\n",
               i, hash[i], hash[i], Bi, Bi, term);

        total_sum += term;
    }

    if (!isfinite(total_sum) || total_sum < 0.0)
        total_sum = fabs(total_sum);

    double integer_part = 0.0;
    double frac = modf(total_sum, &integer_part);

    printf("\n=== Final Summation ===\n");
    printf("Total sum        = %.18f\n", total_sum);
    printf("Integer part     = %.0f\n", integer_part);
    printf("Fractional part  = %.18f\n", frac);

    printf("Binary (64-bit fraction, repeated pattern): ");

    char frac_bits[65] = {0};
    double temp = frac;
    int bit_count = 0;

    for (int i = 0; i < 16; ++i)
    {
        temp *= 2.0;
        int bit = (int)temp;
        frac_bits[i] = bit ? '1' : '0';
        temp -= bit;
        bit_count++;

        if (temp == 0.0)
            break;
    }

    if (bit_count == 0)
    {
        strcpy(frac_bits, "0");
        bit_count = 1;
    }

    uint64_t bits = 0;

    for (int i = 0; i < 64; ++i)
    {
        int bit = (frac_bits[i % bit_count] == '1') ? 1 : 0;
        bits = (bits << 1) | bit;
        putchar(bit ? '1' : '0');
    }

    printf("\n");

    return bits;
}

// ================= SHA256 =================

#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

uint32_t k256[64]={
1116352408,1899447441,3049323471,3921009573,
961987163,1508970993,2453635748,2870763221,
3624381080,310598401,607225278,1426881987,
1925078388,2162078206,2614888103,3248222580,
3835390401,4022224774,264347078,604807628,
770255983,1249150122,1555081692,1996064986,
2554220882,2821834349,2952996808,3210313671,
3336571891,3584528711,113926993,338241895,
666307205,773529912,1294757372,1396182291,
1695183700,1986661051,2177026350,2456956037,
2730485921,2820302411,3259730800,3345764771,
3516065817,3600352804,4094571909,275423344,
430227734,506948616,659060556,883997877,
958139571,1322822218,1537002063,1747873779,
1955562222,2024104815,2227730452,2361852424,
2428436474,2756734187,3204031479,3329325298
};

void sha256(const uint8_t *msg,size_t len,uint8_t hash[32])
{
    uint32_t h[8]={
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };

    uint8_t block[64]={0};

    /* copy message */
    memcpy(block,msg,len);

    /* append the 1 bit */
    block[len]=0x80;

    /* append message length in BIG ENDIAN */
    uint64_t bitlen=len*8;

    for(int i=0;i<8;i++)
    {
        block[63-i]=bitlen & 0xFF;
        bitlen >>=8;
    }

    uint32_t w[64];

    for(int i=0;i<16;i++)
        w[i]=(block[i*4]<<24)|(block[i*4+1]<<16)|(block[i*4+2]<<8)|block[i*4+3];

    for(int i=16;i<64;i++)
    {
        uint32_t s0=ROTRIGHT(w[i-15],7)^ROTRIGHT(w[i-15],18)^(w[i-15]>>3);
        uint32_t s1=ROTRIGHT(w[i-2],17)^ROTRIGHT(w[i-2],19)^(w[i-2]>>10);
        w[i]=w[i-16]+s0+w[i-7]+s1;
    }

    uint32_t a=h[0],b=h[1],c=h[2],d=h[3];
    uint32_t e=h[4],f=h[5],g=h[6],hh=h[7];

    for(int i=0;i<64;i++)
    {
        uint32_t S1=ROTRIGHT(e,6)^ROTRIGHT(e,11)^ROTRIGHT(e,25);
        uint32_t ch=(e&f)^((~e)&g);
        uint32_t temp1=hh+S1+ch+k256[i]+w[i];

        uint32_t S0=ROTRIGHT(a,2)^ROTRIGHT(a,13)^ROTRIGHT(a,22);
        uint32_t maj=(a&b)^(a&c)^(b&c);
        uint32_t temp2=S0+maj;

        hh=g;
        g=f;
        f=e;
        e=d+temp1;
        d=c;
        c=b;
        b=a;
        a=temp1+temp2;
    }

    h[0]+=a;
    h[1]+=b;
    h[2]+=c;
    h[3]+=d;
    h[4]+=e;
    h[5]+=f;
    h[6]+=g;
    h[7]+=hh;

    for(int i=0;i<8;i++)
    {
        hash[i*4]=(h[i]>>24)&0xFF;
        hash[i*4+1]=(h[i]>>16)&0xFF;
        hash[i*4+2]=(h[i]>>8)&0xFF;
        hash[i*4+3]=h[i]&0xFF;
    }
}

// ================= MAIN =================

int main()
{
    char password[256];
    printf("Enter password: ");
    scanf("%s",password);

    uint8_t digest[64];
    sha512((uint8_t*)password,strlen(password),digest);

    double x=0;
    for(int i=0;i<8;i++)
        x+=digest[i]/pow(256,i+1);

    uint8_t keys[NUM_KEYS][KEY_SIZE];

    for(int k=0;k<NUM_KEYS;k++)
        for(int j=0;j<KEY_SIZE;j++)
        {
            x=logistic(x);
            keys[k][j]=(uint8_t)(x*256);
        }

    uint8_t folded[NUM_KEYS][8];
    uint32_t forward_rules[NUM_KEYS];

    for(int i=0;i<NUM_KEYS;i++)
    {
        xor_fold(keys[i],folded[i]);
        forward_rules[i]=xor_fold_4bytes(folded[i]);
    }

    printf("\nCA RULES\n");

    for(int i=0;i<NUM_KEYS;i++)
    {
        printf("Key %d Forward:%08X Backward:%08X\n",
        i+1,forward_rules[i],0xFFFFFFFF-forward_rules[i]);
    }

    // PLAINTEXT

    char plaintext[256];

    getchar();
    printf("Enter plaintext: ");
    fgets(plaintext,256,stdin);

    plaintext[strcspn(plaintext,"\n")]=0;
    printf("\nPlaintext Entered:\n%s\n",plaintext);

    uint8_t hash256[32];
    sha256((uint8_t*)plaintext,strlen(plaintext),hash256);

    printf("\nSHA256 of Plaintext:\n");
for(int i=0;i<32;i++)
    printf("%02X",hash256[i]);
printf("\n");

/* Generate random fraction bits */
uint64_t rand64 = generate_random_fraction_bits_from_result(hash256);

printf("\nGenerated 64-bit Random Fraction:\n%016llX\n",rand64);

    uint8_t residual[8];

    for(int i=0;i<8;i++)
        residual[i]=(rand64>>(56-8*i))&0xFF;

    printf("\nInitial Residual Random Data:\n");

    for(int i=0;i<8;i++)
        printf("%02X ",residual[i]);

    printf("\n");

    // ================= PROCESS PLAINTEXT BLOCKS =================

int len = strlen(plaintext);
int blocks = (len+7)/8;

printf("\nTotal Blocks: %d\n",blocks);

for(int b=0;b<blocks;b++)
{
    printf("\n=== Processing Block %d ===\n",b+1);

    uint8_t plaintext_block[8]={0};

    for(int i=0;i<8;i++)
    {
        int index=b*8+i;

        if(index<len)
            plaintext_block[i]=plaintext[index];
        else
            plaintext_block[i]=0;
    }

    printf("Block Characters:\n");
    for(int i=0;i<8;i++)
    {
        if(plaintext_block[i]==0)
            printf("_ ");
        else
            printf("%c ",plaintext_block[i]);
    }
    printf("\n");

    printf("Block Bytes:\n");
    for(int i=0;i<8;i++)
        printf("%02X ",plaintext_block[i]);

    printf("\n");

    // ===== Convert plaintext to bits

    uint8_t plain_bits[64];

    for(int i=0;i<8;i++)
        for(int bit=0;bit<8;bit++)
            plain_bits[i*8+bit]=(plaintext_block[i]>>(7-bit))&1;

    // ===== Initialize CA state from residual (PURE state(t-1))

uint8_t state[64];

for(int i=0;i<8;i++)
    for(int bit=0;bit<8;bit++)
        state[i*8+bit]=(residual[i]>>(7-bit))&1;

/*
IMPORTANT CHANGE:
We DO NOT XOR plaintext here.

Reason:
state(t-1) must be ONLY the random residual data.
Plaintext will be used separately as input(t) in CA.
*/

    printf("Initial State:\n");

    for(int i=0;i<64;i++)
    {
        printf("%d",state[i]);
        if((i+1)%8==0) printf(" ");
    }
    printf("\n");

    // ===== 16 CA ITERATIONS (TIME-DEPENDENT MODEL)

uint8_t prev_input[64];
uint8_t curr_output[64];

/*
Iteration Logic:
1st iteration:
    state(t-1) = residual (already in state[])
    input(t)   = plaintext

2nd iteration:
    state(t-1) = result1
    input(t)   = plaintext

3rd iteration onwards:
    state(t-1) = result(k-1)
    input(t)   = result(k-2)
*/

// Initial input = plaintext
for(int i=0;i<64;i++)
    prev_input[i] = plain_bits[i];

for(int k=0;k<16;k++)
{
    uint32_t backward = 0xFFFFFFFF - forward_rules[k];

    // Apply CA
    ca_mix(state, prev_input, 64,
           forward_rules[k],
           backward);

    printf("\nCA Iteration %d\n",k+1);

    for(int i=0;i<64;i++)
    {
        printf("%d",state[i]);
        if((i+1)%8==0) printf(" ");
    }
    printf("\n");

    // Store current result
    for(int i=0;i<64;i++)
        curr_output[i] = state[i];

    // SHIFT LOGIC

    // From 2nd iteration onwards, input = previous output

for(int i=0;i<64;i++)
    prev_input[i] = curr_output[i];
}

    // ===== Convert final state → Ciphertext

    uint8_t cipher[8]={0};

    for(int i=0;i<8;i++)
        for(int bit=0;bit<8;bit++)
            cipher[i]=(cipher[i]<<1)|state[i*8+bit];

    printf("\nFinal Ciphertext Block %d:\n",b+1);

    for(int i=0;i<8;i++)
        printf("%02X ",cipher[i]);

    printf("\n");

    // ===== Update residual for next block

    // Extra CA evolution for residual (strong chaining)

for(int i=0;i<4;i++)
    ca_step(state,64,forward_rules[i]);

    for(int i=0;i<8;i++)
    {
        residual[i]=0;

        for(int bit=0;bit<8;bit++)
            residual[i]=(residual[i]<<1)|state[i*8+bit];
    }

    printf("\nUpdated Residual for Next Block:\n");

    for(int i=0;i<8;i++)
        printf("%02X ",residual[i]);

    printf("\n");
}
    
} 