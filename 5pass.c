/*
FINAL IMPLEMENTATION WITH XOR FOLDING

Password → SHA512
→ Logistic Map → 16 Keys (64 bytes each)
→ XOR Folding → 8 bytes (64 bits)
→ Correlation Matrix using those 64 bits
→ 4-Byte XOR Fold → Forward & Backward Rules (32-bit)

NO rehash used
Uses handwritten logistic algorithm logic
*/

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

#define NUM_KEYS 16
#define KEY_SIZE 64
#define FOLD_SIZE 8
#define BIT_SIZE 64


// ================= SHA512 =================

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

uint64_t ROTR(uint64_t x,int n)
{
    return (x>>n)|(x<<(64-n));
}

void sha512(const uint8_t *msg,size_t len,uint8_t hash[64])
{
    uint64_t H[8]={
    0x6a09e667f3bcc908ULL,
    0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL,
    0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL,
    0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL,
    0x5be0cd19137e2179ULL};

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


// ================= XOR FOLDING 8 BYTES =================

void xor_fold(uint8_t key[64], uint8_t folded[8])
{
    memset(folded,0,8);

    for(int block=0; block<8; block++)
        for(int i=0;i<8;i++)
            folded[i] ^= key[block*8 + i];
}


// ================= 4-BYTE XOR FOLD (FORWARD RULE) =================

uint32_t xor_fold_4bytes(uint8_t folded8[8])
{
    uint32_t forward = 0;

    for(int i = 0; i < 4; i++)
    {
        uint8_t value = folded8[i] ^ folded8[i+4];
        forward = (forward << 8) | value;
    }

    return forward;
}


// ================= BYTES TO BITS =================

void bytes_to_bits(uint8_t bytes[8], uint8_t bits[64])
{
    for(int i=0;i<64;i++)
        bits[i] = (bytes[i/8] >> (7-(i%8))) & 1;
}


// ================= CORRELATION =================

double correlation(uint8_t a[64], uint8_t b[64])
{
    int matching = 0;

    for(int i=0;i<64;i++)
        if(a[i]==b[i]) matching++;

    return (double)matching/64.0;
}


// ================= MAIN =================

int main()
{
    int total_passwords = 5;
    char password[256];

    for(int p=0;p<total_passwords;p++)
    {
        printf("\n================ PASSWORD %d ================\n",p+1);
        printf("Enter password: ");
        scanf("%s",password);

        uint8_t digest[64];
        sha512((uint8_t*)password,strlen(password),digest);

        printf("\nSHA512:\n");
        for(int i=0;i<64;i++)
            printf("%02X",digest[i]);

        double x=0;
        for(int i=0;i<8;i++)
            x+=digest[i]/pow(256,i+1);

        uint8_t keys[NUM_KEYS][KEY_SIZE];

        printf("\n\nGENERATED KEYS:\n");

        for(int k=0;k<NUM_KEYS;k++)
        {
            printf("\nKey %d:\n",k+1);

            for(int j=0;j<KEY_SIZE;j++)
            {
                x=logistic(x);
                keys[k][j]=(uint8_t)(x*256);
                printf("%02X",keys[k][j]);
            }
        }

        uint8_t folded[NUM_KEYS][FOLD_SIZE];
        uint8_t bits[NUM_KEYS][BIT_SIZE];

        printf("\n\nXOR FOLDED KEYS:\n");

        for(int i=0;i<NUM_KEYS;i++)
        {
            xor_fold(keys[i],folded[i]);

            printf("\nKey %d Folded: ",i+1);
            for(int j=0;j<8;j++)
                printf("%02X",folded[i][j]);

            bytes_to_bits(folded[i],bits[i]);
        }

        printf("\n\n================ CORRELATION MATRIX ================\n\n");

        printf("%6s","");
        for(int j=0;j<NUM_KEYS;j++)
            printf("K%-7d",j+1);

        printf("\n");

        for(int i=0;i<NUM_KEYS;i++)
        {
            printf("K%-4d ",i+1);

            for(int j=0;j<NUM_KEYS;j++)
                printf("%8.4f ",correlation(bits[i],bits[j]));

            printf("\n");
        }

        printf("\n================ FORWARD & BACKWARD RULES ================\n");

        for(int i=0;i<NUM_KEYS;i++)
        {
            uint32_t forward=xor_fold_4bytes(folded[i]);
            uint32_t backward=0xFFFFFFFF-forward;

            printf("\nKey %2d:",i+1);
            printf("\n  Forward  Rule: %08X",forward);
            printf("\n  Backward Rule: %08X\n",backward);
        }

        printf("\n===========================================================\n");
    }

    return 0;
}