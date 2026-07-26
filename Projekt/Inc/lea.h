#ifndef LEA_H_
#define LEA_H_

#include <stdint.h>

#define LEA_BLOCK_SIZE 16
#define LEA_RK_WORDS   192

typedef struct {
    uint32_t rk[LEA_RK_WORDS];
    uint32_t rounds;
} LEA_KEY;

void lea_set_key(LEA_KEY *key, const unsigned char *mk, unsigned int mk_len);
void lea_encrypt(unsigned char *ct, const unsigned char *pt, const LEA_KEY *key);
void lea_decrypt(unsigned char *pt, const unsigned char *ct, const LEA_KEY *key);
void lea_ecb_encrypt(unsigned char *ct, const unsigned char *pt, unsigned int len, const LEA_KEY *key);
void lea_ecb_decrypt(unsigned char *pt, const unsigned char *ct, unsigned int len, const LEA_KEY *key);

#endif
