#ifndef AES_CTR_H
#define AES_CTR_H
#include "miracl.h"
#include "pairing_3.h"
#include "bn_transfer.h"
#include "WjCryptLib_AesCtr.h"
class AES_CTR
{
    AesCtrContext State;
    unsigned char *Data;
    unsigned int DataLen;
    BN_transfer BN_T;
public:
    AES_CTR();
    ~AES_CTR();
    int init(char *key,char *ctr);
    int encrypt_add(Big &data);
    int encrypt_add(G1 &data);
    int encrypt_add(G2 &data);
    int encrypt_add(GT &data);
    int encrypt_data(char *cipher, unsigned int *cipher_len);
    int decrypt_data(char *cipher, unsigned int cipher_len);
    int decrypt_red(Big &data);
    int decrypt_red(G1 &data);
    int decrypt_red(G2 &data);
    int decrypt_red(GT &data);
    
};

#endif // AES_CTR_H
