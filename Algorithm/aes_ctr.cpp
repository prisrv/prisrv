#include "aes_ctr.h"
#define AES_NK 16
#define AES_DATA_LEN 2048

AES_CTR::AES_CTR()
{
    Data=(uint8_t*)malloc(AES_DATA_LEN);

}
AES_CTR::~AES_CTR()
{
    free(Data);

}
int AES_CTR::init(char *key,char *ctr)
{
    memset(Data,0,AES_DATA_LEN);
    DataLen=0;    
    return AesCtrInitialiseWithKey( &State, (uint8_t const*)key, 16, (uint8_t const*)ctr );
    //return aes_init(&State,MR_ECB,AES_NK,key,NULL);
}

int AES_CTR::encrypt_add(Big &data)
{
    Big_C data_c;
    BN_T.Trf_Big_to_Char(data,data_c);

    int add_len = sizeof(Big_C);    
    if(DataLen+add_len > AES_DATA_LEN)
        return -1;
    memcpy(Data+DataLen,&data_c,add_len);
    DataLen=DataLen+add_len;
   // printf("encrypt_add DataLen=%d\n",DataLen);
    return 0;
}
int AES_CTR::encrypt_add(G1 &data)
{
    G1_C data_c;
    BN_T.Trf_G1_to_Char(data,data_c);

    int add_len = sizeof(G1_C);  
    if(DataLen+add_len > AES_DATA_LEN)
        return -1;  
    memcpy(Data+DataLen,&data_c,add_len);
    DataLen=DataLen+add_len;
  //  printf("encrypt_add DataLen=%d\n",DataLen);
    return 0;

}
int AES_CTR::encrypt_add(G2 &data)
{
    G2_C data_c;
    BN_T.Trf_G2_to_Char(data,data_c);

    int add_len = sizeof(G2_C);  
    if(DataLen+add_len > AES_DATA_LEN)
        return -1;  
    memcpy(Data+DataLen,&data_c,add_len);
    DataLen=DataLen+add_len;
  //  printf("encrypt_add DataLen=%d\n",DataLen);
    return 0;

}
int AES_CTR::encrypt_add(GT &data)
{
    GT_C data_c;
    BN_T.Trf_GT_to_Char(data,data_c);

    int add_len = sizeof(GT_C);    
    if(DataLen+add_len > AES_DATA_LEN)
        return -1;
    memcpy(Data+DataLen,&data_c,add_len);
    DataLen=DataLen+add_len;
  //  printf("encrypt_add DataLen=%d\n",DataLen);
    return 0;

}
int AES_CTR::encrypt_data(char *cipher, unsigned int *cipher_len)
{
    *cipher_len=DataLen;
   // memcpy(cipher,Data,DataLen);
    AesCtrXor( &State, Data,(void*)cipher, DataLen );
    return 0;
}
int AES_CTR::decrypt_data(char *cipher, unsigned int cipher_len)
{
    DataLen=cipher_len;
    if(DataLen> AES_DATA_LEN)
        return -1;
    //memcpy(Data,cipher,DataLen);
    AesCtrXor( &State, cipher,(void*)Data, DataLen );
 //   printf("decrypt_data DataLen=%d\n",DataLen);
    return 0;
    
}
int AES_CTR::decrypt_red(Big &data)
{
    int add_len = sizeof(Big_C);    
    if(DataLen-add_len < 0)
        return -1;

    Big_C data_c;
    memcpy(&data_c,Data+DataLen-add_len,add_len);
    BN_T.Trf_Char_to_Big(data_c,data);
    DataLen=DataLen-add_len;
 //   printf("decrypt_red DataLen=%d\n",DataLen);
    return 0;    
}
int AES_CTR::decrypt_red(G1 &data)
{
    int add_len = sizeof(G1_C);    
    if(DataLen-add_len < 0)
        return -1;

    G1_C data_c;
    memcpy(&data_c,Data+DataLen-add_len,add_len);
    BN_T.Trf_Char_to_G1(data_c,data);
    DataLen=DataLen-add_len;
 //   printf("decrypt_red DataLen=%d\n",DataLen);
    return 0;    

}
int AES_CTR::decrypt_red(G2 &data)
{
    int add_len = sizeof(G2_C);    
    if(DataLen-add_len < 0)
        return -1;

    G2_C data_c;
    memcpy(&data_c,Data+DataLen-add_len,add_len);
    BN_T.Trf_Char_to_G2(data_c,data);
    DataLen=DataLen-add_len;
 //   printf("decrypt_red DataLen=%d\n",DataLen);
    return 0;    

}
int AES_CTR::decrypt_red(GT &data)
{
    int add_len = sizeof(GT_C);    
    if(DataLen-add_len < 0)
        return -1;

    GT_C data_c;
    memcpy(&data_c,Data+DataLen-add_len,add_len);
    BN_T.Trf_Char_to_GT(data_c,data);
    DataLen=DataLen-add_len;
 //   printf("decrypt_red DataLen=%d\n",DataLen);
    return 0;    

}



