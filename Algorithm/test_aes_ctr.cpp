#include "aes_ctr.h"
#define AES_SECURITY 128
int main()
{
    int ret=0;
    PFC pfc(AES_SECURITY);
    Big g,g_;
    G1 g1,g1_;
    G2 g2,g2_;
    GT gt,gt_;
    pfc.random(g);
    pfc.random(g1);
    pfc.random(g2);
    gt=pfc.pairing(g2,g1);
    AES_CTR aec_ctr;
    char key[16],iv[16],cipher[1024];
    unsigned int cipher_len=0;
    for(int i=0;i<16;i++)
    {
        key[i]=100+i;
        iv[i]=i;
    }
    aec_ctr.init(key,iv);
    ret =aec_ctr.encrypt_add(g);
    if(ret !=0)
    {
        printf("encrypt_add Big erro ret=%d\n",ret);
        return -1;
    }
    ret =aec_ctr.encrypt_add(g1);
    if(ret !=0)
    {
        printf("encrypt_add G1 erro ret=%d\n",ret);
        return -1;
    }
    ret =aec_ctr.encrypt_add(g2);
    if(ret !=0)
    {
        printf("encrypt_add G2 erro ret=%d\n",ret);
        return -1;
    }
    ret =aec_ctr.encrypt_add(gt);
    if(ret !=0)
    {
        printf("encrypt_add GT erro ret=%d\n",ret);
        return -1;
    }
    ret =aec_ctr.encrypt_data(cipher,&cipher_len);
    if(ret !=0)
    {
        printf("encrypt_data erro ret=%d\n",ret);
        return -1;
    }
    else
    {
        printf("encrypt_data sunccess , cipher_len =%d\n",cipher_len);
    }
    
    aec_ctr.init(key,iv);
    ret =aec_ctr.decrypt_data(cipher,cipher_len);
    if(ret !=0)
    {
        printf("decrypt_data erro ret=%d\n",ret);
        return -1;
    }
    ret =aec_ctr.decrypt_red(gt_);
    if(ret !=0)
    {
        printf("decrypt_red GT erro ret=%d\n",ret);
        return -1;
    }
    else if(gt != gt_)
    {
        printf("decrypt gt erro\n");
        return -2;
    }
    ret =aec_ctr.decrypt_red(g2_);
    if(ret !=0)
    {
        printf("decrypt_red G2 erro ret=%d\n",ret);
        return -1;
    }
    else if(g2 != g2_)
    {
        printf("decrypt g2 erro\n");
        return -2;
    }
    ret =aec_ctr.decrypt_red(g1_);
    if(ret !=0)
    {
        printf("decrypt_red G1 erro ret=%d\n",ret);
        return -1;
    }
    else if(g1 != g1_)
    {
        printf("decrypt gt=1 erro\n");
        return -2;
    }
    ret =aec_ctr.decrypt_red(g_);
    if(ret !=0)
    {
        printf("decrypt_red big erro ret=%d\n",ret);
        return -1;
    }
    else if(g != g_)
    {
        printf("decrypt big erro\n");
        return -2;
    }
    else
    {
        printf("aes_ctr ok\n");
    }
    return 0;




}