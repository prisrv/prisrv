#include "prisrv_export.h"
#include "test_so.h"
//#include <ctime>
#include <time.h>
#define TEST_TIME 1

int test_so()
{
    int ret=0;
    int i;
    clock_t start,finish;
    double sum;
    //system init
    printf("/////////////// system setup  ////////////////////\n");
    struct ACME_MPK_C *mpk=(struct ACME_MPK_C*)malloc(sizeof(struct ACME_MPK_C));
    struct ACME_MSK_C *msk=(struct ACME_MSK_C*)malloc(sizeof(struct ACME_MSK_C));
#if 1

    ret =SetUp(mpk,msk);
    if(ret != 0)
    {
        printf("prisrv.SetUp Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisrv.SetUp pass\n");
#endif
#if 1
    struct ACME_CRED_KEY_C *cred_key=(struct ACME_CRED_KEY_C*)malloc(sizeof(struct ACME_CRED_KEY_C));
    ret =CredKeyGen(cred_key);
    if(ret != 0)
    {
        printf("prisrv.CredKeyGen Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisrv.CredKeyGen pass\n");
    //return 0;

    struct ACME_CRED_KEY_PK_C *cred_key_pk=(struct ACME_CRED_KEY_PK_C*)malloc(sizeof(struct ACME_CRED_KEY_PK_C));
    memcpy(&(cred_key_pk->pk),&(cred_key->pk),sizeof(struct FAC_CRED_KEY_PK_C));
#endif
    printf("/////////////// server setup  ////////////////////\n");
#if 1

    //server init
    struct ACME_USER_KEY_C *service_key=(struct ACME_USER_KEY_C*)malloc(sizeof(struct ACME_USER_KEY_C));
    ret =UserKeyGen(service_key);
    if(ret != 0)
    {
        printf("prisrv.service_key KeyGen Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisrv.service_key KeyGen pass\n");
#endif
#if 1
    struct USER_ATTR_C *service_attr=(struct USER_ATTR_C*)malloc(sizeof(struct USER_ATTR_C));
    struct Big_C *bid=(struct Big_C*)malloc(sizeof(struct Big_C));
    struct ACME_SPK1_C *spk1=(struct ACME_SPK1_C*)malloc(sizeof(struct ACME_SPK1_C));
    ret =Issue_Send(service_key,service_attr,bid,spk1);
    if(ret != 0)
    {
        printf("prisrv.Issue_Send service Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisrv.Issue_Send service pass\n");
#endif
#if 1
    struct ACME_CRED_U_C *cred_s=(struct ACME_CRED_U_C*)malloc(sizeof(struct ACME_CRED_U_C));
    struct ACME_USER_PK_C *service_key_upk=(struct ACME_USER_PK_C*)malloc(sizeof(struct ACME_USER_PK_C));
    memcpy(&(service_key_upk->upk),&(service_key->upk),sizeof(struct FAC_USER_PK_C));
    ret =Issue_Issuer(cred_key,service_attr,bid,spk1,service_key_upk,cred_s);
    if(ret != 0)
    {
        printf("prisrv.Issue_Issuer service Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisrv.Issue_Issuer service pass\n");
#endif
    ret =Issue_Verify(cred_key_pk,cred_s,service_attr,bid,service_key);
    if(ret != 0)
    {
        printf("prisrv.Issue_Verify service Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisrv.Issue_Verify service pass\n");

    struct ACME_X_C *X_s=(struct ACME_X_C*)malloc(sizeof(struct ACME_X_C));

    struct ACME_ABE_DK_X_REC_C *Dk_S_xrec=(struct ACME_ABE_DK_X_REC_C*)malloc(sizeof(struct ACME_ABE_DK_X_REC_C));

    ret =DKeyGen(msk, X_s, Dk_S_xrec);
    if(ret != 0)
    {
        printf("prisrv.DKeyGen service Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisrv.DKeyGen service pass\n");

    struct ACME_ABE_DK_f_REC_C *DK_S_frec=(struct ACME_ABE_DK_f_REC_C*)malloc(sizeof(struct ACME_ABE_DK_f_REC_C));
    ret =PolGen(msk,DK_S_frec);
    if(ret != 0)
    {
        printf("prisrv.PolGen service Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisrv.PolGen service pass\n");

    printf("/////////////// client setup  ////////////////////\n");

    struct ACME_USER_KEY_C *client_key=(struct ACME_USER_KEY_C*)malloc(sizeof(struct ACME_USER_KEY_C));
    ret =UserKeyGen(client_key);
    if(ret != 0)
    {
        printf("prisrv.client_key KeyGen Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisrv.client_key KeyGen pass\n");

    struct USER_ATTR_C *client_attr=(struct USER_ATTR_C*)malloc(sizeof(struct USER_ATTR_C));
    struct Big_C *sid=(struct Big_C*)malloc(sizeof(struct Big_C));
    //ACME_SPK1 spk1;
    ret =Issue_Send(client_key,client_attr,sid,spk1);
    if(ret != 0)
    {
        printf("prisrv.Issue_Send client Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisrv.Issue_Send client pass\n");

    struct ACME_CRED_U_C *cred_c=(struct ACME_CRED_U_C*)malloc(sizeof(struct ACME_CRED_U_C));
    struct ACME_USER_PK_C *client_key_upk=(struct ACME_USER_PK_C*)malloc(sizeof(struct ACME_USER_PK_C));
    memcpy(&(client_key_upk->upk),&(client_key->upk),sizeof(struct FAC_USER_PK_C));
    ret =Issue_Issuer(cred_key,client_attr,sid,spk1,client_key_upk,cred_c);
    if(ret != 0)
    {
        printf("prisrv.Issue_Issuer client Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisrv.Issue_Issuer client pass\n");


    ret =Issue_Verify(cred_key_pk,cred_c,client_attr,sid,client_key);
    if(ret != 0)
    {
        printf("prisrv.Issue_Verify client Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisrv.Issue_Verify client pass\n");
    struct ACME_X_C *X_c=(struct ACME_X_C*)malloc(sizeof(struct ACME_X_C));
    struct ACME_ABE_DK_X_REC_C *Dk_C_xrec=(struct ACME_ABE_DK_X_REC_C*)malloc(sizeof(struct ACME_ABE_DK_X_REC_C));
    ret =DKeyGen(msk, X_c, Dk_C_xrec);
    if(ret != 0)
    {
        printf("prisrv.DKeyGen client Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisrv.DKeyGen client pass\n");
    struct ACME_ABE_DK_f_REC_C *DK_C_frec=(struct ACME_ABE_DK_f_REC_C*)malloc(sizeof(struct ACME_ABE_DK_f_REC_C));
    ret =PolGen(msk,DK_C_frec);
    if(ret != 0)
    {
        printf("prisrv.PolGen client Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisrv.PolGen client pass\n");
    //test
    for(int k=0;k<5;k++)
    {
        printf("/////////////// test %d round ////////////////////\n",k);
        printf("/////////////// server broadcast  ////////////////////\n");
        struct ACME_CIPHER_C *cipher=(struct ACME_CIPHER_C*)malloc(sizeof(struct ACME_CIPHER_C));
        struct PriSrv_MSG_B_C *msg_b=(struct PriSrv_MSG_B_C*)malloc(sizeof(struct PriSrv_MSG_B_C));
        struct Big_C *z=(struct Big_C*)malloc(sizeof(struct Big_C));
        start=clock();
        for(i=0;i<TEST_TIME;i++)
        {
            ret =Broadcast(mpk, cred_key, cred_s, service_key, service_attr,bid, X_s, cipher, msg_b,z);
            if(ret != 0)
            {
                printf("prisrv.Broadcast  Erro ret =%d\n",ret);
                return 1;
            }
          //  else
           // {
                // printf("ACME_CIPHER_C = %d bytes\n",sizeof(struct ACME_CIPHER_C));
                // printf("ACME_CIPHER_CT = %d bytes\n",sizeof(struct ACME_CIPHER_CC));
            //    printf("prisrv.Broadcast  pass\n");
           // }
        }
        finish=clock();
        sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
        printf("prisrv.Broadcast ret : %d time =%f sec\n",ret,sum);

        printf("/////////////// client receive and init  ////////////////////\n");

        struct PriSrv_C1_C *C1_msg=(struct PriSrv_C1_C*)malloc(sizeof(struct PriSrv_C1_C));
        start=clock();
        for(i=0;i<TEST_TIME;i++)
        {
            ret =AMA_Cinit(mpk, cred_key, cred_c, client_key, Dk_C_xrec, DK_C_frec, X_s, X_c, client_attr, sid, cipher, msg_b, C1_msg);
            if(ret != 0)
            {
                printf("prisrv.AMA_Cinit  Erro ret =%d\n",ret);
                return 1;
            }
            //else
              //  printf("prisrv.AMA_Cinit  pass\n");
        }
        finish=clock();
        sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
        printf("prisrv.AMA_Cinit ret : %d time =%f sec\n",ret,sum);
#if 1
        printf("/////////////// service receive and kaa  ////////////////////\n");
        struct PriSrv_S_C *S_msg=(struct PriSrv_S_C*)malloc(sizeof(struct PriSrv_S_C));
        struct PriSrv_SSK_C *ssk_s=(struct PriSrv_SSK_C*)malloc(sizeof(struct PriSrv_SSK_C));
        start=clock();
        for(i=0;i<TEST_TIME;i++)
        {
            ret =AMA_S(mpk, cred_key, cred_s, service_key,z, service_attr, bid, Dk_S_xrec, DK_S_frec, X_s, X_c, C1_msg, S_msg, ssk_s);
            if(ret != 0)
            {
                printf("prisrv.AMA_S  Erro ret =%d\n",ret);
                return 1;
            }
            //else
             //   printf("prisrv.AMA_S  pass\n");
        }
        finish=clock();
        sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
        printf("prisrv.AMA_S ret : %d time =%f sec\n",ret,sum);

        printf("/////////////// client receive and kaa  ////////////////////\n");

        struct PriSrv_SSK_C *ssk_c=(struct PriSrv_SSK_C*)malloc(sizeof(struct PriSrv_SSK_C));
        start=clock();
        for(i=0;i<TEST_TIME;i++)
        {
            ret =AMA_Cverify(mpk, cred_key, cred_c, client_key, Dk_C_xrec, DK_C_frec, X_s, X_c, client_attr, sid, C1_msg, S_msg,ssk_c);
            if(ret != 0)
            {
                printf("prisrv.AMA_Cverify  Erro ret =%d\n",ret);
                return 1;
            }
           // else
             //   printf("prisrv.AMA_Cverify  pass\n");
        }
        finish=clock();
        sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
        printf("prisrv.AMA_Cverify ret : %d time =%f sec\n",ret,sum);


        printf("/////////////// key  ////////////////////\n");
        for(int i=0;i<4;i++)
        {
            if(ssk_c->ssk.w[i]!=ssk_s->ssk.w[i])
                printf("kaa erro!\n");
        }
        printf("prisrv.Kaa success!\n");
#endif
    }


    return ret;
}
int main()
{
    return test_so();
}
