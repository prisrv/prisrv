#include"acme.h"

#define AES_SECURITY 128
int correct()
{
    PFC pfc(AES_SECURITY);
    ACME acme(&pfc);

    int ret =0;
    ACME_MSK msk;
    ACME_MPK mpk;
    ret =acme.SetUp(msk,mpk);
    if(ret != 0)
    {
        printf("acme.SetUp Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("acme.SetUp pass\n");
    ACME_CRED_KEY cred_key;
    ret =acme.CredKeyGen(cred_key);
    if(ret != 0)
    {
        printf("acme.CredKeyGen Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("acme.CredKeyGen pass\n");
    ACME_USER_KEY user_key;
    ret =acme.UserKeyGen(user_key);
    if(ret != 0)
    {
        printf("acme.UserKeyGen Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("acme.UserKeyGen pass\n");
    USER_ATTR attr;
    Big uid;
    ACME_SPK1 spk1;
    ret =acme.IssueUser_Send(user_key,attr,uid,spk1);
    if(ret != 0)
    {
        printf("acme.IssueUser_Send Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("acme.IssueUser_Send pass\n");


    ACME_CRED_U cred_u;
    ACME_USER_PK upk;
    upk.upk=user_key.user_key.upk;
    ret =acme.IssueIssuer(cred_key,attr,uid,spk1,upk,cred_u);
    if(ret != 0)
    {
        printf("acme.IssueIssuer Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("acme.IssueIssuer pass\n");
    ACME_CRED_KEY_PK pk;
    pk.pk=cred_key.cred_key.pk;
    ret =acme.IssueUser_Verify(pk,cred_u,attr,uid,user_key);
    if(ret != 0)
    {
        printf("acme.IssueUser_Verify Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("acme.IssueUser_Verify pass\n");
    ACME_X X_rcv,X_snd;
    for(int i=0;i<CP_ABE_PARA_N;i++)
    {
        X_rcv.X.x[i]=0;
        X_snd.X.x[i]=0;
    }
    X_rcv.X.x[0]=X_rcv.X.x[2]=1;
    X_snd.X.x[0]=X_snd.X.x[2]=1;
    ACME_ABE_DK_X_REC Dk_xrec;
    ret =acme.DKeyGen(msk,X_rcv,Dk_xrec);
    if(ret != 0)
    {
        printf("acme.DKeyGen Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("acme.DKeyGen pass\n");
    ACME_ABE_DK_f_REC DK_f_rec;
    ret =acme.PolGen(msk,DK_f_rec);
    if(ret != 0)
    {
        printf("acme.PolGen Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("acme.PolGen pass\n");

    Big M;
    ACME_CIPHER cipher;
    ACME_PLAIN plain;
    pfc.random(M);
    ret =acme.Enc(mpk,  cred_key, cred_u, user_key, attr, uid, X_snd, M, cipher);
    if(ret != 0)
    {
        printf("acme.Enc Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("acme.Enc pass\n");
    ACME_TOK tok;
    ret =acme.Den( cred_key,Dk_xrec,DK_f_rec,X_rcv,X_rcv,cipher,plain);
    if(ret != 0)
    {
        printf("acme.Den Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("acme.Den pass\n");
    //ACME_TOK tok;
    ret =acme.Trace(cred_key, tok, uid);
    if(ret != 0)
    {
        printf("acme.Trace Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("acme.Trace pass\n");



    return 0;
}
#include <ctime>
#include <time.h>
#define TEST_TIME 1
int speed_test()
{
    int i;
    clock_t start,finish;
    double sum;


    PFC pfc(AES_SECURITY);
    ACME acme(&pfc);
    printf("#################test acme speed start#######################\n");
    printf("The number of user attributes `n` is %d \n",FAC_PARA_N);
    printf("The number of disclose attributes is %d \n",FAC_PARA_D);
    printf("The para of key `k` is %d \n",CP_ABE_PARA_K);
    printf("The para of shar `m` is %d \n",LSS_NC_SHARE_NUM);
    int ret =0;
    ACME_MSK msk;
    ACME_MPK mpk;
        //1. basic
    //G1
    start=clock();
    for(int k=0;k<TEST_TIME;k++)
    {
        G1 G;
        pfc.random(G);
        Big r;
        pfc.random(r);
        G1 T=pfc.mult(G,r);
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("BN256.e_1 ret : %d time =%f sec\n",ret,sum);

    //G2
    start=clock();
    for(int k=0;k<TEST_TIME;k++)
    {
        G2 G;
        pfc.random(G);
        Big r;
        pfc.random(r);
        G2 T=pfc.mult(G,r);
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("BN256.e_2 ret : %d time =%f sec\n",ret,sum);

    //e
    start=clock();
    for(int k=0;k<TEST_TIME;k++)
    {
        G1 G;
        G2 H;
        pfc.random(G);
        pfc.random(H);
        GT T=pfc.pairing(H,G);
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("BN256.e_p ret : %d time =%f sec\n",ret,sum);
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret =acme.SetUp(msk,mpk);
        if(ret != 0)
        {
            printf("acme.SetUp Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("acme.SetUp ret : %d time =%f sec\n",ret,sum);
    ACME_CRED_KEY cred_key;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret =acme.CredKeyGen(cred_key);
        if(ret != 0)
        {
            printf("acme.CredKeyGen Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("acme.CredKeyGen ret : %d time =%f sec\n",ret,sum);
    ACME_USER_KEY user_key;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret =acme.UserKeyGen(user_key);
        if(ret != 0)
        {
            printf("acme.UserKeyGen Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("acme.UserKeyGen ret : %d time =%f sec\n",ret,sum);
    USER_ATTR attr;
    Big uid;
    ACME_SPK1 spk1;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret =acme.IssueUser_Send(user_key,attr,uid,spk1);
        if(ret != 0)
        {
            printf("acme.IssueUser_Send Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("acme.IssueUser_Send ret : %d time =%f sec\n",ret,sum);


    ACME_CRED_U cred_u;
    ACME_USER_PK upk;
    upk.upk=user_key.user_key.upk;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret =acme.IssueIssuer(cred_key,attr,uid,spk1,upk,cred_u);
        if(ret != 0)
        {
            printf("acme.IssueIssuer Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("acme.IssueIssuer ret : %d time =%f sec\n",ret,sum);
    ACME_CRED_KEY_PK pk;
    pk.pk=cred_key.cred_key.pk;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret =acme.IssueUser_Verify(pk,cred_u,attr,uid,user_key);
        if(ret != 0)
        {
            printf("acme.IssueUser_Verify Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("acme.IssueUser_Verify ret : %d time =%f sec\n",ret,sum);
    ACME_X X_rcv,X_snd;
    for(int i=0;i<CP_ABE_PARA_N;i++)
    {
        X_rcv.X.x[i]=0;
        X_snd.X.x[i]=0;
    }
    X_rcv.X.x[0]=X_rcv.X.x[2]=1;
    X_snd.X.x[0]=X_snd.X.x[2]=1;
    ACME_ABE_DK_X_REC Dk_xrec;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret =acme.DKeyGen(msk,X_rcv,Dk_xrec);
        if(ret != 0)
        {
            printf("acme.DKeyGen Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("acme.DKeyGen ret : %d time =%f sec\n",ret,sum);
    ACME_ABE_DK_f_REC DK_f_rec;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret =acme.PolGen(msk,DK_f_rec);
        if(ret != 0)
        {
            printf("acme.PolGen Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("acme.PolGen ret : %d time =%f sec\n",ret,sum);

    Big M;
    ACME_CIPHER cipher;
    ACME_PLAIN plain;
    pfc.random(M);
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret =acme.Enc(mpk,  cred_key, cred_u, user_key, attr, uid, X_snd, M, cipher);
        if(ret != 0)
        {
            printf("acme.Enc Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("acme.Enc ret : %d time =%f sec\n",ret,sum);
    ACME_TOK tok;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret =acme.Den( cred_key,Dk_xrec,DK_f_rec,X_rcv,X_rcv,cipher,plain);
        if(ret != 0)
        {
            printf("acme.Den Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("acme.Den ret : %d time =%f sec\n",ret,sum);
    //ACME_TOK tok;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret =acme.Trace(cred_key, tok, uid);
        if(ret != 0)
        {
            printf("acme.Trace Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("acme.Trace ret : %d time =%f sec\n",ret,sum);
    printf("#################test acme speed end#######################\n");

    return 0;
}
int main()
{
    //return correct();
    return speed_test();

}
