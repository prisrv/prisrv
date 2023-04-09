#include"fac.h"

#define AES_SECURITY 128
int correct()
{
    PFC pfc(AES_SECURITY);
    FAC fac(&pfc);
    int ret =0;
    FAC_CRED_KEY cred_key;
    ret = fac.CredKeyGen(cred_key);
    if(ret != 0)
    {
        printf("fac.CredKeyGen Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("fac.CredKeyGen pass\n");
    //cout<< cred_key.pk.W.g<<endl;

    FAC_USER_KEY user_key;
    ret= fac.UserKeyGen(user_key);
    if(ret != 0)
    {
        printf("fac.UserKeyGen Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("fac.UserKeyGen pass\n");
    USER_ATTR attr;
    Big uid;
    FAC_SPK1 spk1;
    ret = fac.IssueUser_Send(user_key, attr, uid,spk1);
    if(ret != 0)
    {
        printf("fac.IssueUser_Send Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("fac.IssueUser_Send pass\n");
    FAC_CRED_U cred_u;
    ret = fac.IssueIssuer(cred_key,attr,uid,spk1, user_key.upk,cred_u);
    if(ret != 0)
    {
        printf("fac.IssueIssuer Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("fac.IssueIssuer pass\n");

    ret= fac.IssueUser_Verify(cred_key.pk,cred_u,attr,uid,user_key);
    if(ret != 0)
    {
        printf("fac.IssueUser_Verify Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("fac.IssueUser_Verify pass\n");

    FAC_TOK tok;
    Big m;
    pfc.random(m);//ramdom m test
    FAC_USER_DISCLOSE_ATTR disclose;
    ret= fac.Show(cred_key.pk,cred_u,attr,disclose,uid,user_key,tok,m);
    if(ret != 0)
    {
        printf("fac.Show Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("fac.Show pass\n");
    ret= fac.Verify(cred_key.pk,tok,m,disclose);
    if(ret != 0)
    {
        printf("fac.Verify Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("fac.Verify pass\n");
    //Trace
    ret= fac.Trace(cred_key,tok,uid);
    if(ret != 0)
    {
        printf("fac.Trace Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("fac.Trace  pass\n");

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
    FAC fac(&pfc);
    int ret =0;
    FAC_CRED_KEY cred_key;
    printf("#################test fac speed start#######################\n");
    printf("The number of user attributes `n` is %d \n",FAC_PARA_N);
    printf("The number of disclose attributes is %d \n",FAC_PARA_D);

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
        ret = fac.CredKeyGen(cred_key);
        if(ret != 0)
        {
            printf("fac.CredKeyGen Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("fac.CredKeyGen ret : %d time =%f sec\n",ret,sum);
    FAC_USER_KEY user_key;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret= fac.UserKeyGen(user_key);
        if(ret != 0)
        {
            printf("fac.UserKeyGen Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("fac.UserKeyGen ret : %d time =%f sec\n",ret,sum);
    USER_ATTR attr;
    Big uid;
    FAC_SPK1 spk1;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = fac.IssueUser_Send(user_key, attr, uid,spk1);
        if(ret != 0)
        {
            printf("fac.IssueUser_Send Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("fac.IssueUser_Send ret : %d time =%f sec\n",ret,sum);
    FAC_CRED_U cred_u;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = fac.IssueIssuer(cred_key,attr,uid,spk1, user_key.upk,cred_u);
        if(ret != 0)
        {
            printf("fac.IssueIssuer Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("fac.IssueIssuer ret : %d time =%f sec\n",ret,sum);
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret= fac.IssueUser_Verify(cred_key.pk,cred_u,attr,uid,user_key);
        if(ret != 0)
        {
            printf("fac.IssueUser_Verify Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("fac.IssueUser_Verify ret : %d time =%f sec\n",ret,sum);

    FAC_TOK tok;
    Big m;
    pfc.random(m);//ramdom m test
    FAC_USER_DISCLOSE_ATTR disclose;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret= fac.Show(cred_key.pk,cred_u,attr,disclose,uid,user_key,tok,m);
        if(ret != 0)
        {
            printf("fac.Show Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("fac.Show ret : %d time =%f sec\n",ret,sum);
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret= fac.Verify(cred_key.pk,tok,m,disclose);
        if(ret != 0)
        {
            printf("fac.Verify Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("fac.Verify ret : %d time =%f sec\n",ret,sum);
    //Trace
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret= fac.Trace(cred_key,tok,uid);
        if(ret != 0)
        {
            printf("fac.Trace Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("fac.Trace ret : %d time =%f sec\n",ret,sum);
     printf("#################test fac speed end#######################\n");

    return 0;
}
int main()
{
    //return correct();
    return speed_test();

}
