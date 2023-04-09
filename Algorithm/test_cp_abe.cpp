#include"cp_abe.h"

#define AES_SECURITY 128
int correct()
{
    PFC pfc(AES_SECURITY);
    CP_ABE cp_abe(&pfc);

    int ret =0;
    CP_ABE_MSK msk;
    CP_ABE_MPK mpk;
    ret =cp_abe.SetUp(msk,mpk);
    if(ret != 0)
    {
        printf("\ncp_abe.SetUp Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("\ncp_abe.SetUp pass\n");
    CP_APE_X X;
    CP_ABE_SK sk;
    X.x[0]=1;X.x[2]=1;
    X.x[1]=0;
    ret =cp_abe.KeyGen(msk,X,sk);
    if(ret != 0)
    {
        printf("\ncp_abe.KeyGen Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("\ncp_abe.KeyGen pass\n");
    GT M;
    CP_ABE_CIPHER cipher;
    CP_ABE_SHARE_INFO share_info;
    G1 R1;G2 R2;
    pfc.random(R1);
    pfc.random(R2);
    M=pfc.pairing(R2,R1);
    ret =cp_abe.Enc(mpk, M, cipher,  share_info);
    if(ret != 0)
    {
        printf("\ncp_abe.Enc Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("\ncp_abe.Enc pass\n");
    GT M_;
    ret =cp_abe.Dec(mpk,X,sk,cipher, share_info,M_);
    if(ret != 0)
    {
        printf("\ncp_abe.Dec Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("\ncp_abe.Dec pass\n");
    if(M!=M_)
    {
        printf("\ncp_abe Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("\ncp_abe pass\n");
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
    CP_ABE cp_abe(&pfc);
    printf("#################test cp-abe speed start#######################\n");
    printf("The number of user attributes `n` is %d \n",CP_ABE_PARA_N);
    printf("The para of key `k` is %d \n",CP_ABE_PARA_K);
    int ret =0;
    CP_ABE_MSK msk;
    CP_ABE_MPK mpk;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret =cp_abe.SetUp(msk,mpk);
        if(ret != 0)
        {
            printf("\ncp_abe.SetUp Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("cp_abe.SetUp ret : %d time =%f sec\n",ret,sum);
    CP_APE_X X;
    CP_ABE_SK sk;
    X.x[0]=1;X.x[2]=1;
    X.x[1]=0;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret =cp_abe.KeyGen(msk,X,sk);
        if(ret != 0)
        {
            printf("\ncp_abe.KeyGen Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("cp_abe.KeyGen ret : %d time =%f sec\n",ret,sum);
    GT M;
    CP_ABE_CIPHER cipher;
    CP_ABE_SHARE_INFO share_info;
    G1 R1;G2 R2;
    pfc.random(R1);
    pfc.random(R2);
    M=pfc.pairing(R2,R1);
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret =cp_abe.Enc(mpk, M, cipher,  share_info);
        if(ret != 0)
        {
            printf("\ncp_abe.Enc Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("cp_abe.Enc ret : %d time =%f sec\n",ret,sum);
    GT M_;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret =cp_abe.Dec(mpk,X,sk,cipher, share_info,M_);
        if(ret != 0)
        {
            printf("\ncp_abe.Dec Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("cp_abe.Dec ret : %d time =%f sec\n",ret,sum);
    if(M!=M_)
    {
        printf("\ncp_abe Erro ret =%d\n",ret);
        return 1;
    }
    printf("#################test cp-abe speed end#######################\n");
    return 0;
}
int main()
{
    //return correct();
    return speed_test();

}
