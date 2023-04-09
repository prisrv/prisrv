#include"macddh.h"
#define AES_SECURITY 128
int correct()
{
    PFC pfc(AES_SECURITY);
    MACddh mac_ddh(&pfc);

    int ret =0;
    MACddh_SK sk;
    MACddh_PK pk;
    ret= mac_ddh.KeyGen(sk,pk);
    if(ret != 0)
    {
        printf("mac_ddh.KeyGen Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("mac_ddh.KeyGen pass\n");
    MACddh_M M;
    MACddh_MAC mac;
    M.N=7;
    for(int i=0;i<MACddh_PARA_N;i++)
        pfc.random(M.m[i]);
    ret = mac_ddh.MAC(sk,M,mac);
    if(ret != 0)
    {
        printf("mac_ddh.MAC Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("mac_ddh.MAC pass\n");
    ret = mac_ddh.Verify(sk,M,mac);
    if(ret != 0)
    {
        printf("mac_ddh.Verify Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("mac_ddh.Verify pass\n");
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
    MACddh mac_ddh(&pfc);
    printf("#################test macddh speed start#######################\n");
    printf("The para `n` is %d \n",MACddh_PARA_N);

    int ret =0;
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
    MACddh_SK sk;
    MACddh_PK pk;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret= mac_ddh.KeyGen(sk,pk);
        if(ret != 0)
        {
            printf("mac_ddh.KeyGen Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("mac_ddh.KeyGen ret : %d time =%f sec\n",ret,sum);
    MACddh_M M;
    MACddh_MAC mac;
    for(int i=0;i<MACddh_PARA_N;i++)
        pfc.random(M.m[i]);
    M.N=7;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = mac_ddh.MAC(sk,M,mac);
        if(ret != 0)
        {
            printf("mac_ddh.MAC Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("mac_ddh.MAC ret : %d time =%f sec\n",ret,sum);
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = mac_ddh.Verify(sk,M,mac);
        if(ret != 0)
        {
            printf("mac_ddh.Verify Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("mac_ddh.Verify ret : %d time =%f sec\n",ret,sum);
    printf("#################test macddh speed end#######################\n");
    return 0;

}
int main()
{
    //return correct();
    return speed_test();

}
