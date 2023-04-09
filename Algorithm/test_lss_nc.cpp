#include"lss_nc.h"

#define AES_SECURITY 128
int correct()
{
    PFC pfc(AES_SECURITY);
    LSS_NC lss_nc(&pfc);

    int ret =0;
    G1 u,v;
    pfc.random(u);
    LSS_NC_SHARE_INFO share_info;
    ret = lss_nc.share(u,share_info);
    if(ret != 0)
    {
        printf("lss_nc.share Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("lss_nc.share pass\n");
    ret = lss_nc.reconstruct(share_info,v);
    if(ret != 0)
    {
        printf("lss_nc.reconstruct Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("lss_nc.reconstruct pass\n");
    if(u != v)
    {
        printf("lss_nc fail\n");
        return 1;
    }
    else
        printf("lss_nc success\n");
    Big bu,bv;
    pfc.random_ord(bu);

    ret = lss_nc.share(bu,share_info);
    if(ret != 0)
    {
        printf("lss_nc.bshare Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("lss_nc.bshare pass\n");
    for(int i=0;i<1;i++)
    {

        ret = lss_nc.reconstruct(share_info,bv);
        if(ret != 0)
        {
            printf("lss_nc.breconstruct Erro ret =%d\n",ret);
            return 1;
        }
        else
            printf("lss_nc.breconstruct pass\n");
        if(bu != bv)
        {
            printf("lss_ncb fail I=%d\n",i);
            return 1;
        }
        else
            printf("lss_nc b success\n");
    }

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
    LSS_NC lss_nc(&pfc);
    printf("#################test lss speed start#######################\n");
    printf("The para of shar `n` is %d \n",LSS_NC_PARA_N);
    printf("The para of shar `m` is %d \n",LSS_NC_SHARE_NUM);

    int ret =0;
    G1 u,v;
    pfc.random(u);
    LSS_NC_SHARE_INFO share_info;
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
        ret = lss_nc.share(u,share_info);
        if(ret != 0)
        {
            printf("lss_nc.share G1 Erro ret =%d\n",ret);
            return 1;
        }

    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("lss_nc.share G1 ret : %d time =%f sec\n",ret,sum);
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = lss_nc.reconstruct(share_info,v);
        if(ret != 0)
        {
            printf("lss_nc.reconstruct G1 Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("lss_nc.reconstruct G1 ret : %d time =%f sec\n",ret,sum);
    if(u != v)
    {
        printf("lss_nc G1 fail\n");
        return 1;
    }

    Big bu,bv;
    pfc.random_ord(bu);
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = lss_nc.share(bu,share_info);
        if(ret != 0)
        {
            printf("lss_nc.bshare Big Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("lss_nc.bshare Big ret : %d time =%f sec\n",ret,sum);
    for(int i=0;i<1;i++)
    {
        start=clock();
        for(i=0;i<TEST_TIME;i++)
        {
            ret = lss_nc.reconstruct(share_info,bv);
            if(ret != 0)
            {
                printf("lss_nc.breconstruct Big Erro ret =%d\n",ret);
                return 1;
            }
        }
        finish=clock();
        sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
        printf("lss_nc.breconstruct Big ret : %d time =%f sec\n",ret,sum);
        if(bu != bv)
        {
            printf("lss_ncb fail I=%d\n",i);
            return 1;
        }
    }
    printf("#################test lss speed end#######################\n");

    return 0;
}
int main()
{
    //return correct();
    return speed_test();

}
