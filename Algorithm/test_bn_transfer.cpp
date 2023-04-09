#include "bn_transfer.h"

int test()
{

    PFC pfc(128);
    BN_transfer BN_T;
    //Big
    Big a,b;
    Big_C ac;

    pfc.random(a);
    if(a ==b) return -1;
    BN_T.Trf_Big_to_Char(a,ac);
    BN_T.Trf_Char_to_Big(ac,b);
    if(a != b) return -2;

    //G1
    G1 g1a,g1b;
    G1_C g1c;
    pfc.random(g1a);
    if(g1a==g1b) return -3;
    BN_T.Trf_G1_to_Char(g1a,g1c);
    BN_T.Trf_Char_to_G1(g1c,g1b);
    if(g1a != g1b) return -4;

    //G2
    G2 g2a,g2b;
    G2_C g2c;
    pfc.random(g2a);
    if(g2a==g2b) return -5;
    BN_T.Trf_G2_to_Char(g2a,g2c);
    BN_T.Trf_Char_to_G2(g2c,g2b);
    if(g2a != g2b) return -6;


    //GT
    GT gta,gtb;
    GT_C gtc;
    gta=pfc.pairing(g2a,g1a);
    if(gta==gtb) return -7;
    BN_T.Trf_GT_to_Char(gta,gtc);
    BN_T.Trf_Char_to_GT(gtc,gtb);
    if(gta != gtb) return -8;

    return 0;


}
int main()
{
    int ret =test();
    printf("ret =%d\n",ret);

    return ret;
}
