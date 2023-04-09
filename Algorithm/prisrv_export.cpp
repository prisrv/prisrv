#include "prisrv_export.h"
#include "prisrv.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "bn_transfer.h"


#define AES_SECURITY 128
static PFC pfc(AES_SECURITY);
static PriSrv prisrv(&pfc);
static  BN_transfer BNT;

#define WRITE_SET_DATA 0

int SetUp(struct ACME_MPK_C *mpk, struct ACME_MSK_C *msk)
{


    //////////////////////////////////////////////////
    int ret=0;
#if 1 //test
    ACME_MPK mpk2;
    ACME_MSK msk2;

    ret = prisrv.SetUp(mpk2,msk2);
    if (ret !=0) return ret;

//    streambuf* coutBuf = cout.rdbuf();
//    ofstream of("setup_data.txt");
//    streambuf* fileBuf = of.rdbuf();
//    cout.rdbuf(fileBuf);
#endif
#if 0
    //A,[A]1,k*2k
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        for(int j=0;j<2*CP_ABE_PARA_K;j++)
        {

 //           BNT.Trf_Big_to_Char(msk2.msk.A[i][j],msk->A[i][j]);
            BNT.Trf_G1_to_Char(mpk2.mpk.A1[i][j],mpk->A1[i][j]);
            BNT.bn_printfG1("mpk->A1[i][j]",mpk->A1[i][j]);
#if 0
            BNT.bn_printfBig("msk->A[i][j]",msk->A[i][j]);

#endif
        }
    }
#else

    mpk->A1[0][0].X.len=0x4;
    mpk->A1[0][0].X.w[0]=0xefe410fe28aed4c1;
    mpk->A1[0][0].X.w[1]=0x9bd277d65b18a3db;
    mpk->A1[0][0].X.w[2]=0x3cf7466e2f128d3f;
    mpk->A1[0][0].X.w[3]=0x22ea253580b324de;

    mpk->A1[0][0].Y.len=0x4;
    mpk->A1[0][0].Y.w[0]=0x45677df1671f14e4;
    mpk->A1[0][0].Y.w[1]=0x6fe99e1fc001c79;
    mpk->A1[0][0].Y.w[2]=0xeb4355782edfe9b5;
    mpk->A1[0][0].Y.w[3]=0x94058950fad5dce;

    mpk->A1[0][0].Z.len=0x4;
    mpk->A1[0][0].Z.w[0]=0x6ecfc56ff6401696;
    mpk->A1[0][0].Z.w[1]=0xfde541781f5fab6;
    mpk->A1[0][0].Z.w[2]=0xea4c8b028d6aafaf;
    mpk->A1[0][0].Z.w[3]=0x1afccc41eea4e165;

    mpk->A1[0][1].X.len=0x4;
    mpk->A1[0][1].X.w[0]=0xc959d2379ac186a2;
    mpk->A1[0][1].X.w[1]=0x6380e0ddc77923ab;
    mpk->A1[0][1].X.w[2]=0x756918d5a050bb59;
    mpk->A1[0][1].X.w[3]=0x14fdfecf5e6bc912;

    mpk->A1[0][1].Y.len=0x4;
    mpk->A1[0][1].Y.w[0]=0x546973e0853bc594;
    mpk->A1[0][1].Y.w[1]=0xd2a3ce9115f21461;
    mpk->A1[0][1].Y.w[2]=0x22f4f43a83e00e9e;
    mpk->A1[0][1].Y.w[3]=0x99f7ae3b824e7fa;

    mpk->A1[0][1].Z.len=0x4;
    mpk->A1[0][1].Z.w[0]=0x627269ee4efea474;
    mpk->A1[0][1].Z.w[1]=0x48a8bef51345ffea;
    mpk->A1[0][1].Z.w[2]=0xd2455a6b23da9a44;
    mpk->A1[0][1].Z.w[3]=0x465edaeb7712e0b;

    mpk->A1[0][2].X.len=0x4;
    mpk->A1[0][2].X.w[0]=0xb95734ae21f82d74;
    mpk->A1[0][2].X.w[1]=0xa98107218be947ab;
    mpk->A1[0][2].X.w[2]=0xd736e9f3ebd602d7;
    mpk->A1[0][2].X.w[3]=0xc38c0b86605fb6c;

    mpk->A1[0][2].Y.len=0x4;
    mpk->A1[0][2].Y.w[0]=0x65b7b6ff83fb3761;
    mpk->A1[0][2].Y.w[1]=0x283cc15a950d7968;
    mpk->A1[0][2].Y.w[2]=0xfe6d546eeaed8aa9;
    mpk->A1[0][2].Y.w[3]=0x1e4443fd2ff48ee7;

    mpk->A1[0][2].Z.len=0x4;
    mpk->A1[0][2].Z.w[0]=0x9004408350f34deb;
    mpk->A1[0][2].Z.w[1]=0xb99000865313b1dd;
    mpk->A1[0][2].Z.w[2]=0x150a00b81c95ab69;
    mpk->A1[0][2].Z.w[3]=0x1c1adc88da7953b;

    mpk->A1[0][3].X.len=0x4;
    mpk->A1[0][3].X.w[0]=0xfbc10a1bed28d574;
    mpk->A1[0][3].X.w[1]=0x21525fa70a66a132;
    mpk->A1[0][3].X.w[2]=0x8cd60b30f6e78ed5;
    mpk->A1[0][3].X.w[3]=0x3a1674fc89d2ac;

    mpk->A1[0][3].Y.len=0x4;
    mpk->A1[0][3].Y.w[0]=0x68eadfe70039d630;
    mpk->A1[0][3].Y.w[1]=0x42cae9de84664157;
    mpk->A1[0][3].Y.w[2]=0xf222844d5eec7a45;
    mpk->A1[0][3].Y.w[3]=0xc904de5c6c1b0a1;

    mpk->A1[0][3].Z.len=0x4;
    mpk->A1[0][3].Z.w[0]=0xc239d106fd5700e8;
    mpk->A1[0][3].Z.w[1]=0xe9cea0852a24e36c;
    mpk->A1[0][3].Z.w[2]=0x5d817129fb7fb365;
    mpk->A1[0][3].Z.w[3]=0x164461d8c93ebe70;

    mpk->A1[0][4].X.len=0x4;
    mpk->A1[0][4].X.w[0]=0xb4c8cd2923f20661;
    mpk->A1[0][4].X.w[1]=0xf337b92c8c019f6e;
    mpk->A1[0][4].X.w[2]=0x82010b1423fa4b4f;
    mpk->A1[0][4].X.w[3]=0x12475a835eebcc4c;

    mpk->A1[0][4].Y.len=0x4;
    mpk->A1[0][4].Y.w[0]=0x6bb38c9130b133fc;
    mpk->A1[0][4].Y.w[1]=0x6fbfe7c26755608c;
    mpk->A1[0][4].Y.w[2]=0x6672c8b749ea3a31;
    mpk->A1[0][4].Y.w[3]=0x244762d92c96d4a6;

    mpk->A1[0][4].Z.len=0x4;
    mpk->A1[0][4].Z.w[0]=0x9131b58078f0aab6;
    mpk->A1[0][4].Z.w[1]=0x163c33de2612b17e;
    mpk->A1[0][4].Z.w[2]=0xd4b9b49ee2e81206;
    mpk->A1[0][4].Z.w[3]=0x4453cc251818046;

    mpk->A1[0][5].X.len=0x4;
    mpk->A1[0][5].X.w[0]=0x4dce9712aad95563;
    mpk->A1[0][5].X.w[1]=0xbcc653d52a62e8db;
    mpk->A1[0][5].X.w[2]=0x2fd28a77c03d7786;
    mpk->A1[0][5].X.w[3]=0x1b55c4dc1ee77f37;

    mpk->A1[0][5].Y.len=0x4;
    mpk->A1[0][5].Y.w[0]=0xc62c4c10deee4df2;
    mpk->A1[0][5].Y.w[1]=0xd5eab899d136e101;
    mpk->A1[0][5].Y.w[2]=0xe8af2a2a4dabcf15;
    mpk->A1[0][5].Y.w[3]=0x4cedf91ac86f377;

    mpk->A1[0][5].Z.len=0x4;
    mpk->A1[0][5].Z.w[0]=0xce662af7ec5daaa8;
    mpk->A1[0][5].Z.w[1]=0xb43a93c63085b3d6;
    mpk->A1[0][5].Z.w[2]=0xbcd13a4a04dda24f;
    mpk->A1[0][5].Z.w[3]=0x194da18f72b65679;

    mpk->A1[1][0].X.len=0x4;
    mpk->A1[1][0].X.w[0]=0x710b9eac59f81304;
    mpk->A1[1][0].X.w[1]=0x3408e77a9981c09b;
    mpk->A1[1][0].X.w[2]=0x1f8576ff87bfd56b;
    mpk->A1[1][0].X.w[3]=0x11d758222c417247;

    mpk->A1[1][0].Y.len=0x4;
    mpk->A1[1][0].Y.w[0]=0x4e7e5e6027f7f611;
    mpk->A1[1][0].Y.w[1]=0x4e311da1d8d7424b;
    mpk->A1[1][0].Y.w[2]=0xc2c12e8b7e20d234;
    mpk->A1[1][0].Y.w[3]=0x43b869562bd1c90;

    mpk->A1[1][0].Z.len=0x4;
    mpk->A1[1][0].Z.w[0]=0x54bd0aba52b85068;
    mpk->A1[1][0].Z.w[1]=0x7dcdf7f68a439da8;
    mpk->A1[1][0].Z.w[2]=0x54ea5feb45dbc73a;
    mpk->A1[1][0].Z.w[3]=0x1839fd5c93c50f42;

    mpk->A1[1][1].X.len=0x4;
    mpk->A1[1][1].X.w[0]=0x5c312ddbf81df772;
    mpk->A1[1][1].X.w[1]=0x5e0744c6e31f8352;
    mpk->A1[1][1].X.w[2]=0xd6a39a7e4741d74;
    mpk->A1[1][1].X.w[3]=0x1e9d5d92eea2c325;

    mpk->A1[1][1].Y.len=0x4;
    mpk->A1[1][1].Y.w[0]=0x5f2e38aa4417940;
    mpk->A1[1][1].Y.w[1]=0x9049a66f29e2501e;
    mpk->A1[1][1].Y.w[2]=0xa8314a52e5ae2c1e;
    mpk->A1[1][1].Y.w[3]=0xbd86cda67669e33;

    mpk->A1[1][1].Z.len=0x4;
    mpk->A1[1][1].Z.w[0]=0xed1aaad5a733f7d8;
    mpk->A1[1][1].Z.w[1]=0xd6f30934957b34d5;
    mpk->A1[1][1].Z.w[2]=0xee12af24f1f5b133;
    mpk->A1[1][1].Z.w[3]=0x146adb56a189b7f8;

    mpk->A1[1][2].X.len=0x4;
    mpk->A1[1][2].X.w[0]=0xa0d5c53b2993df1a;
    mpk->A1[1][2].X.w[1]=0x3339ff4b7ad54e59;
    mpk->A1[1][2].X.w[2]=0x5747e4bf3f861028;
    mpk->A1[1][2].X.w[3]=0x17b8ba22592946de;

    mpk->A1[1][2].Y.len=0x4;
    mpk->A1[1][2].Y.w[0]=0x949310fc467a68f3;
    mpk->A1[1][2].Y.w[1]=0x54da2842ca8e1ab4;
    mpk->A1[1][2].Y.w[2]=0xbb1d81acd666be98;
    mpk->A1[1][2].Y.w[3]=0x180ea10aab2cf358;

    mpk->A1[1][2].Z.len=0x4;
    mpk->A1[1][2].Z.w[0]=0xefe08ad8cf98eed;
    mpk->A1[1][2].Z.w[1]=0x603dbfd806a1e76;
    mpk->A1[1][2].Z.w[2]=0x4771981ac4783234;
    mpk->A1[1][2].Z.w[3]=0x2398d0423d83d8e4;

    mpk->A1[1][3].X.len=0x4;
    mpk->A1[1][3].X.w[0]=0x23f8c726870309a6;
    mpk->A1[1][3].X.w[1]=0x79a62917d75d59c6;
    mpk->A1[1][3].X.w[2]=0x3f2df4f8221ad8d6;
    mpk->A1[1][3].X.w[3]=0x1aa5fdc6c46738bc;

    mpk->A1[1][3].Y.len=0x4;
    mpk->A1[1][3].Y.w[0]=0x16550efbd2963b86;
    mpk->A1[1][3].Y.w[1]=0x4e21e91d0b81b77c;
    mpk->A1[1][3].Y.w[2]=0xa4d1c84d791d9404;
    mpk->A1[1][3].Y.w[3]=0x1133858d68807653;

    mpk->A1[1][3].Z.len=0x4;
    mpk->A1[1][3].Z.w[0]=0xb41a1d45a7f4e9c5;
    mpk->A1[1][3].Z.w[1]=0x6e959d98a8d1d90d;
    mpk->A1[1][3].Z.w[2]=0xfd3a2f9ec2db9760;
    mpk->A1[1][3].Z.w[3]=0xd757434190d35a4;

    mpk->A1[1][4].X.len=0x4;
    mpk->A1[1][4].X.w[0]=0x4fca7d794e66f7c;
    mpk->A1[1][4].X.w[1]=0x6ddd869a074ba68e;
    mpk->A1[1][4].X.w[2]=0x234ee838d29d54e7;
    mpk->A1[1][4].X.w[3]=0xabbe6ecb0f0dc01;

    mpk->A1[1][4].Y.len=0x4;
    mpk->A1[1][4].Y.w[0]=0x8a881cb7ae6bc239;
    mpk->A1[1][4].Y.w[1]=0x4971379d2608b183;
    mpk->A1[1][4].Y.w[2]=0xa6ec72dae784e9a4;
    mpk->A1[1][4].Y.w[3]=0x36d3cecbea7eb64;

    mpk->A1[1][4].Z.len=0x4;
    mpk->A1[1][4].Z.w[0]=0x12a39984fba99e0e;
    mpk->A1[1][4].Z.w[1]=0x1977e14ce365b7b1;
    mpk->A1[1][4].Z.w[2]=0xfd160782aa805da3;
    mpk->A1[1][4].Z.w[3]=0xc8dedc7d6062499;

    mpk->A1[1][5].X.len=0x4;
    mpk->A1[1][5].X.w[0]=0xce2b79bf025221ab;
    mpk->A1[1][5].X.w[1]=0xafa46abeac0c2360;
    mpk->A1[1][5].X.w[2]=0x8dbc67e5af93cedb;
    mpk->A1[1][5].X.w[3]=0xbd5ffe94cec9be5;

    mpk->A1[1][5].Y.len=0x4;
    mpk->A1[1][5].Y.w[0]=0x74d2b925a99f4c60;
    mpk->A1[1][5].Y.w[1]=0xeaee6e450ccad364;
    mpk->A1[1][5].Y.w[2]=0x6477a90aeb6f9c5a;
    mpk->A1[1][5].Y.w[3]=0xb0678339b745733;

    mpk->A1[1][5].Z.len=0x4;
    mpk->A1[1][5].Z.w[0]=0x56b9dcc5641361ee;
    mpk->A1[1][5].Z.w[1]=0xb158294af21605fb;
    mpk->A1[1][5].Z.w[2]=0xaf7945fd44248195;
    mpk->A1[1][5].Z.w[3]=0xfff60084b18bae1;

    mpk->A1[2][0].X.len=0x4;
    mpk->A1[2][0].X.w[0]=0x781a89099942bcd8;
    mpk->A1[2][0].X.w[1]=0xe91bc5a9a30f5965;
    mpk->A1[2][0].X.w[2]=0xef15654d898198df;
    mpk->A1[2][0].X.w[3]=0x1b1348fa07831b4;

    mpk->A1[2][0].Y.len=0x4;
    mpk->A1[2][0].Y.w[0]=0x99b63e232b6c474a;
    mpk->A1[2][0].Y.w[1]=0x4d0cb1f421aa97aa;
    mpk->A1[2][0].Y.w[2]=0x308500c790892b8f;
    mpk->A1[2][0].Y.w[3]=0x12530a36fc6cf1e5;

    mpk->A1[2][0].Z.len=0x4;
    mpk->A1[2][0].Z.w[0]=0x3a711a2e8703dd00;
    mpk->A1[2][0].Z.w[1]=0x5a561310f53e7a3e;
    mpk->A1[2][0].Z.w[2]=0xcb25e8e0fd760249;
    mpk->A1[2][0].Z.w[3]=0x724ee8c83e63eb4;

    mpk->A1[2][1].X.len=0x4;
    mpk->A1[2][1].X.w[0]=0x4d08f47cf586b8c1;
    mpk->A1[2][1].X.w[1]=0xf50623285b4bfe4a;
    mpk->A1[2][1].X.w[2]=0x8789a10bf7961b84;
    mpk->A1[2][1].X.w[3]=0xf072b0bfa9c88d3;

    mpk->A1[2][1].Y.len=0x4;
    mpk->A1[2][1].Y.w[0]=0x3f532ebbf18502af;
    mpk->A1[2][1].Y.w[1]=0xba3c899ed420c4e7;
    mpk->A1[2][1].Y.w[2]=0xec1664f71e2b6286;
    mpk->A1[2][1].Y.w[3]=0x13a3d0d611f42284;

    mpk->A1[2][1].Z.len=0x4;
    mpk->A1[2][1].Z.w[0]=0xe5a6316657409c0a;
    mpk->A1[2][1].Z.w[1]=0xcab3c73fa3d8558;
    mpk->A1[2][1].Z.w[2]=0x1e2643bbd1b9b6e0;
    mpk->A1[2][1].Z.w[3]=0x12b70ab0a1b1173;

    mpk->A1[2][2].X.len=0x4;
    mpk->A1[2][2].X.w[0]=0xa1153b6dfd3aa8d8;
    mpk->A1[2][2].X.w[1]=0xee9100413ca7758d;
    mpk->A1[2][2].X.w[2]=0xeede0b96e7901f58;
    mpk->A1[2][2].X.w[3]=0xdc20ebbf04d0540;

    mpk->A1[2][2].Y.len=0x4;
    mpk->A1[2][2].Y.w[0]=0x843e8dbd1b9371ed;
    mpk->A1[2][2].Y.w[1]=0x6e884a9f1292fde8;
    mpk->A1[2][2].Y.w[2]=0x7bcb9a2234e8aff9;
    mpk->A1[2][2].Y.w[3]=0x120a0c2185315dfb;

    mpk->A1[2][2].Z.len=0x4;
    mpk->A1[2][2].Z.w[0]=0xe561bfd255727cb8;
    mpk->A1[2][2].Z.w[1]=0xc5c5f6e8788b7932;
    mpk->A1[2][2].Z.w[2]=0xfc23414a7a64ec06;
    mpk->A1[2][2].Z.w[3]=0x2437718c13d5286b;

    mpk->A1[2][3].X.len=0x4;
    mpk->A1[2][3].X.w[0]=0x54a63f5131d33468;
    mpk->A1[2][3].X.w[1]=0x53a7971a97ee6f89;
    mpk->A1[2][3].X.w[2]=0xe1d7408b28d947e;
    mpk->A1[2][3].X.w[3]=0x2261336d011463d8;

    mpk->A1[2][3].Y.len=0x4;
    mpk->A1[2][3].Y.w[0]=0xbbbfb95807014dfe;
    mpk->A1[2][3].Y.w[1]=0x8bac6f5a99d8e5f5;
    mpk->A1[2][3].Y.w[2]=0xb7febdc33ed46ab0;
    mpk->A1[2][3].Y.w[3]=0xdb8aed90e8d94b4;

    mpk->A1[2][3].Z.len=0x4;
    mpk->A1[2][3].Z.w[0]=0x3d3a10ac053a8929;
    mpk->A1[2][3].Z.w[1]=0xda03de84bf6dbd79;
    mpk->A1[2][3].Z.w[2]=0xb4961bee5dd2cd1c;
    mpk->A1[2][3].Z.w[3]=0x54fcf5661bb4a87;

    mpk->A1[2][4].X.len=0x4;
    mpk->A1[2][4].X.w[0]=0x26f1fe7c72740c7e;
    mpk->A1[2][4].X.w[1]=0x6daea833ba3feaeb;
    mpk->A1[2][4].X.w[2]=0x8acd7688c64fbd29;
    mpk->A1[2][4].X.w[3]=0x107c7bd70d8fe426;

    mpk->A1[2][4].Y.len=0x4;
    mpk->A1[2][4].Y.w[0]=0x59a57bc53c68d4a9;
    mpk->A1[2][4].Y.w[1]=0xfa6bf8974894fb53;
    mpk->A1[2][4].Y.w[2]=0x97a9f2db9cc28fe3;
    mpk->A1[2][4].Y.w[3]=0x234bb5aa12ee09cd;

    mpk->A1[2][4].Z.len=0x4;
    mpk->A1[2][4].Z.w[0]=0xe01380b16b07d8ed;
    mpk->A1[2][4].Z.w[1]=0x474601a64b5e161f;
    mpk->A1[2][4].Z.w[2]=0x50b89a322e76101d;
    mpk->A1[2][4].Z.w[3]=0x23c873ec4989a074;


    mpk->A1[2][5].X.len=0x4;
    mpk->A1[2][5].X.w[0]=0xf73e87695977b0be;
    mpk->A1[2][5].X.w[1]=0x81ea470ad2063c6c;
    mpk->A1[2][5].X.w[2]=0x3005e91aa4c03d6c;
    mpk->A1[2][5].X.w[3]=0x15c0cf3a882c225c;

    mpk->A1[2][5].Y.len=0x4;
    mpk->A1[2][5].Y.w[0]=0x49c26ccf1601349f;
    mpk->A1[2][5].Y.w[1]=0x28c4a20a989c665e;
    mpk->A1[2][5].Y.w[2]=0x6166d69723dd4838;
    mpk->A1[2][5].Y.w[3]=0x17cc6f648b402771;

    mpk->A1[2][5].Z.len=0x4;
    mpk->A1[2][5].Z.w[0]=0x18ad9a2287833656;
    mpk->A1[2][5].Z.w[1]=0xf138645be9892ee5;
    mpk->A1[2][5].Z.w[2]=0x151f221269574e37;
    mpk->A1[2][5].Z.w[3]=0xed104627545e87e;

    ////////////////////
    msk->A[0][0].len=0x4;
    msk->A[0][0].w[0]=0x27d0e2cba388f8ff;
    msk->A[0][0].w[1]=0xb7e01dd947ef58e8;
    msk->A[0][0].w[2]=0xec55b8d020cb53c9;
    msk->A[0][0].w[3]=0xf9a74eab06f8e483;

    msk->A[0][1].len=0x4;
    msk->A[0][1].w[0]=0x26165277d027bfe5;
    msk->A[0][1].w[1]=0x9b7d04aed594e20;
    msk->A[0][1].w[2]=0xa8adc5e2af8244a;
    msk->A[0][1].w[3]=0x80eca0dca4a463aa;

    msk->A[0][2].len=0x4;
    msk->A[0][2].w[0]=0xa1df74f231a7a352;
    msk->A[0][2].w[1]=0xc00d5a55de3b3fb7;
    msk->A[0][2].w[2]=0x8acedc1b55905de5;
    msk->A[0][2].w[3]=0xcce57c0db02d6870;

    msk->A[0][3].len=0x4;
    msk->A[0][3].w[0]=0xc521785012772f9c;
    msk->A[0][3].w[1]=0xb0a52c0c9c28dfc4;
    msk->A[0][3].w[2]=0x25da8fed9b0ff3d3;
    msk->A[0][3].w[3]=0x99f707dd0e137fd2;

    msk->A[0][4].len=0x4;
    msk->A[0][4].w[0]=0xc25a9fae85354426;
    msk->A[0][4].w[1]=0xf7b4e3af9c713d01;
    msk->A[0][4].w[2]=0xce935a84a571d157;
    msk->A[0][4].w[3]=0xae7265b38e5170d7;

    msk->A[0][5].len=0x4;
    msk->A[0][5].w[0]=0x8897d5c6f3417d04;
    msk->A[0][5].w[1]=0xdd3a087a31dc3b2e;
    msk->A[0][5].w[2]=0x7076f960234e2615;
    msk->A[0][5].w[3]=0xe28357518fbecbb8;

    msk->A[1][0].len=0x4;
    msk->A[1][0].w[0]=0x19037e03e5ea86f8;
    msk->A[1][0].w[1]=0xae35b27a4367e6f2;
    msk->A[1][0].w[2]=0xa0e546d89394db43;
    msk->A[1][0].w[3]=0xe3c1cf86269e583c;

    msk->A[1][1].len=0x4;
    msk->A[1][1].w[0]=0xe3f8bfcff54c5475;
    msk->A[1][1].w[1]=0x72019e268de08fc6;
    msk->A[1][1].w[2]=0xa59bc327ef93b064;
    msk->A[1][1].w[3]=0xcccb52a3f3fae203;

    msk->A[1][2].len=0x4;
    msk->A[1][2].w[0]=0x2ba236f361d8ad0c;
    msk->A[1][2].w[1]=0xf47e4f55bd5a6792;
    msk->A[1][2].w[2]=0x1c0a436cd57c0537;
    msk->A[1][2].w[3]=0xa241747306c60abf;

    msk->A[1][3].len=0x4;
    msk->A[1][3].w[0]=0xc1ae08e4706aaa8f;
    msk->A[1][3].w[1]=0xbff9f8b801ab1dc8;
    msk->A[1][3].w[2]=0x3547b1024aec54ae;
    msk->A[1][3].w[3]=0x8e4acb59e74de62d;

    msk->A[1][4].len=0x4;
    msk->A[1][4].w[0]=0x9339f8c931e1ce2d;
    msk->A[1][4].w[1]=0x3d5f183c74c97c76;
    msk->A[1][4].w[2]=0xe3048518f0bd250b;
    msk->A[1][4].w[3]=0xb2cd60f68d83433f;

    msk->A[1][5].len=0x4;
    msk->A[1][5].w[0]=0xb587dd6294d1e2d1;
    msk->A[1][5].w[1]=0xe25d9dbd7165fdf6;
    msk->A[1][5].w[2]=0x5e843943f8efd64d;
    msk->A[1][5].w[3]=0x8079aca6a26f216d;

    msk->A[2][0].len=0x4;
    msk->A[2][0].w[0]=0xce9d1867da1d96fd;
    msk->A[2][0].w[1]=0xcbc9a739c8f63330;
    msk->A[2][0].w[2]=0xfd5f8c20ee47955a;
    msk->A[2][0].w[3]=0xd10f9d2ac4972b6a;

    msk->A[2][1].len=0x4;
    msk->A[2][1].w[0]=0x6266904077c3ddba;
    msk->A[2][1].w[1]=0xf59977a25841223d;
    msk->A[2][1].w[2]=0xac4767497f706867;
    msk->A[2][1].w[3]=0xc8d55cdf1fe6e445;

    msk->A[2][2].len=0x4;
    msk->A[2][2].w[0]=0x8e0b85c695b115a1;
    msk->A[2][2].w[1]=0x191c2cc96cae4383;
    msk->A[2][2].w[2]=0x2a6d911e91c73b23;
    msk->A[2][2].w[3]=0xa3c890f101f9c3bc;

    msk->A[2][3].len=0x4;
    msk->A[2][3].w[0]=0xcf9e28ba8a8a3979;
    msk->A[2][3].w[1]=0x46dad4320db254fe;
    msk->A[2][3].w[2]=0x6ecf8581113708f4;
    msk->A[2][3].w[3]=0xec9617fd33751e3a;

    msk->A[2][4].len=0x4;
    msk->A[2][4].w[0]=0x9078d1c13a9669b;
    msk->A[2][4].w[1]=0xf4aa0625d3bdeaf8;
    msk->A[2][4].w[2]=0x534b1fec3659ded9;
    msk->A[2][4].w[3]=0xad98e9463b755e4b;

    msk->A[2][5].len=0x4;
    msk->A[2][5].w[0]=0x7654a58bdba9084e;
    msk->A[2][5].w[1]=0xfd6cb13c7e31d926;
    msk->A[2][5].w[2]=0x3257619e64a682ef;
    msk->A[2][5].w[3]=0xda27f376b4eb2f48;
#endif

#if 0
    //B,k*k
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        for(int j=0;j<CP_ABE_PARA_K;j++)
        {
            BNT.Trf_Big_to_Char(msk2.msk.B[i][j],msk->B[i][j]);
#if 1
            BNT.bn_printfBig("msk->B[i][j]",msk->B[i][j]);

#endif

        }
    }
#else
    msk->B[0][0].len=0x4;
    msk->B[0][0].w[0]=0xb9361049834208d;
    msk->B[0][0].w[1]=0x8205839c31317fb6;
    msk->B[0][0].w[2]=0x3ec670469f92340e;
    msk->B[0][0].w[3]=0xbded39cd3545a58f;

    msk->B[0][1].len=0x4;
    msk->B[0][1].w[0]=0x88a4d5b5dfbc1857;
    msk->B[0][1].w[1]=0x3020de2b0316ec82;
    msk->B[0][1].w[2]=0xfbbd763fc8198cc6;
    msk->B[0][1].w[3]=0xf82e5956c50498db;

    msk->B[0][2].len=0x4;
    msk->B[0][2].w[0]=0x3299424d0fa05b07;
    msk->B[0][2].w[1]=0xd5bf345150bf0b3;
    msk->B[0][2].w[2]=0xeea2f6580c783247;
    msk->B[0][2].w[3]=0x8a0d18bb6c995185;

    msk->B[1][0].len=0x4;
    msk->B[1][0].w[0]=0xaedc154d159d3348;
    msk->B[1][0].w[1]=0xadbb0b7d16280af2;
    msk->B[1][0].w[2]=0xd97246a01472eb44;
    msk->B[1][0].w[3]=0xe5cf47e9352cd166;

    msk->B[1][1].len=0x4;
    msk->B[1][1].w[0]=0xe6e02e2000ae5d6c;
    msk->B[1][1].w[1]=0xd4c05bf3d0ef9402;
    msk->B[1][1].w[2]=0x4fdea52985d435be;
    msk->B[1][1].w[3]=0x8c671afd0ee6de00;

    msk->B[1][2].len=0x4;
    msk->B[1][2].w[0]=0x70dbdb4636231b98;
    msk->B[1][2].w[1]=0xcd688647e9d77c71;
    msk->B[1][2].w[2]=0x4b963be2cce5e0d3;
    msk->B[1][2].w[3]=0xe38ec8a4c9d1eb98;

    msk->B[2][0].len=0x4;
    msk->B[2][0].w[0]=0x1a53c88f0fd060a7;
    msk->B[2][0].w[1]=0xd2413e3b574cd3e7;
    msk->B[2][0].w[2]=0xd7cfacc211969775;
    msk->B[2][0].w[3]=0x916767db3d2f0a52;

    msk->B[2][1].len=0x4;
    msk->B[2][1].w[0]=0x3a772ef3202cb5fc;
    msk->B[2][1].w[1]=0x4c353ffc67d35e66;
    msk->B[2][1].w[2]=0xa221691f96347407;
    msk->B[2][1].w[3]=0xe790af100291f3e8;

    msk->B[2][2].len=0x4;
    msk->B[2][2].w[0]=0xedea9bdee1e95844;
    msk->B[2][2].w[1]=0x3e5d44d1adb882f5;
    msk->B[2][2].w[2]=0x1aa2ca31e9c9ae2d;
    msk->B[2][2].w[3]=0xa1b4e72d77343617;



#endif
#if 0
    //U0,2k*k
    for(int i=0;i<2*CP_ABE_PARA_K;i++)
    {
        for(int j=0;j<CP_ABE_PARA_K;j++)
        {
            BNT.Trf_Big_to_Char(msk2.msk.U0[i][j],msk->U0[i][j]);
#if 1
            BNT.bn_printfBig("msk->U0[i][j]",msk->U0[i][j]);

#endif

        }
    }
#else
    msk->U0[0][0].len=0x4;
    msk->U0[0][0].w[0]=0x54b17788e545b5be;
    msk->U0[0][0].w[1]=0xccf2cde3fdaf5b97;
    msk->U0[0][0].w[2]=0xac65140fc965d86f;
    msk->U0[0][0].w[3]=0x87b82fed467e0c1a;

    msk->U0[0][1].len=0x4;
    msk->U0[0][1].w[0]=0xfc94bf666fd441a;
    msk->U0[0][1].w[1]=0x539f9bd5b40720c4;
    msk->U0[0][1].w[2]=0xfe9b286cf0b80964;
    msk->U0[0][1].w[3]=0xdce89e44639f254f;

    msk->U0[0][2].len=0x4;
    msk->U0[0][2].w[0]=0xb1b7fe9a89fb533f;
    msk->U0[0][2].w[1]=0x978d94855a022e45;
    msk->U0[0][2].w[2]=0xe1422dafb50a8fb1;
    msk->U0[0][2].w[3]=0xca14d2e8654b1726;

    msk->U0[1][0].len=0x4;
    msk->U0[1][0].w[0]=0x6addf5f991beed7e;
    msk->U0[1][0].w[1]=0xd9981856ac967a06;
    msk->U0[1][0].w[2]=0xc5c210566dea1e5e;
    msk->U0[1][0].w[3]=0xd2da181575052da7;

    msk->U0[1][1].len=0x4;
    msk->U0[1][1].w[0]=0x66afeeba77a6625d;
    msk->U0[1][1].w[1]=0x7930081e073ed0a9;
    msk->U0[1][1].w[2]=0xb3fba3303f681b23;
    msk->U0[1][1].w[3]=0xfade7b6c3bc6bd16;

    msk->U0[1][2].len=0x4;
    msk->U0[1][2].w[0]=0x8476d1f80c5acb36;
    msk->U0[1][2].w[1]=0x8e90dbc7a108847c;
    msk->U0[1][2].w[2]=0x9de989a40d721831;
    msk->U0[1][2].w[3]=0xbdba9cb2c9b7ebd4;

    msk->U0[2][0].len=0x4;
    msk->U0[2][0].w[0]=0xd444ae6ed33a2012;
    msk->U0[2][0].w[1]=0x2e9f0780197e1663;
    msk->U0[2][0].w[2]=0xb250e1878a11c51e;
    msk->U0[2][0].w[3]=0xef7a658b5d8216b4;

    msk->U0[2][1].len=0x4;
    msk->U0[2][1].w[0]=0xf48f72c2b672a5e6;
    msk->U0[2][1].w[1]=0xb64ef6fe26dd4c69;
    msk->U0[2][1].w[2]=0x465ab81c7cae3053;
    msk->U0[2][1].w[3]=0xaa2835880d234b2c;

    msk->U0[2][2].len=0x4;
    msk->U0[2][2].w[0]=0xd7dcd2b9e340dbcf;
    msk->U0[2][2].w[1]=0x7815e2e0970d5c0d;
    msk->U0[2][2].w[2]=0x5bea8292ae703092;
    msk->U0[2][2].w[3]=0xb9b7ced7f7d8dced;

    msk->U0[3][0].len=0x4;
    msk->U0[3][0].w[0]=0x6ec38fd30d51b4d8;
    msk->U0[3][0].w[1]=0xed0cba347460e884;
    msk->U0[3][0].w[2]=0x26ed2952e7fc4dfd;
    msk->U0[3][0].w[3]=0xef8654ebff7c81c4;

    msk->U0[3][1].len=0x4;
    msk->U0[3][1].w[0]=0x643ffff589dfbdba;
    msk->U0[3][1].w[1]=0x26b1ee25aa351c4e;
    msk->U0[3][1].w[2]=0x9bfd39b8207ffa1a;
    msk->U0[3][1].w[3]=0xbefc0bdd8e4af78d;

    msk->U0[3][2].len=0x4;
    msk->U0[3][2].w[0]=0x3b6987f20544e697;
    msk->U0[3][2].w[1]=0x96a2545b6b8cae3d;
    msk->U0[3][2].w[2]=0x118087ceb40ccf8e;
    msk->U0[3][2].w[3]=0xc7744195b7c3801e;

    msk->U0[4][0].len=0x4;
    msk->U0[4][0].w[0]=0x7f288fde36779112;
    msk->U0[4][0].w[1]=0x6f9b8a6864c37e30;
    msk->U0[4][0].w[2]=0xccb862657427e25d;
    msk->U0[4][0].w[3]=0xd997988f77a7142f;

    msk->U0[4][1].len=0x4;
    msk->U0[4][1].w[0]=0x78ad9011fe959903;
    msk->U0[4][1].w[1]=0x14e85d7407646ad;
    msk->U0[4][1].w[2]=0x363f6339dee197f5;
    msk->U0[4][1].w[3]=0x95d8f1017a2ebc73;

    msk->U0[4][2].len=0x4;
    msk->U0[4][2].w[0]=0x66963551ec8b72e1;
    msk->U0[4][2].w[1]=0x88b2f4d2c854199c;
    msk->U0[4][2].w[2]=0x36b0ae645ec555c0;
    msk->U0[4][2].w[3]=0x858ddefe1d0c642e;

    msk->U0[5][0].len=0x4;
    msk->U0[5][0].w[0]=0xd05144a349f7a413;
    msk->U0[5][0].w[1]=0x64a31b6fa52e80c;
    msk->U0[5][0].w[2]=0x37f3bc45f4d4b473;
    msk->U0[5][0].w[3]=0xca5d086c863cc0a0;

    msk->U0[5][1].len=0x4;
    msk->U0[5][1].w[0]=0xbb855a0c749944;
    msk->U0[5][1].w[1]=0xf5d87fe4f1d34e49;
    msk->U0[5][1].w[2]=0x649b0930d41efdb2;
    msk->U0[5][1].w[3]=0x93bcb2ba4b684964;

    msk->U0[5][2].len=0x4;
    msk->U0[5][2].w[0]=0x4f8c123cb083ef52;
    msk->U0[5][2].w[1]=0x4a74ddfc9ce9e7a3;
    msk->U0[5][2].w[2]=0x33a117606d7aac8c;
    msk->U0[5][2].w[3]=0xe7ab32ec2bfa5967;
#endif
#if 0
    //[AU0]1,k*k
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        for(int j=0;j<CP_ABE_PARA_K;j++)
        {
            BNT.Trf_G1_to_Char(mpk2.mpk.AU01[i][j],mpk->AU01[i][j]);
#if 1
            BNT.bn_printfG1("mpk->AU01[i][j]",mpk->AU01[i][j]);

#endif
        }
    }
#else
    mpk->AU01[0][0].X.len=0x4;
    mpk->AU01[0][0].X.w[0]=0xf8e73ad5721c0c6a;
    mpk->AU01[0][0].X.w[1]=0x8263f9d2e71185a2;
    mpk->AU01[0][0].X.w[2]=0x9b32168a778111da;
    mpk->AU01[0][0].X.w[3]=0xacc158d4382ddda;

    mpk->AU01[0][0].Y.len=0x4;
    mpk->AU01[0][0].Y.w[0]=0x3758bae7d28c771a;
    mpk->AU01[0][0].Y.w[1]=0xcd29a2d920039a0b;
    mpk->AU01[0][0].Y.w[2]=0xbf7c995aa5b199a9;
    mpk->AU01[0][0].Y.w[3]=0x1115723d3fca0d17;

    mpk->AU01[0][0].Z.len=0x4;
    mpk->AU01[0][0].Z.w[0]=0x5f7a3a4bb83d63e1;
    mpk->AU01[0][0].Z.w[1]=0x469cd3affa84322f;
    mpk->AU01[0][0].Z.w[2]=0xf4511309e09864a1;
    mpk->AU01[0][0].Z.w[3]=0x1767cd7d1109f0d2;

    mpk->AU01[0][1].X.len=0x4;
    mpk->AU01[0][1].X.w[0]=0xf1b44b3a6ce07e66;
    mpk->AU01[0][1].X.w[1]=0xb88d86f66221205c;
    mpk->AU01[0][1].X.w[2]=0xc2d70510a073b138;
    mpk->AU01[0][1].X.w[3]=0x128f3e5d636101dd;

    mpk->AU01[0][1].Y.len=0x4;
    mpk->AU01[0][1].Y.w[0]=0x84d3a7987522d1d4;
    mpk->AU01[0][1].Y.w[1]=0x4f87733219aff585;
    mpk->AU01[0][1].Y.w[2]=0x86633f10b7c9beca;
    mpk->AU01[0][1].Y.w[3]=0x1d568d560461d3e2;

    mpk->AU01[0][1].Z.len=0x4;
    mpk->AU01[0][1].Z.w[0]=0xfb20505b8bad6893;
    mpk->AU01[0][1].Z.w[1]=0x231980deb45ae3d6;
    mpk->AU01[0][1].Z.w[2]=0xec4adecc17cba49a;
    mpk->AU01[0][1].Z.w[3]=0x22e89e8968858dc0;

    mpk->AU01[0][2].X.len=0x4;
    mpk->AU01[0][2].X.w[0]=0x4a21bd5497e66c0f;
    mpk->AU01[0][2].X.w[1]=0xd22a191b91a42bc1;
    mpk->AU01[0][2].X.w[2]=0xa4c2d9ea12e6e785;
    mpk->AU01[0][2].X.w[3]=0x218e04b526c9b7f1;

    mpk->AU01[0][2].Y.len=0x4;
    mpk->AU01[0][2].Y.w[0]=0x39e0fbdc95146aaf;
    mpk->AU01[0][2].Y.w[1]=0xd45478cd0ff8cfe9;
    mpk->AU01[0][2].Y.w[2]=0x7bf7bf182457c7f8;
    mpk->AU01[0][2].Y.w[3]=0xd472fc4dce879;

    mpk->AU01[0][2].Z.len=0x4;
    mpk->AU01[0][2].Z.w[0]=0xdcf2b206e1015821;
    mpk->AU01[0][2].Z.w[1]=0x721b2e99b612f83;
    mpk->AU01[0][2].Z.w[2]=0x4810794c73a5dc1f;
    mpk->AU01[0][2].Z.w[3]=0xf73d10045588170;

    mpk->AU01[1][0].X.len=0x4;
    mpk->AU01[1][0].X.w[0]=0xc83d40d2d382cca1;
    mpk->AU01[1][0].X.w[1]=0x9df917e33c3c7550;
    mpk->AU01[1][0].X.w[2]=0x37bb779f0a21d5b1;
    mpk->AU01[1][0].X.w[3]=0x1557149738682737;

    mpk->AU01[1][0].Y.len=0x4;
    mpk->AU01[1][0].Y.w[0]=0x56f1c43d8abe6ddd;
    mpk->AU01[1][0].Y.w[1]=0xc52d3c92fcbac26f;
    mpk->AU01[1][0].Y.w[2]=0xd92e8eae922ef57f;
    mpk->AU01[1][0].Y.w[3]=0x5dc823dba9a3c77;

    mpk->AU01[1][0].Z.len=0x4;
    mpk->AU01[1][0].Z.w[0]=0xed5241068488adda;
    mpk->AU01[1][0].Z.w[1]=0xacb0f74735596fbe;
    mpk->AU01[1][0].Z.w[2]=0xe15f961bb8c31f04;
    mpk->AU01[1][0].Z.w[3]=0x1d8016fb1f7c2f22;

    mpk->AU01[1][1].X.len=0x4;
    mpk->AU01[1][1].X.w[0]=0x19456e41b54722c7;
    mpk->AU01[1][1].X.w[1]=0xa2a7b5cf297e900d;
    mpk->AU01[1][1].X.w[2]=0x7f58c0ff3596d49f;
    mpk->AU01[1][1].X.w[3]=0x91b0af980d227bd;

    mpk->AU01[1][1].Y.len=0x4;
    mpk->AU01[1][1].Y.w[0]=0xce504159cb7ee824;
    mpk->AU01[1][1].Y.w[1]=0x575305450906b8fa;
    mpk->AU01[1][1].Y.w[2]=0xe6095fe56adf0571;
    mpk->AU01[1][1].Y.w[3]=0xff5292f4f2e1def;

    mpk->AU01[1][1].Z.len=0x4;
    mpk->AU01[1][1].Z.w[0]=0xb0a97da3b64e8e6c;
    mpk->AU01[1][1].Z.w[1]=0x9c9ba3df6cb95a57;
    mpk->AU01[1][1].Z.w[2]=0xbf049c6c77d000d5;
    mpk->AU01[1][1].Z.w[3]=0x1a9456d2d14cc90c;

    mpk->AU01[1][2].X.len=0x4;
    mpk->AU01[1][2].X.w[0]=0x1d66f6e3b4823cbb;
    mpk->AU01[1][2].X.w[1]=0x23d69c76da3e5510;
    mpk->AU01[1][2].X.w[2]=0x6ac6c94035a598ba;
    mpk->AU01[1][2].X.w[3]=0x1cba97a6dcd47789;

    mpk->AU01[1][2].Y.len=0x4;
    mpk->AU01[1][2].Y.w[0]=0x612917ca4c6a0afb;
    mpk->AU01[1][2].Y.w[1]=0x472d1b4f1fa1294e;
    mpk->AU01[1][2].Y.w[2]=0xc5d9397010646940;
    mpk->AU01[1][2].Y.w[3]=0x5aabbe76c53f513;

    mpk->AU01[1][2].Z.len=0x4;
    mpk->AU01[1][2].Z.w[0]=0x1bd1b77d74485170;
    mpk->AU01[1][2].Z.w[1]=0x61b3bccd9ff37a5c;
    mpk->AU01[1][2].Z.w[2]=0xc70b1f98d2c919f4;
    mpk->AU01[1][2].Z.w[3]=0x1f2bf50ca22bca2a;

    mpk->AU01[2][0].X.len=0x4;
    mpk->AU01[2][0].X.w[0]=0x4c3ff144f770c088;
    mpk->AU01[2][0].X.w[1]=0x4839df8bc5d155fe;
    mpk->AU01[2][0].X.w[2]=0x57f5c47744a5c468;
    mpk->AU01[2][0].X.w[3]=0x19900970b7fca706;

    mpk->AU01[2][0].Y.len=0x4;
    mpk->AU01[2][0].Y.w[0]=0xa630b61d0f0a2b55;
    mpk->AU01[2][0].Y.w[1]=0x6f7c15360dc65c82;
    mpk->AU01[2][0].Y.w[2]=0xa4f0cd96aa1d447e;
    mpk->AU01[2][0].Y.w[3]=0x20516aa10490239d;

    mpk->AU01[2][0].Z.len=0x4;
    mpk->AU01[2][0].Z.w[0]=0x5868f69f2ab2a6d3;
    mpk->AU01[2][0].Z.w[1]=0xe75389360bcf2382;
    mpk->AU01[2][0].Z.w[2]=0xa7a89f59c04d69b2;
    mpk->AU01[2][0].Z.w[3]=0x1136290960518086;


    mpk->AU01[2][1].X.len=0x4;
    mpk->AU01[2][1].X.w[0]=0xc9d5b6edc465a4c6;
    mpk->AU01[2][1].X.w[1]=0xf7952478da609a9a;
    mpk->AU01[2][1].X.w[2]=0xf4449aed90443e6;
    mpk->AU01[2][1].X.w[3]=0xccac981cd9c3d34;

    mpk->AU01[2][1].Y.len=0x4;
    mpk->AU01[2][1].Y.w[0]=0x97931f3fd40acb31;
    mpk->AU01[2][1].Y.w[1]=0x4783c22d63b39b99;
    mpk->AU01[2][1].Y.w[2]=0x16522e575c33ca41;
    mpk->AU01[2][1].Y.w[3]=0x17860097e303909a;

    mpk->AU01[2][1].Z.len=0x4;
    mpk->AU01[2][1].Z.w[0]=0xa37029e1c3dfddfd;
    mpk->AU01[2][1].Z.w[1]=0xc55133836d38337f;
    mpk->AU01[2][1].Z.w[2]=0x7ba24dd051210780;
    mpk->AU01[2][1].Z.w[3]=0x23d0e5f2f9c64406;

    mpk->AU01[2][2].X.len=0x4;
    mpk->AU01[2][2].X.w[0]=0xcf1372d76a229523;
    mpk->AU01[2][2].X.w[1]=0x92872e36a2996b8a;
    mpk->AU01[2][2].X.w[2]=0xba7980f2151c770b;
    mpk->AU01[2][2].X.w[3]=0x13bf7ef783c1779b;

    mpk->AU01[2][2].Y.len=0x4;
    mpk->AU01[2][2].Y.w[0]=0x7971c98d259fc5b8;
    mpk->AU01[2][2].Y.w[1]=0xa6973c455a2fe525;
    mpk->AU01[2][2].Y.w[2]=0x67c6c3e74e83e37a;
    mpk->AU01[2][2].Y.w[3]=0x2249f0617dc893b6;

    mpk->AU01[2][2].Z.len=0x4;
    mpk->AU01[2][2].Z.w[0]=0x594065876d474091;
    mpk->AU01[2][2].Z.w[1]=0x6048e942dc06192a;
    mpk->AU01[2][2].Z.w[2]=0x8f483a4bb857ae59;
    mpk->AU01[2][2].Z.w[3]=0x20af3322f0c11b0f;
#endif
    //Wi N*2k*k
#if 0
    for(int i=0;i<CP_ABE_PARA_N;i++)
    {
        for(int j=0;j<2*CP_ABE_PARA_K;j++)
        {
            for(int k=0;k<CP_ABE_PARA_K;k++)
            {
                BNT.Trf_Big_to_Char(msk2.msk.W[i][j][k],msk->W[i][j][k]);
#if 1
                BNT.bn_printfBig("msk->W[i][j][k]",msk->W[i][j][k]);

#endif
            }
        }
    }
#else
    //3-6-3
    msk->W[0][0][0].len=0x4;
    msk->W[0][0][0].w[0]=0x49e95f74a79cb2c3;
    msk->W[0][0][0].w[1]=0x34775335f1d05bd7;
    msk->W[0][0][0].w[2]=0xc6ae5bb570b04d7;
    msk->W[0][0][0].w[3]=0x9fc898b4fe653a36;

    msk->W[0][0][1].len=0x4;
    msk->W[0][0][1].w[0]=0x5c9982e8deb5e9a3;
    msk->W[0][0][1].w[1]=0x3f9919edd05e54a0;
    msk->W[0][0][1].w[2]=0xa92990e82492b282;
    msk->W[0][0][1].w[3]=0xc3a14439805bfe5a;

    msk->W[0][0][2].len=0x4;
    msk->W[0][0][2].w[0]=0xb79c03bd3f53b7c1;
    msk->W[0][0][2].w[1]=0xe8eb3cd56d7ddc93;
    msk->W[0][0][2].w[2]=0x2077736117812741;
    msk->W[0][0][2].w[3]=0xa0827147583424fe;

    msk->W[0][1][0].len=0x4;
    msk->W[0][1][0].w[0]=0x1a51acede87d6afd;
    msk->W[0][1][0].w[1]=0x2725a237686b8f84;
    msk->W[0][1][0].w[2]=0xf68af0ec21b2082d;
    msk->W[0][1][0].w[3]=0xc76fff3538461f4f;

    msk->W[0][1][1].len=0x4;
    msk->W[0][1][1].w[0]=0xe4ddc01e26ab2787;
    msk->W[0][1][1].w[1]=0xf8419c06a1ccda78;
    msk->W[0][1][1].w[2]=0xcb1a05fa0fa4342;
    msk->W[0][1][1].w[3]=0x8c51b9ec8ec7f2f0;

    msk->W[0][1][2].len=0x4;
    msk->W[0][1][2].w[0]=0xaf0a94153a80dc9f;
    msk->W[0][1][2].w[1]=0xe2430a6e99f5ae92;
    msk->W[0][1][2].w[2]=0xca585408f694653e;
    msk->W[0][1][2].w[3]=0xb0cf8bc6b737392a;

    msk->W[0][2][0].len=0x4;
    msk->W[0][2][0].w[0]=0x17ceabee101d1cd9;
    msk->W[0][2][0].w[1]=0xceff30df8ca99b1f;
    msk->W[0][2][0].w[2]=0xc7979865525d4d5e;
    msk->W[0][2][0].w[3]=0x877b2d8b24343562;

    msk->W[0][2][1].len=0x4;
    msk->W[0][2][1].w[0]=0x983d02048b6ddb4f;
    msk->W[0][2][1].w[1]=0x10780e1e97ddfd57;
    msk->W[0][2][1].w[2]=0x876c4ffbcaff3a79;
    msk->W[0][2][1].w[3]=0xfd654a4f734a870a;

    msk->W[0][2][2].len=0x4;
    msk->W[0][2][2].w[0]=0xa41deb67163cf5e8;
    msk->W[0][2][2].w[1]=0xac75116ccb2a2fb0;
    msk->W[0][2][2].w[2]=0x38350f85fedb1438;
    msk->W[0][2][2].w[3]=0xdd9f07098d16bbc5;

    msk->W[0][3][0].len=0x4;
    msk->W[0][3][0].w[0]=0x59dbe15983403bcb;
    msk->W[0][3][0].w[1]=0x73169ea1e105c8d9;
    msk->W[0][3][0].w[2]=0x52a70ff6b685eb7d;
    msk->W[0][3][0].w[3]=0x800f5168774f3322;

    msk->W[0][3][1].len=0x4;
    msk->W[0][3][1].w[0]=0x5632b70ec217814c;
    msk->W[0][3][1].w[1]=0x72b4f8a07a3af7ed;
    msk->W[0][3][1].w[2]=0x87c529572e78b105;
    msk->W[0][3][1].w[3]=0xcef8b33acac8d2f0;

    msk->W[0][3][2].len=0x4;
    msk->W[0][3][2].w[0]=0x8c99dd2a713715e9;
    msk->W[0][3][2].w[1]=0xe6edc578dee383eb;
    msk->W[0][3][2].w[2]=0xc61777b101f94970;
    msk->W[0][3][2].w[3]=0xce880948080bbeb3;

    msk->W[0][4][0].len=0x4;
    msk->W[0][4][0].w[0]=0x9e48ab53eaaf680d;
    msk->W[0][4][0].w[1]=0x467f9527871e91e2;
    msk->W[0][4][0].w[2]=0xe667de9f85db5a1c;
    msk->W[0][4][0].w[3]=0x9fc9604ec8f2824f;

    msk->W[0][4][1].len=0x4;
    msk->W[0][4][1].w[0]=0xf86c970081657588;
    msk->W[0][4][1].w[1]=0x2901288a153864ff;
    msk->W[0][4][1].w[2]=0x82acf256687294d;
    msk->W[0][4][1].w[3]=0xa985beaca6260c4c;

    msk->W[0][4][2].len=0x4;
    msk->W[0][4][2].w[0]=0x886c3e1832caa3ce;
    msk->W[0][4][2].w[1]=0x31f2b033536724d5;
    msk->W[0][4][2].w[2]=0x5b8267ee1bd98f34;
    msk->W[0][4][2].w[3]=0x8ab87d372a88fcf1;

    msk->W[0][5][0].len=0x4;
    msk->W[0][5][0].w[0]=0xc31de00c204ab22f;
    msk->W[0][5][0].w[1]=0xbe3d0cdccd7ab791;
    msk->W[0][5][0].w[2]=0x2c144456e71806a4;
    msk->W[0][5][0].w[3]=0x9dd0559e081d9eb9;

    msk->W[0][5][1].len=0x4;
    msk->W[0][5][1].w[0]=0xc099f7f366e5a2af;
    msk->W[0][5][1].w[1]=0xf1e7e1fde24631cb;
    msk->W[0][5][1].w[2]=0x83908ac5d3ec4307;
    msk->W[0][5][1].w[3]=0xbcf9eaf3c091824c;

    msk->W[0][5][2].len=0x4;
    msk->W[0][5][2].w[0]=0x3ad0630b647b383e;
    msk->W[0][5][2].w[1]=0x218d57f0918f1d5c;
    msk->W[0][5][2].w[2]=0x10861af1e737c379;
    msk->W[0][5][2].w[3]=0xed3f2d6dc9b0b1d9;

    msk->W[1][0][0].len=0x4;
    msk->W[1][0][0].w[0]=0x52e3839bbfa3e825;
    msk->W[1][0][0].w[1]=0xe432d958326a44ca;
    msk->W[1][0][0].w[2]=0x80d4a8d793858ff5;
    msk->W[1][0][0].w[3]=0xbfe164ef1eaa1da7;

    msk->W[1][0][1].len=0x4;
    msk->W[1][0][1].w[0]=0x63a03dc44c1e0f60;
    msk->W[1][0][1].w[1]=0xa561b4767b852b38;
    msk->W[1][0][1].w[2]=0x7048b837d322da7f;
    msk->W[1][0][1].w[3]=0xcd335dd6a5fafdb3;

    msk->W[1][0][2].len=0x4;
    msk->W[1][0][2].w[0]=0xfa4a4fe1a453e91c;
    msk->W[1][0][2].w[1]=0x54b90d38debd2ae5;
    msk->W[1][0][2].w[2]=0x8c4e154b5191f774;
    msk->W[1][0][2].w[3]=0xed3467b817fbc9fe;

    msk->W[1][1][0].len=0x4;
    msk->W[1][1][0].w[0]=0xa7b311c70e315bbb;
    msk->W[1][1][0].w[1]=0xec91bff915066f5f;
    msk->W[1][1][0].w[2]=0x1238aaa03906fb12;
    msk->W[1][1][0].w[3]=0xc49203a08ea4a11c;

    msk->W[1][1][1].len=0x4;
    msk->W[1][1][1].w[0]=0x2f932dc73a83e76a;
    msk->W[1][1][1].w[1]=0xb3842dfc3462eb00;
    msk->W[1][1][1].w[2]=0x3121378378c4243a;
    msk->W[1][1][1].w[3]=0xc5a0a35103e73db9;

    msk->W[1][1][2].len=0x4;
    msk->W[1][1][2].w[0]=0x482462e6867a9a65;
    msk->W[1][1][2].w[1]=0x59b21223b5cdf96c;
    msk->W[1][1][2].w[2]=0x1b9d32e86d78c607;
    msk->W[1][1][2].w[3]=0xa0330af9029101a1;

    msk->W[1][2][0].len=0x4;
    msk->W[1][2][0].w[0]=0xbc07744ce5156511;
    msk->W[1][2][0].w[1]=0xf8a418d4ef6327db;
    msk->W[1][2][0].w[2]=0x8e53a46b41d4f17c;
    msk->W[1][2][0].w[3]=0x8cafd93922efdbc7;

    msk->W[1][2][1].len=0x4;
    msk->W[1][2][1].w[0]=0xf1ae9319983517d9;
    msk->W[1][2][1].w[1]=0x4d6fa34b97fc1ca;
    msk->W[1][2][1].w[2]=0x217e3c17e5f10c2e;
    msk->W[1][2][1].w[3]=0x863acba4e1194b7e;

    msk->W[1][2][2].len=0x4;
    msk->W[1][2][2].w[0]=0xd16fca1e66eb445b;
    msk->W[1][2][2].w[1]=0xf2c4475bb8203692;
    msk->W[1][2][2].w[2]=0x13d95225134e0f22;
    msk->W[1][2][2].w[3]=0xb07fb5ee68e88d76;

    msk->W[1][3][0].len=0x4;
    msk->W[1][3][0].w[0]=0x52c5a712781fa68e;
    msk->W[1][3][0].w[1]=0xdf2046bfae7fee56;
    msk->W[1][3][0].w[2]=0xdab8e01a422a1369;
    msk->W[1][3][0].w[3]=0xc671a3797ba43a4b;

    msk->W[1][3][1].len=0x4;
    msk->W[1][3][1].w[0]=0x476a515e4eb0861a;
    msk->W[1][3][1].w[1]=0x5cc2c6b8ff95ad2;
    msk->W[1][3][1].w[2]=0xfb827db5802f394e;
    msk->W[1][3][1].w[3]=0xdc996831ab13e627;

    msk->W[1][3][2].len=0x4;
    msk->W[1][3][2].w[0]=0xd05b060daae1d267;
    msk->W[1][3][2].w[1]=0xca3dabdb44ecd046;
    msk->W[1][3][2].w[2]=0x23020b1145cd4947;
    msk->W[1][3][2].w[3]=0xe684c4f3cf738eaf;

    msk->W[1][4][0].len=0x4;
    msk->W[1][4][0].w[0]=0xfa509bdb28623c5a;
    msk->W[1][4][0].w[1]=0xc133250212b7a075;
    msk->W[1][4][0].w[2]=0x4979a69936528720;
    msk->W[1][4][0].w[3]=0x81d0f2e8e2d95b10;

    msk->W[1][4][1].len=0x4;
    msk->W[1][4][1].w[0]=0x57620d86ed256397;
    msk->W[1][4][1].w[1]=0x54ef60ee73fef96a;
    msk->W[1][4][1].w[2]=0x50cd7b22bb915a33;
    msk->W[1][4][1].w[3]=0xe18c145639a5ad25;

    msk->W[1][4][2].len=0x4;
    msk->W[1][4][2].w[0]=0x6ac396415642ccc1;
    msk->W[1][4][2].w[1]=0xff57c0ea2d61d332;
    msk->W[1][4][2].w[2]=0x27814c420006a51b;
    msk->W[1][4][2].w[3]=0xa8b1b31fc594d19d;

    msk->W[1][5][0].len=0x4;
    msk->W[1][5][0].w[0]=0x7b58f82c203586c0;
    msk->W[1][5][0].w[1]=0xb66e1176eb56ef5d;
    msk->W[1][5][0].w[2]=0xb4c10b25014b64e9;
    msk->W[1][5][0].w[3]=0xb896608ff4e2e14e;

    msk->W[1][5][1].len=0x4;
    msk->W[1][5][1].w[0]=0x338d372036b2564c;
    msk->W[1][5][1].w[1]=0xf912a7ad79ff333a;
    msk->W[1][5][1].w[2]=0x20b4eaa26265dbc;
    msk->W[1][5][1].w[3]=0xeb9592c57e4292db;

    msk->W[1][5][2].len=0x4;
    msk->W[1][5][2].w[0]=0x34144ff3052eaf6b;
    msk->W[1][5][2].w[1]=0x590d24f3c3388652;
    msk->W[1][5][2].w[2]=0xab1bd9413329fadc;
    msk->W[1][5][2].w[3]=0x8093591c5e7e3e64;

    msk->W[2][0][0].len=0x4;
    msk->W[2][0][0].w[0]=0xcd61950c5f3e54d0;
    msk->W[2][0][0].w[1]=0xdc2d3a046df86582;
    msk->W[2][0][0].w[2]=0xd217522461567dab;
    msk->W[2][0][0].w[3]=0xfea63b0ee1d5c7e9;

    msk->W[2][0][1].len=0x4;
    msk->W[2][0][1].w[0]=0x36b9eea83c8e5169;
    msk->W[2][0][1].w[1]=0x7fab4a4b6b034951;
    msk->W[2][0][1].w[2]=0xbf0f743d6b92e8e3;
    msk->W[2][0][1].w[3]=0xee37356f75910136;

    msk->W[2][0][2].len=0x4;
    msk->W[2][0][2].w[0]=0x8b008b6b4d861ede;
    msk->W[2][0][2].w[1]=0x81e18e4eef83be50;
    msk->W[2][0][2].w[2]=0xa876582d2b41e296;
    msk->W[2][0][2].w[3]=0xf478a6d433fe092a;

    msk->W[2][1][0].len=0x4;
    msk->W[2][1][0].w[0]=0x2bc46a0bd02c2c19;
    msk->W[2][1][0].w[1]=0xff37b9ccc871a464;
    msk->W[2][1][0].w[2]=0x8cbf9ddcd4c440a1;
    msk->W[2][1][0].w[3]=0xc1b4dfa5f60696a0;

    msk->W[2][1][1].len=0x4;
    msk->W[2][1][1].w[0]=0x957e1c1d35ed079e;
    msk->W[2][1][1].w[1]=0x614ba4c8dc0736d3;
    msk->W[2][1][1].w[2]=0xfc777737e20fe453;
    msk->W[2][1][1].w[3]=0xe1fbfa23a0c47c8c;

    msk->W[2][1][2].len=0x4;
    msk->W[2][1][2].w[0]=0x3bc021f47c6dc465;
    msk->W[2][1][2].w[1]=0x15362a43886e8321;
    msk->W[2][1][2].w[2]=0xecd27394f3efd16e;
    msk->W[2][1][2].w[3]=0xcbd156648dfe36fb;

    msk->W[2][2][0].len=0x4;
    msk->W[2][2][0].w[0]=0xbed71221c91de54c;
    msk->W[2][2][0].w[1]=0xae32a55f9f77857c;
    msk->W[2][2][0].w[2]=0x385cab40390498c;
    msk->W[2][2][0].w[3]=0x8867d5446b861477;

    msk->W[2][2][1].len=0x4;
    msk->W[2][2][1].w[0]=0xff8dfcb28bab198a;
    msk->W[2][2][1].w[1]=0x1312141f02971f6;
    msk->W[2][2][1].w[2]=0xde8b9e76a54ea53d;
    msk->W[2][2][1].w[3]=0xf2f06703b6e56bf5;

    msk->W[2][2][2].len=0x4;
    msk->W[2][2][2].w[0]=0x6a2b2ef2bb0f038a;
    msk->W[2][2][2].w[1]=0x84a97c72306f206f;
    msk->W[2][2][2].w[2]=0xc51000d013f21caf;
    msk->W[2][2][2].w[3]=0xcbcce89eae6a6843;

    msk->W[2][3][0].len=0x4;
    msk->W[2][3][0].w[0]=0x81b00f598d0d7b2a;
    msk->W[2][3][0].w[1]=0x52f2d8fa2eaf179b;
    msk->W[2][3][0].w[2]=0x61e16f2c02606afd;
    msk->W[2][3][0].w[3]=0xebf0fdcf7c0f059c;

    msk->W[2][3][1].len=0x4;
    msk->W[2][3][1].w[0]=0xc97851e19f6bc4fe;
    msk->W[2][3][1].w[1]=0xacdf7c525015ecf2;
    msk->W[2][3][1].w[2]=0x889113d4a55c1361;
    msk->W[2][3][1].w[3]=0xe6cb82ae740165eb;

    msk->W[2][3][2].len=0x4;
    msk->W[2][3][2].w[0]=0x2a2a0a4757083f68;
    msk->W[2][3][2].w[1]=0xb5cc9e6c739a1e9a;
    msk->W[2][3][2].w[2]=0xd7ef615f6e93874f;
    msk->W[2][3][2].w[3]=0xce65dd99fb8398a9;

    msk->W[2][4][0].len=0x4;
    msk->W[2][4][0].w[0]=0x121ff6bfcadb13e5;
    msk->W[2][4][0].w[1]=0x18585fa1f0314e0b;
    msk->W[2][4][0].w[2]=0xb62b594e1492881c;
    msk->W[2][4][0].w[3]=0xc6693add13f9d76e;

    msk->W[2][4][1].len=0x4;
    msk->W[2][4][1].w[0]=0x1b00412b7fa23a21;
    msk->W[2][4][1].w[1]=0xa60b5f2bad5764b6;
    msk->W[2][4][1].w[2]=0x19715a885b77cb49;
    msk->W[2][4][1].w[3]=0xc60743c35f2319e6;

    msk->W[2][4][2].len=0x4;
    msk->W[2][4][2].w[0]=0x78a21cf7deeeb70c;
    msk->W[2][4][2].w[1]=0x9353b8f51c5f94cd;
    msk->W[2][4][2].w[2]=0x68e77491c579a371;
    msk->W[2][4][2].w[3]=0xcafbf3ad5031fd04;

    msk->W[2][5][0].len=0x4;
    msk->W[2][5][0].w[0]=0x80e7a1ce3c515840;
    msk->W[2][5][0].w[1]=0xdbd9652fd70540dd;
    msk->W[2][5][0].w[2]=0xd1fdb599bbdea232;
    msk->W[2][5][0].w[3]=0xa59e658a981d316f;

    msk->W[2][5][1].len=0x4;
    msk->W[2][5][1].w[0]=0x1da2b50a9e0b22c8;
    msk->W[2][5][1].w[1]=0xf4d29bd34aeea8b6;
    msk->W[2][5][1].w[2]=0x6f444a35757b58ea;
    msk->W[2][5][1].w[3]=0xa3de75aec107fedd;

    msk->W[2][5][2].len=0x4;
    msk->W[2][5][2].w[0]=0xda10379b310fa7ec;
    msk->W[2][5][2].w[1]=0x1eac0637ab350b05;
    msk->W[2][5][2].w[2]=0x9db2ce8ee7167d76;
    msk->W[2][5][2].w[3]=0xc03e71092435c459;

#endif
    //[AWi]1,N*k*k
#if 0
    for(int t=0;t<CP_ABE_PARA_N;t++)
    {
        for(int i=0;i<CP_ABE_PARA_K;i++)
        {
            for(int j=0;j<CP_ABE_PARA_K;j++)
            {
                BNT.Trf_G1_to_Char(mpk2.mpk.AW1[t][i][j],mpk->AW1[t][i][j]);
#if 1
                BNT.bn_printfG1("mpk->AW1[t][i][j]",mpk->AW1[t][i][j]);

#endif
            }
        }
    }
#else
    //3-3-3
    mpk->AW1[0][0][0].X.len=0x4;
    mpk->AW1[0][0][0].X.w[0]=0xb18dc7bbc51b2504;
    mpk->AW1[0][0][0].X.w[1]=0xf93c2dd0c232e520;
    mpk->AW1[0][0][0].X.w[2]=0xec71fadfb235b34c;
    mpk->AW1[0][0][0].X.w[3]=0x145b6d6f989a3517;

    mpk->AW1[0][0][0].Y.len=0x4;
    mpk->AW1[0][0][0].Y.w[0]=0x8555968da67f6e75;
    mpk->AW1[0][0][0].Y.w[1]=0x1bda5daa1b0bd303;
    mpk->AW1[0][0][0].Y.w[2]=0xdeb893cacaf26db;
    mpk->AW1[0][0][0].Y.w[3]=0x141bd2facd39f62b;

    mpk->AW1[0][0][0].Z.len=0x4;
    mpk->AW1[0][0][0].Z.w[0]=0x146270c3cc50c5cd;
    mpk->AW1[0][0][0].Z.w[1]=0xe75c7bf79d536fe1;
    mpk->AW1[0][0][0].Z.w[2]=0xba421fdc4e4146ea;
    mpk->AW1[0][0][0].Z.w[3]=0xfa0e665b01f3a84;


    mpk->AW1[0][0][1].X.len=0x4;
    mpk->AW1[0][0][1].X.w[0]=0x2f2e730b636ff794;
    mpk->AW1[0][0][1].X.w[1]=0x919645cfe277308;
    mpk->AW1[0][0][1].X.w[2]=0x4c7dbbcbe7b541f2;
    mpk->AW1[0][0][1].X.w[3]=0x2423d3959cad7d0;

    mpk->AW1[0][0][1].Y.len=0x4;
    mpk->AW1[0][0][1].Y.w[0]=0x94fc5d299862f734;
    mpk->AW1[0][0][1].Y.w[1]=0x4cc1a163b4de6a8b;
    mpk->AW1[0][0][1].Y.w[2]=0x4ec4e389b6a38a1c;
    mpk->AW1[0][0][1].Y.w[3]=0x77beeaba08f2ecc;

    mpk->AW1[0][0][1].Z.len=0x4;
    mpk->AW1[0][0][1].Z.w[0]=0x635ff396c3b07aad;
    mpk->AW1[0][0][1].Z.w[1]=0x81bded56cc6815d3;
    mpk->AW1[0][0][1].Z.w[2]=0x27a45d25a34ef8b8;
    mpk->AW1[0][0][1].Z.w[3]=0xaadec08e51c66f6;


    mpk->AW1[0][0][2].X.len=0x4;
    mpk->AW1[0][0][2].X.w[0]=0x2d1802fc8edb535d;
    mpk->AW1[0][0][2].X.w[1]=0xc6d33657428dfc5e;
    mpk->AW1[0][0][2].X.w[2]=0xd50b83ae75126719;
    mpk->AW1[0][0][2].X.w[3]=0x18744ea5674c3d99;

    mpk->AW1[0][0][2].Y.len=0x4;
    mpk->AW1[0][0][2].Y.w[0]=0x6a05080cba3a7bc6;
    mpk->AW1[0][0][2].Y.w[1]=0x618e57c6129a74f1;
    mpk->AW1[0][0][2].Y.w[2]=0xbd915124acf1798e;
    mpk->AW1[0][0][2].Y.w[3]=0x1b0b1d4a23a37c9e;

    mpk->AW1[0][0][2].Z.len=0x4;
    mpk->AW1[0][0][2].Z.w[0]=0x9a6e0fba9cfedd17;
    mpk->AW1[0][0][2].Z.w[1]=0x64602e33388863ee;
    mpk->AW1[0][0][2].Z.w[2]=0x86714af65dcaa224;
    mpk->AW1[0][0][2].Z.w[3]=0xddc0b87bdd93abc;

    mpk->AW1[0][1][0].X.len=0x4;
    mpk->AW1[0][1][0].X.w[0]=0x3d570efb7d0e315d;
    mpk->AW1[0][1][0].X.w[1]=0x514ebcf5d686bd8b;
    mpk->AW1[0][1][0].X.w[2]=0x9d22f9ac436053a3;
    mpk->AW1[0][1][0].X.w[3]=0x200169b6c89a6b8a;

    mpk->AW1[0][1][0].Y.len=0x4;
    mpk->AW1[0][1][0].Y.w[0]=0x9fdaeedcd8c4c262;
    mpk->AW1[0][1][0].Y.w[1]=0xba85a1214f3c1c37;
    mpk->AW1[0][1][0].Y.w[2]=0x5da4b9e8c566f8e;
    mpk->AW1[0][1][0].Y.w[3]=0xf0a4e622ffe5a90;

    mpk->AW1[0][1][0].Z.len=0x4;
    mpk->AW1[0][1][0].Z.w[0]=0x5c21508a25e63b46;
    mpk->AW1[0][1][0].Z.w[1]=0x53f39e90116280e7;
    mpk->AW1[0][1][0].Z.w[2]=0x83b279bd3d525e5c;
    mpk->AW1[0][1][0].Z.w[3]=0x240ce2ae881de1af;

    mpk->AW1[0][1][1].X.len=0x4;
    mpk->AW1[0][1][1].X.w[0]=0xd27e0e49c56a58d2;
    mpk->AW1[0][1][1].X.w[1]=0x37f5efcbec9ed62f;
    mpk->AW1[0][1][1].X.w[2]=0x62e4d35acd7900f9;
    mpk->AW1[0][1][1].X.w[3]=0x49a25ab3135140c;

    mpk->AW1[0][1][1].Y.len=0x4;
    mpk->AW1[0][1][1].Y.w[0]=0xb3d94c5068b0255a;
    mpk->AW1[0][1][1].Y.w[1]=0x4272a7a58030de5;
    mpk->AW1[0][1][1].Y.w[2]=0xc248f67e3fa58ed0;
    mpk->AW1[0][1][1].Y.w[3]=0x14d60532a154027d;

    mpk->AW1[0][1][1].Z.len=0x4;
    mpk->AW1[0][1][1].Z.w[0]=0xa1f4a97ec425f519;
    mpk->AW1[0][1][1].Z.w[1]=0x61730380db844603;
    mpk->AW1[0][1][1].Z.w[2]=0x238b015f38a6c1af;
    mpk->AW1[0][1][1].Z.w[3]=0x222e5fe91de5d3e6;

    mpk->AW1[0][1][2].X.len=0x4;
    mpk->AW1[0][1][2].X.w[0]=0xc5bdef2086e2c1ee;
    mpk->AW1[0][1][2].X.w[1]=0x13a311e9ad5036de;
    mpk->AW1[0][1][2].X.w[2]=0x526ee50249d2c65a;
    mpk->AW1[0][1][2].X.w[3]=0x21d629b71170171d;

    mpk->AW1[0][1][2].Y.len=0x4;
    mpk->AW1[0][1][2].Y.w[0]=0xc2d19f1f351d85e7;
    mpk->AW1[0][1][2].Y.w[1]=0x504e186bd37e8e82;
    mpk->AW1[0][1][2].Y.w[2]=0x713916efda1e016d;
    mpk->AW1[0][1][2].Y.w[3]=0x231c4d5cbfa4c07a;

    mpk->AW1[0][1][2].Z.len=0x4;
    mpk->AW1[0][1][2].Z.w[0]=0x374016cc6e95251d;
    mpk->AW1[0][1][2].Z.w[1]=0x6883de7e7b5d3a3d;
    mpk->AW1[0][1][2].Z.w[2]=0xf39d67b2535a9508;
    mpk->AW1[0][1][2].Z.w[3]=0x19789b6a934fdf5c;

    mpk->AW1[0][2][0].X.len=0x4;
    mpk->AW1[0][2][0].X.w[0]=0xf1d750fdf537b811;
    mpk->AW1[0][2][0].X.w[1]=0xe8e512f14f43713e;
    mpk->AW1[0][2][0].X.w[2]=0x4581206e981bccdc;
    mpk->AW1[0][2][0].X.w[3]=0x27b29681b3168a7;

    mpk->AW1[0][2][0].Y.len=0x4;
    mpk->AW1[0][2][0].Y.w[0]=0x1374e2db607107be;
    mpk->AW1[0][2][0].Y.w[1]=0xb95244f587c73c01;
    mpk->AW1[0][2][0].Y.w[2]=0x6c49ed89f83916b2;
    mpk->AW1[0][2][0].Y.w[3]=0x192ffba7f6758f3e;

    mpk->AW1[0][2][0].Z.len=0x4;
    mpk->AW1[0][2][0].Z.w[0]=0x4e9615274fb1de79;
    mpk->AW1[0][2][0].Z.w[1]=0x16ecd77d4f33cd39;
    mpk->AW1[0][2][0].Z.w[2]=0x3bb0871cc7db4c2d;
    mpk->AW1[0][2][0].Z.w[3]=0x1735fae129a99cd2;

    mpk->AW1[0][2][1].X.len=0x4;
    mpk->AW1[0][2][1].X.w[0]=0x888e37a486648335;
    mpk->AW1[0][2][1].X.w[1]=0xd15010fd58fe9471;
    mpk->AW1[0][2][1].X.w[2]=0x57dc82a19f1c2053;
    mpk->AW1[0][2][1].X.w[3]=0x1c73d1a6e57a5a97;

    mpk->AW1[0][2][1].Y.len=0x4;
    mpk->AW1[0][2][1].Y.w[0]=0x3d7804eda790b71e;
    mpk->AW1[0][2][1].Y.w[1]=0xc4075b9c50e4c48e;
    mpk->AW1[0][2][1].Y.w[2]=0xd28b8dba579a3443;
    mpk->AW1[0][2][1].Y.w[3]=0x2190d8d5d4384e2;

    mpk->AW1[0][2][1].Z.len=0x4;
    mpk->AW1[0][2][1].Z.w[0]=0x6116bb1ca9c9f346;
    mpk->AW1[0][2][1].Z.w[1]=0xfcd841dbd30c88bf;
    mpk->AW1[0][2][1].Z.w[2]=0x91536728e67044cf;
    mpk->AW1[0][2][1].Z.w[3]=0x194966a44faa8885;

    mpk->AW1[0][2][2].X.len=0x4;
    mpk->AW1[0][2][2].X.w[0]=0xae9b2813309b057b;
    mpk->AW1[0][2][2].X.w[1]=0x14b01b3defb08ca2;
    mpk->AW1[0][2][2].X.w[2]=0x19599463a70aa526;
    mpk->AW1[0][2][2].X.w[3]=0x14d45610c8d7f8b3;

    mpk->AW1[0][2][2].Y.len=0x4;
    mpk->AW1[0][2][2].Y.w[0]=0x1ea72f0e562e2b9c;
    mpk->AW1[0][2][2].Y.w[1]=0x7cbcee85b43f9cf0;
    mpk->AW1[0][2][2].Y.w[2]=0x41aa5c852cc0d3b3;
    mpk->AW1[0][2][2].Y.w[3]=0x1acd4d93a3419f54;

    mpk->AW1[0][2][2].Z.len=0x4;
    mpk->AW1[0][2][2].Z.w[0]=0xefd86f3425d29a53;
    mpk->AW1[0][2][2].Z.w[1]=0x546e5e5771d0ac67;
    mpk->AW1[0][2][2].Z.w[2]=0x77acff4a9b573d1;
    mpk->AW1[0][2][2].Z.w[3]=0x10637ee3ef1641aa;

    mpk->AW1[1][0][0].X.len=0x4;
    mpk->AW1[1][0][0].X.w[0]=0xb0bfc03848cb6e30;
    mpk->AW1[1][0][0].X.w[1]=0xe71c00f93425bfb6;
    mpk->AW1[1][0][0].X.w[2]=0x8a4f61e67e921043;
    mpk->AW1[1][0][0].X.w[3]=0x7a4acd03ad9a1a1;

    mpk->AW1[1][0][0].Y.len=0x4;
    mpk->AW1[1][0][0].Y.w[0]=0xaaa91dda22d102ce;
    mpk->AW1[1][0][0].Y.w[1]=0x181bac71869a6b73;
    mpk->AW1[1][0][0].Y.w[2]=0xabb87966e2fc9349;
    mpk->AW1[1][0][0].Y.w[3]=0x1e97b11aa77d4ae8;

    mpk->AW1[1][0][0].Z.len=0x4;
    mpk->AW1[1][0][0].Z.w[0]=0x9b21ecf7a9e3e69e;
    mpk->AW1[1][0][0].Z.w[1]=0x1dd54eef85020cfb;
    mpk->AW1[1][0][0].Z.w[2]=0xe3f7fe07a60de612;
    mpk->AW1[1][0][0].Z.w[3]=0x225c5b3ba67dec08;

    mpk->AW1[1][0][1].X.len=0x4;
    mpk->AW1[1][0][1].X.w[0]=0x375f736d0973f470;
    mpk->AW1[1][0][1].X.w[1]=0xfd864d395d7010dc;
    mpk->AW1[1][0][1].X.w[2]=0x92e92e7d3243f1c1;
    mpk->AW1[1][0][1].X.w[3]=0x2ac16622be0bc10;

    mpk->AW1[1][0][1].Y.len=0x4;
    mpk->AW1[1][0][1].Y.w[0]=0x912c085055d36bd3;
    mpk->AW1[1][0][1].Y.w[1]=0x53f9b29d406009c0;
    mpk->AW1[1][0][1].Y.w[2]=0x5aa5869b2f6f0b69;
    mpk->AW1[1][0][1].Y.w[3]=0xfa77f60c78af836;

    mpk->AW1[1][0][1].Z.len=0x4;
    mpk->AW1[1][0][1].Z.w[0]=0x449ea68c5924cffd;
    mpk->AW1[1][0][1].Z.w[1]=0x6d1b96c3e18dc00c;
    mpk->AW1[1][0][1].Z.w[2]=0x541120a5ae7777c4;
    mpk->AW1[1][0][1].Z.w[3]=0x1c00e0ca6beb6052;

    mpk->AW1[1][0][2].X.len=0x4;
    mpk->AW1[1][0][2].X.w[0]=0x38701f6d767ffba8;
    mpk->AW1[1][0][2].X.w[1]=0x8e64b8e4fd9e6a4a;
    mpk->AW1[1][0][2].X.w[2]=0x8e86a51b1f52f7b5;
    mpk->AW1[1][0][2].X.w[3]=0x10e64da51f81f947;

    mpk->AW1[1][0][2].Y.len=0x4;
    mpk->AW1[1][0][2].Y.w[0]=0x155522ae3533548;
    mpk->AW1[1][0][2].Y.w[1]=0xafb52bc13bdb435f;
    mpk->AW1[1][0][2].Y.w[2]=0xf363d1b10a5facaf;
    mpk->AW1[1][0][2].Y.w[3]=0xd1f1e0ae2b10377;

    mpk->AW1[1][0][2].Z.len=0x4;
    mpk->AW1[1][0][2].Z.w[0]=0xb726cbb7cfe8f589;
    mpk->AW1[1][0][2].Z.w[1]=0xf00388b45fbcd2c4;
    mpk->AW1[1][0][2].Z.w[2]=0x5d7eac9708ab65b0;
    mpk->AW1[1][0][2].Z.w[3]=0x12ba78a417555605;

    mpk->AW1[1][1][0].X.len=0x4;
    mpk->AW1[1][1][0].X.w[0]=0x90d8982b5c151a53;
    mpk->AW1[1][1][0].X.w[1]=0xd59bc7918f46aec8;
    mpk->AW1[1][1][0].X.w[2]=0x4249d7edc1094509;
    mpk->AW1[1][1][0].X.w[3]=0x1e73f9157949b28f;

    mpk->AW1[1][1][0].Y.len=0x4;
    mpk->AW1[1][1][0].Y.w[0]=0x4abf4ca08e46063b;
    mpk->AW1[1][1][0].Y.w[1]=0xaf644f2decc927fa;
    mpk->AW1[1][1][0].Y.w[2]=0x706389c71b3c572a;
    mpk->AW1[1][1][0].Y.w[3]=0x142827564444ce0f;

    mpk->AW1[1][1][0].Z.len=0x4;
    mpk->AW1[1][1][0].Z.w[0]=0x62faa84bfe4b2e02;
    mpk->AW1[1][1][0].Z.w[1]=0xe35b78e389835543;
    mpk->AW1[1][1][0].Z.w[2]=0xa46e73e50cb0165f;
    mpk->AW1[1][1][0].Z.w[3]=0x1cc1abebf5504119;

    mpk->AW1[1][1][1].X.len=0x4;
    mpk->AW1[1][1][1].X.w[0]=0xc7af13757789a5ba;
    mpk->AW1[1][1][1].X.w[1]=0x74f5d56f35a79224;
    mpk->AW1[1][1][1].X.w[2]=0x6782b746cfa4712;
    mpk->AW1[1][1][1].X.w[3]=0x5d4174be30e9f86;

    mpk->AW1[1][1][1].Y.len=0x4;
    mpk->AW1[1][1][1].Y.w[0]=0x9ffbb691057329ef;
    mpk->AW1[1][1][1].Y.w[1]=0x1866dbeb04b5157;
    mpk->AW1[1][1][1].Y.w[2]=0x6495f5bd496ba350;
    mpk->AW1[1][1][1].Y.w[3]=0x13a2ac0d75c430a3;

    mpk->AW1[1][1][1].Z.len=0x4;
    mpk->AW1[1][1][1].Z.w[0]=0x96f5a25c387e3e09;
    mpk->AW1[1][1][1].Z.w[1]=0xf9b607d45f5b07a1;
    mpk->AW1[1][1][1].Z.w[2]=0xd2eed272c16b63c6;
    mpk->AW1[1][1][1].Z.w[3]=0x9689587f78aafec;

    mpk->AW1[1][1][2].X.len=0x4;
    mpk->AW1[1][1][2].X.w[0]=0x660c2eb59e4fb4dc;
    mpk->AW1[1][1][2].X.w[1]=0x7061da130ed5e5ec;
    mpk->AW1[1][1][2].X.w[2]=0xb1893b057cd908e3;
    mpk->AW1[1][1][2].X.w[3]=0xd67f1f18482e4b5;

    mpk->AW1[1][1][2].Y.len=0x4;
    mpk->AW1[1][1][2].Y.w[0]=0xbd6dda29a12cbeb;
    mpk->AW1[1][1][2].Y.w[1]=0x63363a1a1c9391eb;
    mpk->AW1[1][1][2].Y.w[2]=0xc93200bba7e862f6;
    mpk->AW1[1][1][2].Y.w[3]=0x9c0a2ca70f42f3d;

    mpk->AW1[1][1][2].Z.len=0x4;
    mpk->AW1[1][1][2].Z.w[0]=0xa941e5bcaa800fc7;
    mpk->AW1[1][1][2].Z.w[1]=0x7beb3dbc450c1d8c;
    mpk->AW1[1][1][2].Z.w[2]=0x6406995f8ff6517f;
    mpk->AW1[1][1][2].Z.w[3]=0x4c58f1983b90f64;

    mpk->AW1[1][2][0].X.len=0x4;
    mpk->AW1[1][2][0].X.w[0]=0xe851c5e1339b02e0;
    mpk->AW1[1][2][0].X.w[1]=0xff134c3478f75170;
    mpk->AW1[1][2][0].X.w[2]=0xe410e27224f09bbb;
    mpk->AW1[1][2][0].X.w[3]=0x1df88649117b49de;

    mpk->AW1[1][2][0].Y.len=0x4;
    mpk->AW1[1][2][0].Y.w[0]=0x814bc5ee02b46198;
    mpk->AW1[1][2][0].Y.w[1]=0x7b69118dc5826449;
    mpk->AW1[1][2][0].Y.w[2]=0xa29cc3369c575ec8;
    mpk->AW1[1][2][0].Y.w[3]=0x146f8e6bff7e3b5e;

    mpk->AW1[1][2][0].Z.len=0x4;
    mpk->AW1[1][2][0].Z.w[0]=0xa1e1d23ded94483f;
    mpk->AW1[1][2][0].Z.w[1]=0x84d26d23abe7ce5e;
    mpk->AW1[1][2][0].Z.w[2]=0x9fa5cfd8ba601953;
    mpk->AW1[1][2][0].Z.w[3]=0x23e1bc0591a2797;

    mpk->AW1[1][2][1].X.len=0x4;
    mpk->AW1[1][2][1].X.w[0]=0x76a2b680b185e574;
    mpk->AW1[1][2][1].X.w[1]=0x69e1a7c07744d16f;
    mpk->AW1[1][2][1].X.w[2]=0x7ece2511d43581b;
    mpk->AW1[1][2][1].X.w[3]=0x16fb00bd84dca681;

    mpk->AW1[1][2][1].Y.len=0x4;
    mpk->AW1[1][2][1].Y.w[0]=0xb52398406736aa1;
    mpk->AW1[1][2][1].Y.w[1]=0x6012a41b12c03f2b;
    mpk->AW1[1][2][1].Y.w[2]=0x897de6678510cf57;
    mpk->AW1[1][2][1].Y.w[3]=0x1e2d5d6103d2c578;

    mpk->AW1[1][2][1].Z.len=0x4;
    mpk->AW1[1][2][1].Z.w[0]=0x4a716782f4f7b04c;
    mpk->AW1[1][2][1].Z.w[1]=0x520ff470f3195401;
    mpk->AW1[1][2][1].Z.w[2]=0xdc2818d976444b63;
    mpk->AW1[1][2][1].Z.w[3]=0x1fdcf2389fea8857;

    mpk->AW1[1][2][2].X.len=0x4;
    mpk->AW1[1][2][2].X.w[0]=0x300f69f99174b584;
    mpk->AW1[1][2][2].X.w[1]=0x8e5c12e8a919c84b;
    mpk->AW1[1][2][2].X.w[2]=0x33a89d315846e708;
    mpk->AW1[1][2][2].X.w[3]=0x5e534d1fc4b4548;

    mpk->AW1[1][2][2].Y.len=0x4;
    mpk->AW1[1][2][2].Y.w[0]=0xd03fb317151b5a5f;
    mpk->AW1[1][2][2].Y.w[1]=0xcc0c8b093b07c2e6;
    mpk->AW1[1][2][2].Y.w[2]=0xa075e9a964b30897;
    mpk->AW1[1][2][2].Y.w[3]=0x33a36d91ae24b09;

    mpk->AW1[1][2][2].Z.len=0x4;
    mpk->AW1[1][2][2].Z.w[0]=0x9e96355e4c0e0517;
    mpk->AW1[1][2][2].Z.w[1]=0x6f31cb5eb754efe0;
    mpk->AW1[1][2][2].Z.w[2]=0x9af3328089762f3a;
    mpk->AW1[1][2][2].Z.w[3]=0xe574ce179600478;

    mpk->AW1[2][0][0].X.len=0x4;
    mpk->AW1[2][0][0].X.w[0]=0x94867ebb74039867;
    mpk->AW1[2][0][0].X.w[1]=0xa49857deea3f57ef;
    mpk->AW1[2][0][0].X.w[2]=0xfee3d0dc87f9b307;
    mpk->AW1[2][0][0].X.w[3]=0x1037a559eadda17;

    mpk->AW1[2][0][0].Y.len=0x4;
    mpk->AW1[2][0][0].Y.w[0]=0xa4977c51c7d27ce;
    mpk->AW1[2][0][0].Y.w[1]=0x57cc536f1737afad;
    mpk->AW1[2][0][0].Y.w[2]=0xf2f4e6cad8684f9c;
    mpk->AW1[2][0][0].Y.w[3]=0x13d7a6a79fe9d448;

    mpk->AW1[2][0][0].Z.len=0x4;
    mpk->AW1[2][0][0].Z.w[0]=0x25096e01d14bf2d7;
    mpk->AW1[2][0][0].Z.w[1]=0x917e002ba1a49b3b;
    mpk->AW1[2][0][0].Z.w[2]=0xa99088165b9cfb6c;
    mpk->AW1[2][0][0].Z.w[3]=0x19a14543d1df678f;

    mpk->AW1[2][0][1].X.len=0x4;
    mpk->AW1[2][0][1].X.w[0]=0xd8388aca4b173e1e;
    mpk->AW1[2][0][1].X.w[1]=0x7a19fdf88adf571b;
    mpk->AW1[2][0][1].X.w[2]=0xd66bcac0fac15747;
    mpk->AW1[2][0][1].X.w[3]=0xcd7d484e844aa16;

    mpk->AW1[2][0][1].Y.len=0x4;
    mpk->AW1[2][0][1].Y.w[0]=0xbc0d0c688b5846c0;
    mpk->AW1[2][0][1].Y.w[1]=0xf60760a8ebd54d74;
    mpk->AW1[2][0][1].Y.w[2]=0x23046015c50da7b2;
    mpk->AW1[2][0][1].Y.w[3]=0x191f190356f3e9f;

    mpk->AW1[2][0][1].Z.len=0x4;
    mpk->AW1[2][0][1].Z.w[0]=0x84b71d623891bccf;
    mpk->AW1[2][0][1].Z.w[1]=0x6616986f4010f4a;
    mpk->AW1[2][0][1].Z.w[2]=0xa1ed2fa71caff3da;
    mpk->AW1[2][0][1].Z.w[3]=0x166d9c057d942702;

    mpk->AW1[2][0][2].X.len=0x4;
    mpk->AW1[2][0][2].X.w[0]=0xba2821ddb6f0ec1a;
    mpk->AW1[2][0][2].X.w[1]=0xe4a052bbd863e396;
    mpk->AW1[2][0][2].X.w[2]=0x8612933e6d9ace50;
    mpk->AW1[2][0][2].X.w[3]=0x217fa994152d0bc4;

    mpk->AW1[2][0][2].Y.len=0x4;
    mpk->AW1[2][0][2].Y.w[0]=0x4653b352dffce51;
    mpk->AW1[2][0][2].Y.w[1]=0x3bb4bcd3724d2fae;
    mpk->AW1[2][0][2].Y.w[2]=0x7146b45d8404195b;
    mpk->AW1[2][0][2].Y.w[3]=0x1f58251b31a38d14;

    mpk->AW1[2][0][2].Z.len=0x4;
    mpk->AW1[2][0][2].Z.w[0]=0xd822fc7f1f5af4e7;
    mpk->AW1[2][0][2].Z.w[1]=0xcca1b0d734c48fa;
    mpk->AW1[2][0][2].Z.w[2]=0xe736c378fe89bbba;
    mpk->AW1[2][0][2].Z.w[3]=0xfe231914c3d49ce;

    mpk->AW1[2][1][0].X.len=0x4;
    mpk->AW1[2][1][0].X.w[0]=0x7689c1f6ef5c3efb;
    mpk->AW1[2][1][0].X.w[1]=0x544e2a1091856bca;
    mpk->AW1[2][1][0].X.w[2]=0xac92d4a27eeb6fc8;
    mpk->AW1[2][1][0].X.w[3]=0x7eae87e7b61686e;

    mpk->AW1[2][1][0].Y.len=0x4;
    mpk->AW1[2][1][0].Y.w[0]=0x6c4bffb8f20c4ca1;
    mpk->AW1[2][1][0].Y.w[1]=0x66424555bd83b1a8;
    mpk->AW1[2][1][0].Y.w[2]=0xd84dbeb1adebef6;
    mpk->AW1[2][1][0].Y.w[3]=0x1807524e7ad68cc;

    mpk->AW1[2][1][0].Z.len=0x4;
    mpk->AW1[2][1][0].Z.w[0]=0x796781b6dcc22fd;
    mpk->AW1[2][1][0].Z.w[1]=0xcbe1e03d60485d0f;
    mpk->AW1[2][1][0].Z.w[2]=0xe01ac2a053113b0d;
    mpk->AW1[2][1][0].Z.w[3]=0x160f4141438bf6ae;

    mpk->AW1[2][1][1].X.len=0x4;
    mpk->AW1[2][1][1].X.w[0]=0x89a56e1ea027875a;
    mpk->AW1[2][1][1].X.w[1]=0x49c8f134bf831d2d;
    mpk->AW1[2][1][1].X.w[2]=0xf559261fdae7697d;
    mpk->AW1[2][1][1].X.w[3]=0x798383f210173ff;

    mpk->AW1[2][1][1].Y.len=0x4;
    mpk->AW1[2][1][1].Y.w[0]=0xc7f4d0e6cf4ea8af;
    mpk->AW1[2][1][1].Y.w[1]=0x4b8943d08c2bc08b;
    mpk->AW1[2][1][1].Y.w[2]=0x5dd4b4077187a94b;
    mpk->AW1[2][1][1].Y.w[3]=0x46442b0505ea34d;

    mpk->AW1[2][1][1].Z.len=0x4;
    mpk->AW1[2][1][1].Z.w[0]=0x90a7433955721a67;
    mpk->AW1[2][1][1].Z.w[1]=0x4228765b82eb8edb;
    mpk->AW1[2][1][1].Z.w[2]=0x58aa93e4b2132a1a;
    mpk->AW1[2][1][1].Z.w[3]=0x5d51bf4963c9402;

    mpk->AW1[2][1][2].X.len=0x4;
    mpk->AW1[2][1][2].X.w[0]=0x62c3368d7b62eb58;
    mpk->AW1[2][1][2].X.w[1]=0x1576da87501196e8;
    mpk->AW1[2][1][2].X.w[2]=0xd0fdfae8e6786582;
    mpk->AW1[2][1][2].X.w[3]=0x207d9f35e2b0dafa;

    mpk->AW1[2][1][2].Y.len=0x4;
    mpk->AW1[2][1][2].Y.w[0]=0x97130b50368af4f4;
    mpk->AW1[2][1][2].Y.w[1]=0x2b4ee978424f543;
    mpk->AW1[2][1][2].Y.w[2]=0x8a205c5d2be7f417;
    mpk->AW1[2][1][2].Y.w[3]=0x123069e011b5d0d9;

    mpk->AW1[2][1][2].Z.len=0x4;
    mpk->AW1[2][1][2].Z.w[0]=0xb1bb7c9359441e0c;
    mpk->AW1[2][1][2].Z.w[1]=0x4c76b46c69975222;
    mpk->AW1[2][1][2].Z.w[2]=0xf2ba4f0fa33ff374;
    mpk->AW1[2][1][2].Z.w[3]=0x1f854833bfb34f2;

    mpk->AW1[2][2][0].X.len=0x4;
    mpk->AW1[2][2][0].X.w[0]=0x23aa183b00749f54;
    mpk->AW1[2][2][0].X.w[1]=0xaf86fd9b5612e070;
    mpk->AW1[2][2][0].X.w[2]=0x5e0a2126bbaee554;
    mpk->AW1[2][2][0].X.w[3]=0x18ec2fbca11be4b6;

    mpk->AW1[2][2][0].Y.len=0x4;
    mpk->AW1[2][2][0].Y.w[0]=0x1f26d820ac0c18ed;
    mpk->AW1[2][2][0].Y.w[1]=0x380c3834f92a4abe;
    mpk->AW1[2][2][0].Y.w[2]=0x4ad3617a42d256c1;
    mpk->AW1[2][2][0].Y.w[3]=0x2046efd40ab69864;

    mpk->AW1[2][2][0].Z.len=0x4;
    mpk->AW1[2][2][0].Z.w[0]=0xcf8f5538a6c2500d;
    mpk->AW1[2][2][0].Z.w[1]=0x18aefce0d8ecf6db;
    mpk->AW1[2][2][0].Z.w[2]=0xa0f2b97ba7320a48;
    mpk->AW1[2][2][0].Z.w[3]=0x58bee50e4f06e65;

    mpk->AW1[2][2][1].X.len=0x4;
    mpk->AW1[2][2][1].X.w[0]=0xc1174f5e83dbadc8;
    mpk->AW1[2][2][1].X.w[1]=0xcf495e382edb2f41;
    mpk->AW1[2][2][1].X.w[2]=0x199d8378ac872632;
    mpk->AW1[2][2][1].X.w[3]=0x154610c497d6a688;

    mpk->AW1[2][2][1].Y.len=0x4;
    mpk->AW1[2][2][1].Y.w[0]=0x44354a3ea73a95e;
    mpk->AW1[2][2][1].Y.w[1]=0xead99dbc21f99f8f;
    mpk->AW1[2][2][1].Y.w[2]=0x91d97e2c1323881e;
    mpk->AW1[2][2][1].Y.w[3]=0x1e1096c522fd4274;

    mpk->AW1[2][2][1].Z.len=0x4;
    mpk->AW1[2][2][1].Z.w[0]=0x4d220dd1f03153d0;
    mpk->AW1[2][2][1].Z.w[1]=0xc78d3400b2e898d6;
    mpk->AW1[2][2][1].Z.w[2]=0x22031a89d8ebd8f1;
    mpk->AW1[2][2][1].Z.w[3]=0x1c15dc6cb97ed6f;

    mpk->AW1[2][2][2].X.len=0x4;
    mpk->AW1[2][2][2].X.w[0]=0xa8d18849752aabd6;
    mpk->AW1[2][2][2].X.w[1]=0x2b9fe5f39df22a37;
    mpk->AW1[2][2][2].X.w[2]=0xd714ce9491c88ed4;
    mpk->AW1[2][2][2].X.w[3]=0x8eb04cfe2197948;

    mpk->AW1[2][2][2].Y.len=0x4;
    mpk->AW1[2][2][2].Y.w[0]=0xea836a49a44071f3;
    mpk->AW1[2][2][2].Y.w[1]=0x77b07bd2a1b21b8a;
    mpk->AW1[2][2][2].Y.w[2]=0x127c55530c79ab1d;
    mpk->AW1[2][2][2].Y.w[3]=0x176534baa1d8e92d;

    mpk->AW1[2][2][2].Z.len=0x4;
    mpk->AW1[2][2][2].Z.w[0]=0xea9fca9a0f990b26;
    mpk->AW1[2][2][2].Z.w[1]=0xcd7758c2e15ad16e;
    mpk->AW1[2][2][2].Z.w[2]=0xcab74686c28b4c01;
    mpk->AW1[2][2][2].Z.w[3]=0x87f7d8e8e3507e;


#endif
    //V,2k
#if 0
    for(int i=0;i<2*CP_ABE_PARA_K;i++)
    {
        BNT.Trf_Big_to_Char(msk2.msk.V[i],msk->V[i]);
#if 1
        BNT.bn_printfBig("msk->V[i]",msk->V[i]);

#endif
    }
#else
    msk->V[0].len=0x4;
    msk->V[0].w[0]=0xbc96776093eb47e1;
    msk->V[0].w[1]=0x1b78ba739a156cb7;
    msk->V[0].w[2]=0x3d70c12251e92b8a;
    msk->V[0].w[3]=0xa566bb6bd7e139c1;

    msk->V[1].len=0x4;
    msk->V[1].w[0]=0xe49232ab29cb59d1;
    msk->V[1].w[1]=0xd612a01668ddc09f;
    msk->V[1].w[2]=0xa38f775663ec9423;
    msk->V[1].w[3]=0x84622b2bad65ff29;

    msk->V[2].len=0x4;
    msk->V[2].w[0]=0x686601eb34e91195;
    msk->V[2].w[1]=0x8cdbd3e60a9bbf40;
    msk->V[2].w[2]=0x4ca05cc4441cfcd0;
    msk->V[2].w[3]=0xac47493f0fa42f74;

    msk->V[3].len=0x4;
    msk->V[3].w[0]=0x6ff53e06b457f577;
    msk->V[3].w[1]=0x14da8410d485a7dc;
    msk->V[3].w[2]=0xded7522d28ecfa9;
    msk->V[3].w[3]=0xf133d120e25b7a03;

    msk->V[4].len=0x4;
    msk->V[4].w[0]=0x69ccffc407688df3;
    msk->V[4].w[1]=0x1261d8929408248;
    msk->V[4].w[2]=0x6224e0ea7aa7d219;
    msk->V[4].w[3]=0xe074f24829d2b034;

    msk->V[5].len=0x4;
    msk->V[5].w[0]=0x95bb1d3fafa46d68;
    msk->V[5].w[1]=0x5028cd895a28d050;
    msk->V[5].w[2]=0xbef4b44316d95f14;
    msk->V[5].w[3]=0xb94b4441adcceb72;

#endif
#if 0
    //e(A,v),k
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        BNT.Trf_GT_to_Char(mpk2.mpk.eAV[i],mpk->eAV[i]);
#if 1
        BNT.bn_printfGT("mpk->eAV[i]",mpk->eAV[i]);

#endif
    }
#else


    mpk->eAV[0].Aaa.len=0x4;
    mpk->eAV[0].Aaa.w[0]=0x1890c67f4d4c10c6;
    mpk->eAV[0].Aaa.w[1]=0xdd2d4fc54e9460c6;
    mpk->eAV[0].Aaa.w[2]=0x5843eb49919397ab;
    mpk->eAV[0].Aaa.w[3]=0x196e52f5f26b7503;

    mpk->eAV[0].Aab.len=0x4;
    mpk->eAV[0].Aab.w[0]=0xb310fc0f9f044f81;
    mpk->eAV[0].Aab.w[1]=0x175b946b0d827915;
    mpk->eAV[0].Aab.w[2]=0x50ac6b4dbe30abde;
    mpk->eAV[0].Aab.w[3]=0x14fb298505a2e160;

    mpk->eAV[0].Aba.len=0x4;
    mpk->eAV[0].Aba.w[0]=0xee613868fa520948;
    mpk->eAV[0].Aba.w[1]=0x6e63c5e9da4aa01;
    mpk->eAV[0].Aba.w[2]=0xf06fdb0406c58d0a;
    mpk->eAV[0].Aba.w[3]=0x127cbc5dff04c82f;

    mpk->eAV[0].Abb.len=0x4;
    mpk->eAV[0].Abb.w[0]=0x27e4531999d65279;
    mpk->eAV[0].Abb.w[1]=0xa66ad53bfa0b4ec;
    mpk->eAV[0].Abb.w[2]=0x8836072cc24e317e;
    mpk->eAV[0].Abb.w[3]=0x1233fdaa08e6e8a0;

    mpk->eAV[0].Baa.len=0x4;
    mpk->eAV[0].Baa.w[0]=0x63c8bf6bd144ddc9;
    mpk->eAV[0].Baa.w[1]=0x37c043b832158a8;
    mpk->eAV[0].Baa.w[2]=0x7bf64732b93fd017;
    mpk->eAV[0].Baa.w[3]=0x1daf92a80cb4199f;

    mpk->eAV[0].Bab.len=0x4;
    mpk->eAV[0].Bab.w[0]=0x4d86975198d77427;
    mpk->eAV[0].Bab.w[1]=0x7a3a404e6995bb19;
    mpk->eAV[0].Bab.w[2]=0xd47c00c192bf4dca;
    mpk->eAV[0].Bab.w[3]=0xf20919affa577ee;

    mpk->eAV[0].Bba.len=0x4;
    mpk->eAV[0].Bba.w[0]=0xdf4410447aedfaa9;
    mpk->eAV[0].Bba.w[1]=0x212a5266b4d56309;
    mpk->eAV[0].Bba.w[2]=0xfcbf872a7e0ab587;
    mpk->eAV[0].Bba.w[3]=0x1560be4f88d64e69;

    mpk->eAV[0].Bbb.len=0x4;
    mpk->eAV[0].Bbb.w[0]=0xc17be8075a64b4c8;
    mpk->eAV[0].Bbb.w[1]=0x5fc26266232a884c;
    mpk->eAV[0].Bbb.w[2]=0x2858660460317c21;
    mpk->eAV[0].Bbb.w[3]=0xb1d425423a4a117;

    mpk->eAV[0].Caa.len=0x4;
    mpk->eAV[0].Caa.w[0]=0xe040eca21c2dc5fd;
    mpk->eAV[0].Caa.w[1]=0x29df66a40c8cf339;
    mpk->eAV[0].Caa.w[2]=0x8762f4b7ef654499;
    mpk->eAV[0].Caa.w[3]=0x40427fb41e0cae6;

    mpk->eAV[0].Cab.len=0x4;
    mpk->eAV[0].Cab.w[0]=0x1c479ac30f6e9cd7;
    mpk->eAV[0].Cab.w[1]=0x6d96abec2a92d7ca;
    mpk->eAV[0].Cab.w[2]=0x551cf0aff4b69d89;
    mpk->eAV[0].Cab.w[3]=0x1dbd2ce83606cb15;

    mpk->eAV[0].Cba.len=0x4;
    mpk->eAV[0].Cba.w[0]=0x2144b239bc6fae9c;
    mpk->eAV[0].Cba.w[1]=0x68e1cb00eaf856dd;
    mpk->eAV[0].Cba.w[2]=0xc03756646e0b481e;
    mpk->eAV[0].Cba.w[3]=0x1e4a4409142ed87c;

    mpk->eAV[0].Cbb.len=0x4;
    mpk->eAV[0].Cbb.w[0]=0xd8a7d5657217b78f;
    mpk->eAV[0].Cbb.w[1]=0xfae5450a77563be2;
    mpk->eAV[0].Cbb.w[2]=0x2fd64f45114d5115;
    mpk->eAV[0].Cbb.w[3]=0xe42683aa8e07eb2;

    mpk->eAV[1].Aaa.len=0x4;
    mpk->eAV[1].Aaa.w[0]=0xad8568a16af45220;
    mpk->eAV[1].Aaa.w[1]=0x7e7a8f6c02975ae;
    mpk->eAV[1].Aaa.w[2]=0xe1300fd77087b6eb;
    mpk->eAV[1].Aaa.w[3]=0xbb46b02b33ca70e;

    mpk->eAV[1].Aab.len=0x4;
    mpk->eAV[1].Aab.w[0]=0x26269c18246555d2;
    mpk->eAV[1].Aab.w[1]=0x558a2c5ef9a23226;
    mpk->eAV[1].Aab.w[2]=0x4479a3b807a431ef;
    mpk->eAV[1].Aab.w[3]=0x2dcb8c92890f665;

    mpk->eAV[1].Aba.len=0x4;
    mpk->eAV[1].Aba.w[0]=0xdfd8726748f889e6;
    mpk->eAV[1].Aba.w[1]=0xd4376219b62ee640;
    mpk->eAV[1].Aba.w[2]=0x8636c260427e89e;
    mpk->eAV[1].Aba.w[3]=0x6d05f128ac111d3;

    mpk->eAV[1].Abb.len=0x4;
    mpk->eAV[1].Abb.w[0]=0x8f38bba195b1906c;
    mpk->eAV[1].Abb.w[1]=0x5078b811caaf21f9;
    mpk->eAV[1].Abb.w[2]=0xeb58a94f73b8fe7d;
    mpk->eAV[1].Abb.w[3]=0xc43639c75cd3e0a;

    mpk->eAV[1].Baa.len=0x4;
    mpk->eAV[1].Baa.w[0]=0x82c37f5f3837ac3;
    mpk->eAV[1].Baa.w[1]=0xcc0c7e308a134b17;
    mpk->eAV[1].Baa.w[2]=0xf538a062a6f70556;
    mpk->eAV[1].Baa.w[3]=0x16f0894c6ab3f920;

    mpk->eAV[1].Bab.len=0x4;
    mpk->eAV[1].Bab.w[0]=0x5ab8bdd1e8410f3e;
    mpk->eAV[1].Bab.w[1]=0x7b20257097b673d7;
    mpk->eAV[1].Bab.w[2]=0x37e84594d905b115;
    mpk->eAV[1].Bab.w[3]=0x1a1f8e8f3835a0f8;

    mpk->eAV[1].Bba.len=0x4;
    mpk->eAV[1].Bba.w[0]=0x5a35e9dcef2f14db;
    mpk->eAV[1].Bba.w[1]=0x680228c62e112f11;
    mpk->eAV[1].Bba.w[2]=0xd50211ce90f5140;
    mpk->eAV[1].Bba.w[3]=0xd28eb78c818a4fe;

    mpk->eAV[1].Bbb.len=0x4;
    mpk->eAV[1].Bbb.w[0]=0x6ca76d9550d132a1;
    mpk->eAV[1].Bbb.w[1]=0x2ed3c111a2e1cc2e;
    mpk->eAV[1].Bbb.w[2]=0xe2853590a1784eaa;
    mpk->eAV[1].Bbb.w[3]=0x20b112cc6d432561;

    mpk->eAV[1].Caa.len=0x4;
    mpk->eAV[1].Caa.w[0]=0x82b5036020c4bd10;
    mpk->eAV[1].Caa.w[1]=0x460747868f751d9f;
    mpk->eAV[1].Caa.w[2]=0x479969f9ae80663e;
    mpk->eAV[1].Caa.w[3]=0x11175958ed37e53d;

    mpk->eAV[1].Cab.len=0x4;
    mpk->eAV[1].Cab.w[0]=0x59f4ad286754a20b;
    mpk->eAV[1].Cab.w[1]=0x7152f4a889b95531;
    mpk->eAV[1].Cab.w[2]=0x1338b6efb177eb4b;
    mpk->eAV[1].Cab.w[3]=0x7f9e54fe6d0c9e;

    mpk->eAV[1].Cba.len=0x4;
    mpk->eAV[1].Cba.w[0]=0x55a31cccd939eeb6;
    mpk->eAV[1].Cba.w[1]=0xf9db2f200c285402;
    mpk->eAV[1].Cba.w[2]=0x97a0b5f164ac6dfd;
    mpk->eAV[1].Cba.w[3]=0x18b6c3b360befeea;

    mpk->eAV[1].Cbb.len=0x4;
    mpk->eAV[1].Cbb.w[0]=0x7db0cef83064d5c8;
    mpk->eAV[1].Cbb.w[1]=0x3f19eed4bf5a946b;
    mpk->eAV[1].Cbb.w[2]=0xe8f87909990538fe;
    mpk->eAV[1].Cbb.w[3]=0x3d6f5188fe7c0bc;

    mpk->eAV[2].Aaa.len=0x4;
    mpk->eAV[2].Aaa.w[0]=0x7e6c331729f86cc3;
    mpk->eAV[2].Aaa.w[1]=0x2d9fc11396f2417;
    mpk->eAV[2].Aaa.w[2]=0xa1e016ea807d5789;
    mpk->eAV[2].Aaa.w[3]=0x13b914ece7f7cb69;

    mpk->eAV[2].Aab.len=0x4;
    mpk->eAV[2].Aab.w[0]=0x317e8371a4571865;
    mpk->eAV[2].Aab.w[1]=0xea12b978a737b0dc;
    mpk->eAV[2].Aab.w[2]=0xd1c68b2848366d32;
    mpk->eAV[2].Aab.w[3]=0x10e67f9270cc330f;

    mpk->eAV[2].Aba.len=0x4;
    mpk->eAV[2].Aba.w[0]=0xea1f1a0b4f6b843;
    mpk->eAV[2].Aba.w[1]=0xb7b83705caa62148;
    mpk->eAV[2].Aba.w[2]=0xbc49ad4d507bbeb9;
    mpk->eAV[2].Aba.w[3]=0x168ce767e909303a;

    mpk->eAV[2].Abb.len=0x4;
    mpk->eAV[2].Abb.w[0]=0x5495207a20dfad66;
    mpk->eAV[2].Abb.w[1]=0x9ca22c93e118a90f;
    mpk->eAV[2].Abb.w[2]=0x6e0b616f93474656;
    mpk->eAV[2].Abb.w[3]=0x1e7dd4aca6b12ea5;

    mpk->eAV[2].Baa.len=0x4;
    mpk->eAV[2].Baa.w[0]=0x718e674cb6658a2d;
    mpk->eAV[2].Baa.w[1]=0x391e077a676226ab;
    mpk->eAV[2].Baa.w[2]=0x9b25bc9edf4addd7;
    mpk->eAV[2].Baa.w[3]=0xdc75b9ed6206915;

    mpk->eAV[2].Bab.len=0x4;
    mpk->eAV[2].Bab.w[0]=0x7b480b1877e277fc;
    mpk->eAV[2].Bab.w[1]=0x8130e2c9d6efd506;
    mpk->eAV[2].Bab.w[2]=0x40050802c6b7b663;
    mpk->eAV[2].Bab.w[3]=0x18dbf291d63d236d;

    mpk->eAV[2].Bba.len=0x4;
    mpk->eAV[2].Bba.w[0]=0xab7352571e980d8f;
    mpk->eAV[2].Bba.w[1]=0xc6cedfa7f90d7968;
    mpk->eAV[2].Bba.w[2]=0x7eb63b484c0e5211;
    mpk->eAV[2].Bba.w[3]=0x42bd882d2b3df5f;

    mpk->eAV[2].Bbb.len=0x4;
    mpk->eAV[2].Bbb.w[0]=0xb83a743dece5aee0;
    mpk->eAV[2].Bbb.w[1]=0xd211599028fd655e;
    mpk->eAV[2].Bbb.w[2]=0xf086823143f8cf36;
    mpk->eAV[2].Bbb.w[3]=0x1e83f5c8fd3dbd03;

    mpk->eAV[2].Caa.len=0x4;
    mpk->eAV[2].Caa.w[0]=0x81184098bc17016;
    mpk->eAV[2].Caa.w[1]=0xbb41ea782349c2d5;
    mpk->eAV[2].Caa.w[2]=0xe31c63df825440b1;
    mpk->eAV[2].Caa.w[3]=0xa1f9a0d61c41290;

    mpk->eAV[2].Cab.len=0x4;
    mpk->eAV[2].Cab.w[0]=0x8cb525f1d9a6856c;
    mpk->eAV[2].Cab.w[1]=0x73c613cb5c1d07c;
    mpk->eAV[2].Cab.w[2]=0xd47b28d441121ab7;
    mpk->eAV[2].Cab.w[3]=0x21bbd3e9baabe0f2;

    mpk->eAV[2].Cba.len=0x4;
    mpk->eAV[2].Cba.w[0]=0x1c26d4c3cfd671d9;
    mpk->eAV[2].Cba.w[1]=0xc86ae2fce05dc324;
    mpk->eAV[2].Cba.w[2]=0xa801182926a20850;
    mpk->eAV[2].Cba.w[3]=0x22413b7335033fe3;

    mpk->eAV[2].Cbb.len=0x4;
    mpk->eAV[2].Cbb.w[0]=0x3e5d47cd8560a2b1;
    mpk->eAV[2].Cbb.w[1]=0x7b43ce5261542878;
    mpk->eAV[2].Cbb.w[2]=0xf3660302435387f7;
    mpk->eAV[2].Cbb.w[3]=0x9cac0015f9fa3b7;


#endif

    return ret;
}
int CredKeyGen(struct ACME_CRED_KEY_C *cred_key)
{
#if 0 //test
    streambuf* coutBuf = cout.rdbuf();
    ofstream of("setup_data.txt");
    streambuf* fileBuf = of.rdbuf();
    cout.rdbuf(fileBuf);
#endif

    int ret=0;
#if 0
    ACME_CRED_KEY cred_key2;

    ret = prisrv.CredKeyGen(cred_key2);
    if (ret !=0) return ret;
#endif


    //
#if 0
    BNT.Trf_Big_to_Char(cred_key2.cred_key.sk.x,cred_key->sk.x);
    BNT.Trf_G1_to_Char(cred_key2.cred_key.pk.W,cred_key->pk.W);
#else
    cred_key->sk.x.len=0x4;
    cred_key->sk.x.w[0]=0x9fac5065e5c9174;
    cred_key->sk.x.w[1]=0x653e097abcc561ab;
    cred_key->sk.x.w[2]=0xc975d9f8414d7464;
    cred_key->sk.x.w[3]=0xb00858201458ab2a;

//    BNT.bn_printfBig("cred_key->sk.x",cred_key->sk.x);
    cred_key->pk.W.X.len=0x4;
    cred_key->pk.W.X.w[0]=0x93ba08503e69cadf;
    cred_key->pk.W.X.w[1]=0x1f877e2e7862797f;
    cred_key->pk.W.X.w[2]=0xc2a0e0c38deaecae;
    cred_key->pk.W.X.w[3]=0x21ed8401457650d4;

    cred_key->pk.W.Y.len=0x4;
    cred_key->pk.W.Y.w[0]=0xd53240d23b8221ff;
    cred_key->pk.W.Y.w[1]=0xe6f9112be3f6f777;
    cred_key->pk.W.Y.w[2]=0x48567d2d6eac4904;
    cred_key->pk.W.Y.w[3]=0x167f073667badfe7;

    cred_key->pk.W.Z.len=0x4;
    cred_key->pk.W.Z.w[0]=0x3d9047182c64304e;
    cred_key->pk.W.Z.w[1]=0xa51248e7139933de;
    cred_key->pk.W.Z.w[2]=0x1a12bfdc38979a53;
    cred_key->pk.W.Z.w[3]=0x129c5be7570447ed;

//    BNT.bn_printfG1("cred_key->pk.W",cred_key->pk.W);
#endif
#if 0
    for(int i=0;i<FAC_PARA_N+2;i++)
    {
 //       BNT.Trf_Big_to_Char(cred_key2.cred_key.sk.y[i],cred_key->sk.y[i]);
//        BNT.bn_printfBig("cred_key->sk.y[i]",cred_key->sk.y[i]);
//        BNT.Trf_G2_to_Char(cred_key2.cred_key.pk.X[i],cred_key->pk.X[i]);
//        BNT.bn_printfG2("cred_key->pk.X[i]",cred_key->pk.X[i]);
        BNT.Trf_G1_to_Char(cred_key2.cred_key.pk.Y[i],cred_key->pk.Y[i]);
        BNT.bn_printfG1("cred_key->pk.Y[i]",cred_key->pk.Y[i]);
    }
#else
    /***************************/

    cred_key->pk.Y[0].X.len=0x4;
    cred_key->pk.Y[0].X.w[0]=0xb05616e4fa42fb38;
    cred_key->pk.Y[0].X.w[1]=0xe20310311368963d;
    cred_key->pk.Y[0].X.w[2]=0x8814f8712f16fffd;
    cred_key->pk.Y[0].X.w[3]=0x619175dbe9b555f;

    cred_key->pk.Y[0].Y.len=0x4;
    cred_key->pk.Y[0].Y.w[0]=0x5b66c5c6ebca39c8;
    cred_key->pk.Y[0].Y.w[1]=0x468d4cdcb6b84ee8;
    cred_key->pk.Y[0].Y.w[2]=0xf36b538df0b5ba4f;
    cred_key->pk.Y[0].Y.w[3]=0x3e9ec855129de1c;

    cred_key->pk.Y[0].Z.len=0x4;
    cred_key->pk.Y[0].Z.w[0]=0x46c2a13534a50538;
    cred_key->pk.Y[0].Z.w[1]=0x3e629c90c8169d6b;
    cred_key->pk.Y[0].Z.w[2]=0x68ad3beae4bf101f;
    cred_key->pk.Y[0].Z.w[3]=0x129a82cd2e34fd38;


    cred_key->pk.Y[1].X.len=0x4;
    cred_key->pk.Y[1].X.w[0]=0xeb2fb70f303209f1;
    cred_key->pk.Y[1].X.w[1]=0xfaecb9a74b0130b9;
    cred_key->pk.Y[1].X.w[2]=0x3700a7d63247d03e;
    cred_key->pk.Y[1].X.w[3]=0x1a53f8472de4d4be;

    cred_key->pk.Y[1].Y.len=0x4;
    cred_key->pk.Y[1].Y.w[0]=0xfebd56b2340a1c0d;
    cred_key->pk.Y[1].Y.w[1]=0x1902d8cef6bd8a9b;
    cred_key->pk.Y[1].Y.w[2]=0x7479c32f5ed94d1c;
    cred_key->pk.Y[1].Y.w[3]=0x23fa350575ee19c4;

    cred_key->pk.Y[1].Z.len=0x4;
    cred_key->pk.Y[1].Z.w[0]=0xaaaa346609936a8d;
    cred_key->pk.Y[1].Z.w[1]=0x9745fe514ce12e47;
    cred_key->pk.Y[1].Z.w[2]=0x3a1c24237ee11b6d;
    cred_key->pk.Y[1].Z.w[3]=0x23bb8c0148febca5;

    cred_key->pk.Y[2].X.len=0x4;
    cred_key->pk.Y[2].X.w[0]=0x87d260768dce617d;
    cred_key->pk.Y[2].X.w[1]=0x4be165f581e11689;
    cred_key->pk.Y[2].X.w[2]=0x99cb951623a573ef;
    cred_key->pk.Y[2].X.w[3]=0x496bad54c49ab82;

    cred_key->pk.Y[2].Y.len=0x4;
    cred_key->pk.Y[2].Y.w[0]=0x501ae4e8c5f93a2c;
    cred_key->pk.Y[2].Y.w[1]=0xa644c783b13da324;
    cred_key->pk.Y[2].Y.w[2]=0xc78b6c33aca10451;
    cred_key->pk.Y[2].Y.w[3]=0x1d449488d7942a49;

    cred_key->pk.Y[2].Z.len=0x4;
    cred_key->pk.Y[2].Z.w[0]=0xda72cde5e9086e2f;
    cred_key->pk.Y[2].Z.w[1]=0xcdddc1bde89de372;
    cred_key->pk.Y[2].Z.w[2]=0x7dd4a6dff6dc7902;
    cred_key->pk.Y[2].Z.w[3]=0x9fddbc7106652d1;

    cred_key->pk.Y[3].X.len=0x4;
    cred_key->pk.Y[3].X.w[0]=0x8546f4e35f1061bb;
    cred_key->pk.Y[3].X.w[1]=0xd584279f80dac4ce;
    cred_key->pk.Y[3].X.w[2]=0xf4ff0e1bf82612fd;
    cred_key->pk.Y[3].X.w[3]=0x1ddda067d14bc791;

    cred_key->pk.Y[3].Y.len=0x4;
    cred_key->pk.Y[3].Y.w[0]=0x8e5967741b04fd88;
    cred_key->pk.Y[3].Y.w[1]=0xa9deb983d15a7033;
    cred_key->pk.Y[3].Y.w[2]=0x2b4781fceea24172;
    cred_key->pk.Y[3].Y.w[3]=0x1e291cf186fc9ad2;

    cred_key->pk.Y[3].Z.len=0x4;
    cred_key->pk.Y[3].Z.w[0]=0x33e3979e6a5ecc5d;
    cred_key->pk.Y[3].Z.w[1]=0x5c1ab8b0223247d1;
    cred_key->pk.Y[3].Z.w[2]=0xd7b6a05f38d039c5;
    cred_key->pk.Y[3].Z.w[3]=0x4e138ebd360f8dc;

    cred_key->pk.Y[4].X.len=0x4;
    cred_key->pk.Y[4].X.w[0]=0x127e9415f440f3dd;
    cred_key->pk.Y[4].X.w[1]=0x3d3d7aa233ac667;
    cred_key->pk.Y[4].X.w[2]=0x4a47dd03fe495ebb;
    cred_key->pk.Y[4].X.w[3]=0x81547e274cc0aed;

    cred_key->pk.Y[4].Y.len=0x4;
    cred_key->pk.Y[4].Y.w[0]=0x5de8d5002ad52926;
    cred_key->pk.Y[4].Y.w[1]=0xb89cd3d1980255d1;
    cred_key->pk.Y[4].Y.w[2]=0xad23637f39f1c72b;
    cred_key->pk.Y[4].Y.w[3]=0x21ce71a8af95b575;

    cred_key->pk.Y[4].Z.len=0x4;
    cred_key->pk.Y[4].Z.w[0]=0x6204e6c467aa437e;
    cred_key->pk.Y[4].Z.w[1]=0xb4a8c1c0e5a8973f;
    cred_key->pk.Y[4].Z.w[2]=0x53d3006fca8d4b8;
    cred_key->pk.Y[4].Z.w[3]=0x11058adedb8836e1;


    cred_key->pk.Y[5].X.len=0x4;
    cred_key->pk.Y[5].X.w[0]=0x882dd828a8968b0f;
    cred_key->pk.Y[5].X.w[1]=0x4893f4a25d61f011;
    cred_key->pk.Y[5].X.w[2]=0x30da0cf91d9bcf6a;
    cred_key->pk.Y[5].X.w[3]=0x8e01047273562ff;

    cred_key->pk.Y[5].Y.len=0x4;
    cred_key->pk.Y[5].Y.w[0]=0xdbfd40f78ccd7e8f;
    cred_key->pk.Y[5].Y.w[1]=0x50d6cead487d4edb;
    cred_key->pk.Y[5].Y.w[2]=0x71185cb97c7a86d6;
    cred_key->pk.Y[5].Y.w[3]=0x162e7db66110aa00;

    cred_key->pk.Y[5].Z.len=0x4;
    cred_key->pk.Y[5].Z.w[0]=0x9c2ba7983ab85bf;
    cred_key->pk.Y[5].Z.w[1]=0x55d8f9d491b86bb2;
    cred_key->pk.Y[5].Z.w[2]=0xcaad97aaa2f80960;
    cred_key->pk.Y[5].Z.w[3]=0x1e61b87f3090e011;


    cred_key->pk.Y[6].X.len=0x4;
    cred_key->pk.Y[6].X.w[0]=0x663e5f5540303bd7;
    cred_key->pk.Y[6].X.w[1]=0x99bf6bb8732a1232;
    cred_key->pk.Y[6].X.w[2]=0xcd84209235b54a30;
    cred_key->pk.Y[6].X.w[3]=0x4c12a1440768173;

    cred_key->pk.Y[6].Y.len=0x4;
    cred_key->pk.Y[6].Y.w[0]=0x7367508c81aeac7a;
    cred_key->pk.Y[6].Y.w[1]=0xbeae051ecf8fb42e;
    cred_key->pk.Y[6].Y.w[2]=0x424a71a1a84e6615;
    cred_key->pk.Y[6].Y.w[3]=0x82507f784d9b8f9;

    cred_key->pk.Y[6].Z.len=0x4;
    cred_key->pk.Y[6].Z.w[0]=0x78a111fee5b418f9;
    cred_key->pk.Y[6].Z.w[1]=0xd0a7443045a2204;
    cred_key->pk.Y[6].Z.w[2]=0x2ffc7d9208b7269c;
    cred_key->pk.Y[6].Z.w[3]=0x2054e6bd436b00c0;


    /***************************/
    cred_key->pk.X[0].Xa.len=0x4;
    cred_key->pk.X[0].Xa.w[0]=0xbb9f7015b8ecbf8f;
    cred_key->pk.X[0].Xa.w[1]=0xe4cdb6f99a779fac;
    cred_key->pk.X[0].Xa.w[2]=0xda99c9a0dd720d75;
    cred_key->pk.X[0].Xa.w[3]=0x246d0b741b822aa;

    cred_key->pk.X[0].Xb.len=0x4;
    cred_key->pk.X[0].Xb.w[0]=0xb320de0cb1c61507;
    cred_key->pk.X[0].Xb.w[1]=0x166305f88f9fd308;
    cred_key->pk.X[0].Xb.w[2]=0xd4668e58b5b19257;
    cred_key->pk.X[0].Xb.w[3]=0x1a587b474b62df5c;

    cred_key->pk.X[0].Ya.len=0x4;
    cred_key->pk.X[0].Ya.w[0]=0x9e216ac8a9da41d1;
    cred_key->pk.X[0].Ya.w[1]=0x7e5b8f3a5b7b517b;
    cred_key->pk.X[0].Ya.w[2]=0x602b4ecf836d059e;
    cred_key->pk.X[0].Ya.w[3]=0x8b077117057d34;

    cred_key->pk.X[0].Yb.len=0x4;
    cred_key->pk.X[0].Yb.w[0]=0x4ca3689567bfd1a8;
    cred_key->pk.X[0].Yb.w[1]=0x45792bf2d1518612;
    cred_key->pk.X[0].Yb.w[2]=0x69a1d83aef82bf9d;
    cred_key->pk.X[0].Yb.w[3]=0x2174152ee980f297;

    cred_key->pk.X[0].Za.len=0x1;
    cred_key->pk.X[0].Za.w[0]=0x1;

    cred_key->pk.X[0].Zb.len=0x0;
    /************/

    cred_key->pk.X[1].Xa.len=0x4;
    cred_key->pk.X[1].Xa.w[0]=0x2e81971b55b1c80d;
    cred_key->pk.X[1].Xa.w[1]=0x1c6e5f271d68c8b0;
    cred_key->pk.X[1].Xa.w[2]=0x16f54c7f21587ddc;
    cred_key->pk.X[1].Xa.w[3]=0x872e64e81be4032;

    cred_key->pk.X[1].Xb.len=0x4;
    cred_key->pk.X[1].Xb.w[0]=0x8b52f4d49c72875d;
    cred_key->pk.X[1].Xb.w[1]=0x43281aba30152555;
    cred_key->pk.X[1].Xb.w[2]=0x6f6fe8ffef82ad96;
    cred_key->pk.X[1].Xb.w[3]=0x7aad09e2528b06e;

    cred_key->pk.X[1].Ya.len=0x4;
    cred_key->pk.X[1].Ya.w[0]=0x3090e86286bb5331;
    cred_key->pk.X[1].Ya.w[1]=0xd78c9152ef558448;
    cred_key->pk.X[1].Ya.w[2]=0x72832b0281dcb249;
    cred_key->pk.X[1].Ya.w[3]=0x203ebf973e977d65;

    cred_key->pk.X[1].Yb.len=0x4;
    cred_key->pk.X[1].Yb.w[0]=0x9da87e39ed3f1a;
    cred_key->pk.X[1].Yb.w[1]=0xbeeeb2f89b90f619;
    cred_key->pk.X[1].Yb.w[2]=0xdca308b6a9d888a6;
    cred_key->pk.X[1].Yb.w[3]=0x1a8efa35abff03c5;

    cred_key->pk.X[1].Za.len=0x1;
    cred_key->pk.X[1].Za.w[0]=0x1;

    cred_key->pk.X[1].Zb.len=0x1;0x0;
    /*************/

    cred_key->pk.X[2].Xa.len=0x4;
    cred_key->pk.X[2].Xa.w[0]=0x18c38c524440e5d4;
    cred_key->pk.X[2].Xa.w[1]=0x809c823d1ae1350d;
    cred_key->pk.X[2].Xa.w[2]=0xb8aac00dce4b6a62;
    cred_key->pk.X[2].Xa.w[3]=0x9b7bb93336abae8;

    cred_key->pk.X[2].Xb.len=0x4;
    cred_key->pk.X[2].Xb.w[0]=0xef1bd423685dbaf0;
    cred_key->pk.X[2].Xb.w[1]=0x2606e72683d37ace;
    cred_key->pk.X[2].Xb.w[2]=0x79616ab33f552418;
    cred_key->pk.X[2].Xb.w[3]=0x15b4462770293503;

    cred_key->pk.X[2].Ya.len=0x4;
    cred_key->pk.X[2].Ya.w[0]=0x11d29dc6f53ff478;
    cred_key->pk.X[2].Ya.w[1]=0x62007321d0f86836;
    cred_key->pk.X[2].Ya.w[2]=0xee0609d01d20103b;
    cred_key->pk.X[2].Ya.w[3]=0x231713190f2b5134;

    cred_key->pk.X[2].Yb.len=0x4;
    cred_key->pk.X[2].Yb.w[0]=0x4367c21048f46e1a;
    cred_key->pk.X[2].Yb.w[1]=0x661c8e4899037126;
    cred_key->pk.X[2].Yb.w[2]=0x13fbdf7143bba581;
    cred_key->pk.X[2].Yb.w[3]=0xc7a7c58e4b6182e;

    cred_key->pk.X[2].Za.len=0x1;
    cred_key->pk.X[2].Za.w[0]=0x1;

    cred_key->pk.X[2].Zb.len=0x0;
    /********************/
    cred_key->pk.X[3].Xa.len=0x4;
    cred_key->pk.X[3].Xa.w[0]=0xc821b36ac59b30c;
    cred_key->pk.X[3].Xa.w[1]=0x119fe3930d390f5;
    cred_key->pk.X[3].Xa.w[2]=0x84e6678726e0c6ae;
    cred_key->pk.X[3].Xa.w[3]=0x2214208a8dc45594;

    cred_key->pk.X[3].Xb.len=0x4;
    cred_key->pk.X[3].Xb.w[0]=0x7162ef012b26f8;
    cred_key->pk.X[3].Xb.w[1]=0x849c900f08e248a4;
    cred_key->pk.X[3].Xb.w[2]=0x63be4c71cf60a66e;
    cred_key->pk.X[3].Xb.w[3]=0x8ba14b7c5780459;

    cred_key->pk.X[3].Ya.len=0x4;
    cred_key->pk.X[3].Ya.w[0]=0xa41b7b34146b17c1;
    cred_key->pk.X[3].Ya.w[1]=0xf2d86ad477213fd1;
    cred_key->pk.X[3].Ya.w[2]=0xe7ce7538999b4c6e;
    cred_key->pk.X[3].Ya.w[3]=0x1c5e1a015d50e2b;

    cred_key->pk.X[3].Yb.len=0x4;
    cred_key->pk.X[3].Yb.w[0]=0xfffd762580b02eeb;
    cred_key->pk.X[3].Yb.w[1]=0x52f92001cd2f8b07;
    cred_key->pk.X[3].Yb.w[2]=0x20a8b2452bc647a1;
    cred_key->pk.X[3].Yb.w[3]=0x173e9809757f98b5;

    cred_key->pk.X[3].Za.len=0x1;
    cred_key->pk.X[3].Za.w[0]=0x1;

    cred_key->pk.X[3].Zb.len=0x0;
    /************************/
    cred_key->pk.X[4].Xa.len=0x4;
    cred_key->pk.X[4].Xa.w[0]=0x9b54b58d0ff85e24;
    cred_key->pk.X[4].Xa.w[1]=0x7d5ba4b4896f003f;
    cred_key->pk.X[4].Xa.w[2]=0x5365abdbb9b9f6fa;
    cred_key->pk.X[4].Xa.w[3]=0x128742880c01c16f;

    cred_key->pk.X[4].Xb.len=0x4;
    cred_key->pk.X[4].Xb.w[0]=0x2aa9d5d18935d378;
    cred_key->pk.X[4].Xb.w[1]=0x2a60d5c50c39a337;
    cred_key->pk.X[4].Xb.w[2]=0x86801229048db18c;
    cred_key->pk.X[4].Xb.w[3]=0x23adb405920e25f2;

    cred_key->pk.X[4].Ya.len=0x4;
    cred_key->pk.X[4].Ya.w[0]=0x38b1085cea5a9192;
    cred_key->pk.X[4].Ya.w[1]=0x72bd1cb6488b52c3;
    cred_key->pk.X[4].Ya.w[2]=0x6f17406caaf83251;
    cred_key->pk.X[4].Ya.w[3]=0x737091e0e4dd57d;

    cred_key->pk.X[4].Yb.len=0x4;
    cred_key->pk.X[4].Yb.w[0]=0xe8370fd3cb545bf0;
    cred_key->pk.X[4].Yb.w[1]=0x1a5e18ade15ffab1;
    cred_key->pk.X[4].Yb.w[2]=0xf22c38f20bcae226;
    cred_key->pk.X[4].Yb.w[3]=0x1ee07ce6873975f8;

    cred_key->pk.X[4].Za.len=0x1;
    cred_key->pk.X[4].Za.w[0]=0x1;

    cred_key->pk.X[4].Zb.len=0x0;
    /*******************************/
    cred_key->pk.X[5].Xa.len=0x4;
    cred_key->pk.X[5].Xa.w[0]=0xca40c367baf7bf41;
    cred_key->pk.X[5].Xa.w[1]=0x6f7505bfeff13b34;
    cred_key->pk.X[5].Xa.w[2]=0x83e2c9e4d7b32f0f;
    cred_key->pk.X[5].Xa.w[3]=0x1c7555316c2af848;

    cred_key->pk.X[5].Xb.len=0x4;
    cred_key->pk.X[5].Xb.w[0]=0x53445a91842efe41;
    cred_key->pk.X[5].Xb.w[1]=0x50dfce756bad523b;
    cred_key->pk.X[5].Xb.w[2]=0xef541453e2aab2a9;
    cred_key->pk.X[5].Xb.w[3]=0x1ac2095b46be5fae;

    cred_key->pk.X[5].Ya.len=0x4;
    cred_key->pk.X[5].Ya.w[0]=0xdbaef4a92dc8c715;
    cred_key->pk.X[5].Ya.w[1]=0x9c80c13caf0fcd80;
    cred_key->pk.X[5].Ya.w[2]=0xabc45d0c599ee801;
    cred_key->pk.X[5].Ya.w[3]=0x5bb3a397c028ad0;

    cred_key->pk.X[5].Yb.len=0x4;
    cred_key->pk.X[5].Yb.w[0]=0xa722e6bff3e97f5c;
    cred_key->pk.X[5].Yb.w[1]=0xcbeb9209b671d667;
    cred_key->pk.X[5].Yb.w[2]=0xd0bcccbefc08bbf8;
    cred_key->pk.X[5].Yb.w[3]=0x94287854081da2c;

    cred_key->pk.X[5].Za.len=0x1;
    cred_key->pk.X[5].Za.w[0]=0x1;

    cred_key->pk.X[5].Zb.len=0x0;
    /***********************/
    cred_key->pk.X[6].Xa.len=0x4;
    cred_key->pk.X[6].Xa.w[0]=0xc3415b5a3262d37e;
    cred_key->pk.X[6].Xa.w[1]=0xbf75597e5b9c74a;
    cred_key->pk.X[6].Xa.w[2]=0x93f29e5ef7bf64b4;
    cred_key->pk.X[6].Xa.w[3]=0x1389c34faa03ad65;

    cred_key->pk.X[6].Xb.len=0x4;
    cred_key->pk.X[6].Xb.w[0]=0xd68e3b5ba96adbb7;
    cred_key->pk.X[6].Xb.w[1]=0x26d54a4d95ec5219;
    cred_key->pk.X[6].Xb.w[2]=0xb8991bfc02b6c09c;
    cred_key->pk.X[6].Xb.w[3]=0x21bf8443e774f445;

    cred_key->pk.X[6].Ya.len=0x4;
    cred_key->pk.X[6].Ya.w[0]=0xfc501f445735b695;
    cred_key->pk.X[6].Ya.w[1]=0x6cb26852233920da;
    cred_key->pk.X[6].Ya.w[2]=0xc74e8cc2472b3fbb;
    cred_key->pk.X[6].Ya.w[3]=0x14cb5e0b0731c520;

    cred_key->pk.X[6].Yb.len=0x4;
    cred_key->pk.X[6].Yb.w[0]=0x58e8d6857588e1e7;
    cred_key->pk.X[6].Yb.w[1]=0x4f331b43e8622587;
    cred_key->pk.X[6].Yb.w[2]=0x96bbd2996a08f2ed;
    cred_key->pk.X[6].Yb.w[3]=0x22d6e44805d90aa0;

    cred_key->pk.X[6].Za.len=0x1;
    cred_key->pk.X[6].Za.w[0]=0x1;

    cred_key->pk.X[6].Zb.len=0x0;
    /*****************************/

    cred_key->sk.y[0].len=0x4;
    cred_key->sk.y[0].w[0]=0x3e42d9b916d03025;
    cred_key->sk.y[0].w[1]=0x5ba83c165c2dd993;
    cred_key->sk.y[0].w[2]=0xf88f436b594ebf0d;
    cred_key->sk.y[0].w[3]=0xa0e02699cfbf665a;

    cred_key->sk.y[1].len=0x4;
    cred_key->sk.y[1].w[0]=0xc249f03df518c67d;
    cred_key->sk.y[1].w[1]=0xc6c5d027b7739a54;
    cred_key->sk.y[1].w[2]=0x5153af7512a5cb12;
    cred_key->sk.y[1].w[3]=0x95d4df76e4844610;

    cred_key->sk.y[2].len=0x4;
    cred_key->sk.y[2].w[0]=0x5e94042c611cd91f;
    cred_key->sk.y[2].w[1]=0xe684c5d404a1cc18;
    cred_key->sk.y[2].w[2]=0x627427bddce71869;
    cred_key->sk.y[2].w[3]=0xa6fd13c4dd309ae3;

    cred_key->sk.y[3].len=0x4;
    cred_key->sk.y[3].w[0]=0xecfb8b66855ef5d;
    cred_key->sk.y[3].w[1]=0x7658b8d451596c1d;
    cred_key->sk.y[3].w[2]=0x7529df3ea033539;
    cred_key->sk.y[3].w[3]=0x8d86065ed77fd0cb;

    cred_key->sk.y[4].len=0x4;
    cred_key->sk.y[4].w[0]=0x21d03cfc83c5799b;
    cred_key->sk.y[4].w[1]=0x66d1b0f0a961379f;
    cred_key->sk.y[4].w[2]=0x477b1ea5207701c7;
    cred_key->sk.y[4].w[3]=0xd0997f915caeddb3;

    cred_key->sk.y[5].len=0x4;
    cred_key->sk.y[5].w[0]=0x9b883c0a400db5c0;
    cred_key->sk.y[5].w[1]=0x69b82d43b27ce6de;
    cred_key->sk.y[5].w[2]=0x59bd8f16445977cf;
    cred_key->sk.y[5].w[3]=0x9a917ee9df252f48;

    cred_key->sk.y[6].len=0x4;
    cred_key->sk.y[6].w[0]=0xac41e690d6db20f4;
    cred_key->sk.y[6].w[1]=0xbcf34aa815d81e07;
    cred_key->sk.y[6].w[2]=0x833ae265dea2801b;
    cred_key->sk.y[6].w[3]=0xc395fe0e970312e7;
#endif
#if 0
    for(int i=0;i<FAC_PARA_N+2;i++)
    {
        for(int j=0;j<FAC_PARA_N+2;j++)
        {
            BNT.Trf_G1_to_Char(cred_key2.cred_key.pk.Z[i][j],cred_key->pk.Z[i][j]);
            BNT.bn_printfG1("cred_key->pk.Z[i][j]",cred_key->pk.Z[i][j]);
        }
    }
#else
    //////0
    cred_key->pk.Z[0][0].X.len=0x4;
    cred_key->pk.Z[0][0].X.w[0]=0xdc6033c18e7213b7;
    cred_key->pk.Z[0][0].X.w[1]=0x85afbc4b09ed5259;
    cred_key->pk.Z[0][0].X.w[2]=0x181abb4634eb43d6;
    cred_key->pk.Z[0][0].X.w[3]=0xe6c4f936e3e87d4;

    cred_key->pk.Z[0][0].Y.len=0x4;
    cred_key->pk.Z[0][0].Y.w[0]=0x20e7ab6d03023540;
    cred_key->pk.Z[0][0].Y.w[1]=0x50797bd1f9241b2e;
    cred_key->pk.Z[0][0].Y.w[2]=0xb352386928491f81;
    cred_key->pk.Z[0][0].Y.w[3]=0xf50c153e4ec3a2;

    cred_key->pk.Z[0][0].Z.len=0x1;
    cred_key->pk.Z[0][0].Z.w[0]=0x1;

    cred_key->pk.Z[0][1].X.len=0x4;
    cred_key->pk.Z[0][1].X.w[0]=0xf5a2ab833a9f8778;
    cred_key->pk.Z[0][1].X.w[1]=0x35e976ea06c27f40;
    cred_key->pk.Z[0][1].X.w[2]=0x1d6a010df90ffa81;
    cred_key->pk.Z[0][1].X.w[3]=0xad3e0cf09656913;

    cred_key->pk.Z[0][1].Y.len=0x4;
    cred_key->pk.Z[0][1].Y.w[0]=0xf9e8a93e5a1674bf;
    cred_key->pk.Z[0][1].Y.w[1]=0x32efd80d402b30fe;
    cred_key->pk.Z[0][1].Y.w[2]=0xcc6f7d0458ac3858;
    cred_key->pk.Z[0][1].Y.w[3]=0x16c44533ea05e00c;

    cred_key->pk.Z[0][1].Z.len=0x4;
    cred_key->pk.Z[0][1].Z.w[0]=0x39588ca7c0ac6d64;
    cred_key->pk.Z[0][1].Z.w[1]=0x6e08b4e51adfa62c;
    cred_key->pk.Z[0][1].Z.w[2]=0x1d49dbeb267c4286;
    cred_key->pk.Z[0][1].Z.w[3]=0x19069aaf6891f04c;


    cred_key->pk.Z[0][2].X.len=0x4;
    cred_key->pk.Z[0][2].X.w[0]=0xef7213be36dd2807;
    cred_key->pk.Z[0][2].X.w[1]=0x31a3d51ca7c282d8;
    cred_key->pk.Z[0][2].X.w[2]=0xa500e28786ebb8dc;
    cred_key->pk.Z[0][2].X.w[3]=0x1e76cd59d0133d80;

    cred_key->pk.Z[0][2].Y.len=0x4;
    cred_key->pk.Z[0][2].Y.w[0]=0x207b7dbfc1dedc9b;
    cred_key->pk.Z[0][2].Y.w[1]=0xeb8745673ee0f8bf;
    cred_key->pk.Z[0][2].Y.w[2]=0xc698e5f8260c1f84;
    cred_key->pk.Z[0][2].Y.w[3]=0x17a8a3c78de2e78f;

    cred_key->pk.Z[0][2].Z.len=0x4;
    cred_key->pk.Z[0][2].Z.w[0]=0x350abaa8557e435a;
    cred_key->pk.Z[0][2].Z.w[1]=0x5920258e12209782;
    cred_key->pk.Z[0][2].Z.w[2]=0x81bf8243285b6e43;
    cred_key->pk.Z[0][2].Z.w[3]=0x10f4cae3d50ae320;

    cred_key->pk.Z[0][3].X.len=0x4;
    cred_key->pk.Z[0][3].X.w[0]=0xfc8b4132192ff17b;
    cred_key->pk.Z[0][3].X.w[1]=0xa9c9b841e5aa9093;
    cred_key->pk.Z[0][3].X.w[2]=0x7cd61c3767a22282;
    cred_key->pk.Z[0][3].X.w[3]=0x23b9f2db2f7b33ce;

    cred_key->pk.Z[0][3].Y.len=0x4;
    cred_key->pk.Z[0][3].Y.w[0]=0x7d73a40123cd3e41;
    cred_key->pk.Z[0][3].Y.w[1]=0xa8790512efecf04b;
    cred_key->pk.Z[0][3].Y.w[2]=0x1504245c523b939d;
    cred_key->pk.Z[0][3].Y.w[3]=0x225981a705566a1a;

    cred_key->pk.Z[0][3].Z.len=0x4;
    cred_key->pk.Z[0][3].Z.w[0]=0x36e4cdcdc09d71d1;
    cred_key->pk.Z[0][3].Z.w[1]=0xbb18896160dfdfc6;
    cred_key->pk.Z[0][3].Z.w[2]=0x81b38aacd981d06b;
    cred_key->pk.Z[0][3].Z.w[3]=0x1c9adb130fd127b3;

    cred_key->pk.Z[0][4].X.len=0x4;
    cred_key->pk.Z[0][4].X.w[0]=0xf95cf1c213f1737b;
    cred_key->pk.Z[0][4].X.w[1]=0x43e1e4fa87f802bd;
    cred_key->pk.Z[0][4].X.w[2]=0xf46575fe75d6f5d0;
    cred_key->pk.Z[0][4].X.w[3]=0x14282ccd5fddb531;

    cred_key->pk.Z[0][4].Y.len=0x4;
    cred_key->pk.Z[0][4].Y.w[0]=0x170201e6acc6a00a;
    cred_key->pk.Z[0][4].Y.w[1]=0xeced074e43dc9e8f;
    cred_key->pk.Z[0][4].Y.w[2]=0xd05262e57d129bcc;
    cred_key->pk.Z[0][4].Y.w[3]=0x1717518c46da0ecb;

    cred_key->pk.Z[0][4].Z.len=0x4;
    cred_key->pk.Z[0][4].Z.w[0]=0xa4d7253398bfa5f7;
    cred_key->pk.Z[0][4].Z.w[1]=0xa02bfa7786ddb7fd;
    cred_key->pk.Z[0][4].Z.w[2]=0x73224b882ef908e3;
    cred_key->pk.Z[0][4].Z.w[3]=0x1129c605ff74ad0f;

    cred_key->pk.Z[0][5].X.len=0x4;
    cred_key->pk.Z[0][5].X.w[0]=0x943dee048adfa84e;
    cred_key->pk.Z[0][5].X.w[1]=0xbc797072609d281b;
    cred_key->pk.Z[0][5].X.w[2]=0x8165443407035e0b;
    cred_key->pk.Z[0][5].X.w[3]=0x4dc0e81966b027d;

    cred_key->pk.Z[0][5].Y.len=0x4;
    cred_key->pk.Z[0][5].Y.w[0]=0xd2742f7d0cab0c50;
    cred_key->pk.Z[0][5].Y.w[1]=0xa08ee55821f881f;
    cred_key->pk.Z[0][5].Y.w[2]=0xaaba3144fdeaba09;
    cred_key->pk.Z[0][5].Y.w[3]=0x18d295e42cc8f59d;

    cred_key->pk.Z[0][5].Z.len=0x4;
    cred_key->pk.Z[0][5].Z.w[0]=0xa32fc994a0251d35;
    cred_key->pk.Z[0][5].Z.w[1]=0x5b01b3177afe7a4f;
    cred_key->pk.Z[0][5].Z.w[2]=0x681af956ac2f727f;
    cred_key->pk.Z[0][5].Z.w[3]=0x10494f3032258801;

    cred_key->pk.Z[0][6].X.len=0x4;
    cred_key->pk.Z[0][6].X.w[0]=0x6a7d032d847233e4;
    cred_key->pk.Z[0][6].X.w[1]=0x428a7a7cf2d4d403;
    cred_key->pk.Z[0][6].X.w[2]=0xb1c054036552b767;
    cred_key->pk.Z[0][6].X.w[3]=0x19d065426e84f89b;

    cred_key->pk.Z[0][6].Y.len=0x4;
    cred_key->pk.Z[0][6].Y.w[0]=0x599a69a9f564c10;
    cred_key->pk.Z[0][6].Y.w[1]=0xa8a4d3d2081cbd9e;
    cred_key->pk.Z[0][6].Y.w[2]=0x71e5523e305ce7e5;
    cred_key->pk.Z[0][6].Y.w[3]=0x14affdc47047cc58;

    cred_key->pk.Z[0][6].Z.len=0x4;
    cred_key->pk.Z[0][6].Z.w[0]=0xd1e18dc4cb482f28;
    cred_key->pk.Z[0][6].Z.w[1]=0xc47165b42e91b34d;
    cred_key->pk.Z[0][6].Z.w[2]=0x40b95552369b7189;
    cred_key->pk.Z[0][6].Z.w[3]=0x37a285e08d78080;

    /**************************1*/
    cred_key->pk.Z[1][0].X.len=0x4;
    cred_key->pk.Z[1][0].X.w[0]=0x441eb60ee622668d;
    cred_key->pk.Z[1][0].X.w[1]=0xacdbcf2cd9470244;
    cred_key->pk.Z[1][0].X.w[2]=0x2d8292b8e0d7ff5f;
    cred_key->pk.Z[1][0].X.w[3]=0x124bdcd82efb123a;

    cred_key->pk.Z[1][0].Y.len=0x4;
    cred_key->pk.Z[1][0].Y.w[0]=0x1ad31a68ae2bf4be;
    cred_key->pk.Z[1][0].Y.w[1]=0xbfc154bc0bd1975b;
    cred_key->pk.Z[1][0].Y.w[2]=0x72b8a59011736230;
    cred_key->pk.Z[1][0].Y.w[3]=0x116d3626a789a3e6;

    cred_key->pk.Z[1][0].Z.len=0x4;
    cred_key->pk.Z[1][0].Z.w[0]=0x9b1c31b38f01da76;
    cred_key->pk.Z[1][0].Z.w[1]=0xcc6e2680f9565ea4;
    cred_key->pk.Z[1][0].Z.w[2]=0x2350d409372c9a1e;
    cred_key->pk.Z[1][0].Z.w[3]=0x1be9aa812b60a04c;

    cred_key->pk.Z[1][1].X.len=0x4;
    cred_key->pk.Z[1][1].X.w[0]=0xdc6033c18e7213b7;
    cred_key->pk.Z[1][1].X.w[1]=0x85afbc4b09ed5259;
    cred_key->pk.Z[1][1].X.w[2]=0x181abb4634eb43d6;
    cred_key->pk.Z[1][1].X.w[3]=0xe6c4f936e3e87d4;

    cred_key->pk.Z[1][1].Y.len=0x4;
    cred_key->pk.Z[1][1].Y.w[0]=0x20e7ab6d03023540;
    cred_key->pk.Z[1][1].Y.w[1]=0x50797bd1f9241b2e;
    cred_key->pk.Z[1][1].Y.w[2]=0xb352386928491f81;
    cred_key->pk.Z[1][1].Y.w[3]=0xf50c153e4ec3a2;

    cred_key->pk.Z[1][1].Z.len=0x1;
    cred_key->pk.Z[1][1].Z.w[0]=0x1;

    cred_key->pk.Z[1][2].X.len=0x4;
    cred_key->pk.Z[1][2].X.w[0]=0xe280d3dec11a791e;
    cred_key->pk.Z[1][2].X.w[1]=0xde53d8faf8ed51c3;
    cred_key->pk.Z[1][2].X.w[2]=0x45acfaebfedca82b;
    cred_key->pk.Z[1][2].X.w[3]=0x10744f686b2b19a3;

    cred_key->pk.Z[1][2].Y.len=0x4;
    cred_key->pk.Z[1][2].Y.w[0]=0x3357969e9005aaad;
    cred_key->pk.Z[1][2].Y.w[1]=0xd5f94b394845f167;
    cred_key->pk.Z[1][2].Y.w[2]=0xf6f9abb093d6466c;
    cred_key->pk.Z[1][2].Y.w[3]=0xb483dffd46ca4cc;

    cred_key->pk.Z[1][2].Z.len=0x4;
    cred_key->pk.Z[1][2].Z.w[0]=0xe4e686a37d82f7e4;
    cred_key->pk.Z[1][2].Z.w[1]=0xf55757b665bfcfb6;
    cred_key->pk.Z[1][2].Z.w[2]=0x82255c142a8e2c25;
    cred_key->pk.Z[1][2].Z.w[3]=0x929724632cf1a32;


    cred_key->pk.Z[1][3].X.len=0x4;
    cred_key->pk.Z[1][3].X.w[0]=0xdc006199aeb72f;
    cred_key->pk.Z[1][3].X.w[1]=0xd73c952169919b09;
    cred_key->pk.Z[1][3].X.w[2]=0xa41ceb5351902709;
    cred_key->pk.Z[1][3].X.w[3]=0x141d8fd76daaa9ea;

    cred_key->pk.Z[1][3].Y.len=0x4;
    cred_key->pk.Z[1][3].Y.w[0]=0xf1d34e69ef3b8c01;
    cred_key->pk.Z[1][3].Y.w[1]=0x86df90ab6dd9a4c9;
    cred_key->pk.Z[1][3].Y.w[2]=0x2b54cd51547f42e8;
    cred_key->pk.Z[1][3].Y.w[3]=0x15ddc036545155ed;

    cred_key->pk.Z[1][3].Z.len=0x4;
    cred_key->pk.Z[1][3].Z.w[0]=0x1d062c7285ea3f79;
    cred_key->pk.Z[1][3].Z.w[1]=0xcd5fa118e01e3e15;
    cred_key->pk.Z[1][3].Z.w[2]=0x654ecb1c5afc5602;
    cred_key->pk.Z[1][3].Z.w[3]=0x8ac7b0ee01fce3b;

    cred_key->pk.Z[1][4].X.len=0x4;
    cred_key->pk.Z[1][4].X.w[0]=0x32e87030103a064b;
    cred_key->pk.Z[1][4].X.w[1]=0xedaf64bebaea91d7;
    cred_key->pk.Z[1][4].X.w[2]=0x626cb8c563906cf9;
    cred_key->pk.Z[1][4].X.w[3]=0x23fefd03f296ef4;

    cred_key->pk.Z[1][4].Y.len=0x4;
    cred_key->pk.Z[1][4].Y.w[0]=0x2c31d05dbc9e9871;
    cred_key->pk.Z[1][4].Y.w[1]=0xb0e3638db8398636;
    cred_key->pk.Z[1][4].Y.w[2]=0xb5e570001b03d2e3;
    cred_key->pk.Z[1][4].Y.w[3]=0x65f73760e4dd856;

    cred_key->pk.Z[1][4].Z.len=0x4;
    cred_key->pk.Z[1][4].Z.w[0]=0xb1f17907bb0b0033;
    cred_key->pk.Z[1][4].Z.w[1]=0x68e242fff7d2cee3;
    cred_key->pk.Z[1][4].Z.w[2]=0xc3ca52802b97a3b4;
    cred_key->pk.Z[1][4].Z.w[3]=0x99377db3a99503;

    cred_key->pk.Z[1][5].X.len=0x4;
    cred_key->pk.Z[1][5].X.w[0]=0xfe5fbbeb18f28d7e;
    cred_key->pk.Z[1][5].X.w[1]=0xfc958239d512774f;
    cred_key->pk.Z[1][5].X.w[2]=0x3a4683503cb4301f;
    cred_key->pk.Z[1][5].X.w[3]=0x159c410422ab3bf1;

    cred_key->pk.Z[1][5].Y.len=0x4;
    cred_key->pk.Z[1][5].Y.w[0]=0xc8a53556b0df1415;
    cred_key->pk.Z[1][5].Y.w[1]=0x32ccc2e57cd2a48;
    cred_key->pk.Z[1][5].Y.w[2]=0xe2d617eee1f0aa1e;
    cred_key->pk.Z[1][5].Y.w[3]=0xc0fb4f70b734c85;

    cred_key->pk.Z[1][5].Z.len=0x4;
    cred_key->pk.Z[1][5].Z.w[0]=0xff20a5860f16dc1d;
    cred_key->pk.Z[1][5].Z.w[1]=0x35bd8961e86b72f5;
    cred_key->pk.Z[1][5].Z.w[2]=0x7aef491e11575ecb;
    cred_key->pk.Z[1][5].Z.w[3]=0x246bcdfdeb8df268;


    cred_key->pk.Z[1][6].X.len=0x4;
    cred_key->pk.Z[1][6].X.w[0]=0x5138b8c9d7c785e2;
    cred_key->pk.Z[1][6].X.w[1]=0x622acddc82e58d9e;
    cred_key->pk.Z[1][6].X.w[2]=0x1fc73a3c32d13779;
    cred_key->pk.Z[1][6].X.w[3]=0x1d63c664c4532b5;

    cred_key->pk.Z[1][6].Y.len=0x4;
    cred_key->pk.Z[1][6].Y.w[0]=0xa4eb106910bab31e;
    cred_key->pk.Z[1][6].Y.w[1]=0xb28db46b62daf3f7;
    cred_key->pk.Z[1][6].Y.w[2]=0x8be755c9fc81cd40;
    cred_key->pk.Z[1][6].Y.w[3]=0xf0d752704f4bee2;

    cred_key->pk.Z[1][6].Z.len=0x4;
    cred_key->pk.Z[1][6].Z.w[0]=0x1c08f52b8418226;
    cred_key->pk.Z[1][6].Z.w[1]=0x292f67395e6b8233;
    cred_key->pk.Z[1][6].Z.w[2]=0x462a4d920f6cbaf9;
    cred_key->pk.Z[1][6].Z.w[3]=0xf020d8938d971e0;
    /*********************************2**/

    cred_key->pk.Z[2][0].X.len=0x4;
    cred_key->pk.Z[2][0].X.w[0]=0x9b8ebd9e2d5fc1e;
    cred_key->pk.Z[2][0].X.w[1]=0x2e410afb10d3378e;
    cred_key->pk.Z[2][0].X.w[2]=0x1a360b9031b97f80;
    cred_key->pk.Z[2][0].X.w[3]=0x2362eb967df580a4;

    cred_key->pk.Z[2][0].Y.len=0x4;
    cred_key->pk.Z[2][0].Y.w[0]=0x6dfa0525a8c9d66;
    cred_key->pk.Z[2][0].Y.w[1]=0x3812e5ead6291ff;
    cred_key->pk.Z[2][0].Y.w[2]=0x4ba7f7d054ae2818;
    cred_key->pk.Z[2][0].Y.w[3]=0x1891e2b09f1d9dda;

    cred_key->pk.Z[2][0].Z.len=0x4;
    cred_key->pk.Z[2][0].Z.w[0]=0x2dee091db4dea0dd;
    cred_key->pk.Z[2][0].Z.w[1]=0xcf78320464e2c430;
    cred_key->pk.Z[2][0].Z.w[2]=0x599b2fe4c945a6f4;
    cred_key->pk.Z[2][0].Z.w[3]=0x15e08e54ce932c57;

    cred_key->pk.Z[2][1].X.len=0x4;
    cred_key->pk.Z[2][1].X.w[0]=0x73f2f14d1795f407;
    cred_key->pk.Z[2][1].X.w[1]=0x248fad42d820fe34;
    cred_key->pk.Z[2][1].X.w[2]=0xd878ead90235ec02;
    cred_key->pk.Z[2][1].X.w[3]=0x18952b933a9c17c7;

    cred_key->pk.Z[2][1].Y.len=0x4;
    cred_key->pk.Z[2][1].Y.w[0]=0xd5cd561e3af2162c;
    cred_key->pk.Z[2][1].Y.w[1]=0xc74d1193dc5e848;
    cred_key->pk.Z[2][1].Y.w[2]=0xad950041fd5ad009;
    cred_key->pk.Z[2][1].Y.w[3]=0xa40420feeff3cc4;

    cred_key->pk.Z[2][1].Z.len=0x4;
    cred_key->pk.Z[2][1].Z.w[0]=0xd99534f52bac8758;
    cred_key->pk.Z[2][1].Z.w[1]=0xe50a528583625ba5;
    cred_key->pk.Z[2][1].Z.w[2]=0x2d5a8541af69b727;
    cred_key->pk.Z[2][1].Z.w[3]=0x235a4c71dd533eac;

    cred_key->pk.Z[2][2].X.len=0x4;
    cred_key->pk.Z[2][2].X.w[0]=0xdc6033c18e7213b7;
    cred_key->pk.Z[2][2].X.w[1]=0x85afbc4b09ed5259;
    cred_key->pk.Z[2][2].X.w[2]=0x181abb4634eb43d6;
    cred_key->pk.Z[2][2].X.w[3]=0xe6c4f936e3e87d4;

    cred_key->pk.Z[2][2].Y.len=0x4;
    cred_key->pk.Z[2][2].Y.w[0]=0x20e7ab6d03023540;
    cred_key->pk.Z[2][2].Y.w[1]=0x50797bd1f9241b2e;
    cred_key->pk.Z[2][2].Y.w[2]=0xb352386928491f81;
    cred_key->pk.Z[2][2].Y.w[3]=0xf50c153e4ec3a2;

    cred_key->pk.Z[2][2].Z.len=0x1;
    cred_key->pk.Z[2][2].Z.w[0]=0x1;


    cred_key->pk.Z[2][3].X.len=0x4;
    cred_key->pk.Z[2][3].X.w[0]=0xe7f086b67e84984c;
    cred_key->pk.Z[2][3].X.w[1]=0xe7d86bac8612b7ec;
    cred_key->pk.Z[2][3].X.w[2]=0x4e6e2c1f5599d48;
    cred_key->pk.Z[2][3].X.w[3]=0x2752f208d6a6975;

    cred_key->pk.Z[2][3].Y.len=0x4;
    cred_key->pk.Z[2][3].Y.w[0]=0xf2ea6263cab9f0c0;
    cred_key->pk.Z[2][3].Y.w[1]=0x6eed85786352dc71;
    cred_key->pk.Z[2][3].Y.w[2]=0x724de1fcd3c1862a;
    cred_key->pk.Z[2][3].Y.w[3]=0x772ebef4f2bef2d;

    cred_key->pk.Z[2][3].Z.len=0x4;
    cred_key->pk.Z[2][3].Z.w[0]=0x3be6f0ed6abe1585;
    cred_key->pk.Z[2][3].Z.w[1]=0xf37e7ae2479dea2e;
    cred_key->pk.Z[2][3].Z.w[2]=0xc0d49b01347d6dc0;
    cred_key->pk.Z[2][3].Z.w[3]=0x342ef6d0aaa9fce;

    cred_key->pk.Z[2][4].X.len=0x4;
    cred_key->pk.Z[2][4].X.w[0]=0x56a846e8a26b4781;
    cred_key->pk.Z[2][4].X.w[1]=0x7d088a913cb9d3ae;
    cred_key->pk.Z[2][4].X.w[2]=0x17bdc9525aa60ae9;
    cred_key->pk.Z[2][4].X.w[3]=0x2257854a94040e76;

    cred_key->pk.Z[2][4].Y.len=0x4;
    cred_key->pk.Z[2][4].Y.w[0]=0x548482b6ef177608;
    cred_key->pk.Z[2][4].Y.w[1]=0x3105a34ba864587d;
    cred_key->pk.Z[2][4].Y.w[2]=0x9f2850d3fa4643a5;
    cred_key->pk.Z[2][4].Y.w[3]=0x5308fd49917252e;

    cred_key->pk.Z[2][4].Z.len=0x4;
    cred_key->pk.Z[2][4].Z.w[0]=0x1098467b866c9be5;
    cred_key->pk.Z[2][4].Z.w[1]=0x32cde7a2fbe40568;
    cred_key->pk.Z[2][4].Z.w[2]=0xc753fac8723a8de2;
    cred_key->pk.Z[2][4].Z.w[3]=0x73338e9c2d67213;

    cred_key->pk.Z[2][5].X.len=0x4;
    cred_key->pk.Z[2][5].X.w[0]=0x6d7c79ff6c2ec3c3;
    cred_key->pk.Z[2][5].X.w[1]=0x250e78bdfbf471ae;
    cred_key->pk.Z[2][5].X.w[2]=0x91dbae2ad4948088;
    cred_key->pk.Z[2][5].X.w[3]=0x3b4ecc26d5bb722;

    cred_key->pk.Z[2][5].Y.len=0x4;
    cred_key->pk.Z[2][5].Y.w[0]=0x5fa74d37432aca50;
    cred_key->pk.Z[2][5].Y.w[1]=0x640317c1c4dd874e;
    cred_key->pk.Z[2][5].Y.w[2]=0xc6d195ab2beb9a94;
    cred_key->pk.Z[2][5].Y.w[3]=0x3557810cde91f;

    cred_key->pk.Z[2][5].Z.len=0x4;
    cred_key->pk.Z[2][5].Z.w[0]=0xb62d21569edd58a5;
    cred_key->pk.Z[2][5].Z.w[1]=0x8768fcb2b2fae775;
    cred_key->pk.Z[2][5].Z.w[2]=0x6f9eb7576b043e44;
    cred_key->pk.Z[2][5].Z.w[3]=0x198d5097034d345;

    cred_key->pk.Z[2][6].X.len=0x4;
    cred_key->pk.Z[2][6].X.w[0]=0x5e76d10ed1f36665;
    cred_key->pk.Z[2][6].X.w[1]=0xa4cb29d6c0ebb2d1;
    cred_key->pk.Z[2][6].X.w[2]=0x89ff7aef88f2e213;
    cred_key->pk.Z[2][6].X.w[3]=0x5fd20b82777bf4;

    cred_key->pk.Z[2][6].Y.len=0x4;
    cred_key->pk.Z[2][6].Y.w[0]=0x6086a7e8ffc11196;
    cred_key->pk.Z[2][6].Y.w[1]=0x3783ca91bfc646c4;
    cred_key->pk.Z[2][6].Y.w[2]=0x910fbc929d0d0939;
    cred_key->pk.Z[2][6].Y.w[3]=0x19e3c26a82a873ec;

    cred_key->pk.Z[2][6].Z.len=0x4;
    cred_key->pk.Z[2][6].Z.w[0]=0x55c32797d5ba0a6a;
    cred_key->pk.Z[2][6].Z.w[1]=0x9492b9fef0924815;
    cred_key->pk.Z[2][6].Z.w[2]=0x575d20aee118db17;
    cred_key->pk.Z[2][6].Z.w[3]=0xab82f12d542b911;
    /***********************3*/

    cred_key->pk.Z[3][0].X.len=0x4;
    cred_key->pk.Z[3][0].X.w[0]=0x88363860e52c1d0f;
    cred_key->pk.Z[3][0].X.w[1]=0x90054e7f98d83f77;
    cred_key->pk.Z[3][0].X.w[2]=0x377df517e3e7fd0d;
    cred_key->pk.Z[3][0].X.w[3]=0x23ffea713e9673fa;

    cred_key->pk.Z[3][0].Y.len=0x4;
    cred_key->pk.Z[3][0].Y.w[0]=0xa0bb6658798cb5ca;
    cred_key->pk.Z[3][0].Y.w[1]=0xa100f70eb4da6219;
    cred_key->pk.Z[3][0].Y.w[2]=0x5445a6c4b0a07b58;
    cred_key->pk.Z[3][0].Y.w[3]=0x21f0f9421f64b147;

    cred_key->pk.Z[3][0].Z.len=0x4;
    cred_key->pk.Z[3][0].Z.w[0]=0x26d5da37234e1686;
    cred_key->pk.Z[3][0].Z.w[1]=0x31ad129142cc091a;
    cred_key->pk.Z[3][0].Z.w[2]=0x95ef499431d8a;
    cred_key->pk.Z[3][0].Z.w[3]=0x899409afae24092;

    cred_key->pk.Z[3][1].X.len=0x4;
    cred_key->pk.Z[3][1].X.w[0]=0x4187defa222d471;
    cred_key->pk.Z[3][1].X.w[1]=0x55e9d818e57a1f34;
    cred_key->pk.Z[3][1].X.w[2]=0x6e730fe22f6dfbac;
    cred_key->pk.Z[3][1].X.w[3]=0x1b7cab7b3be465f2;

    cred_key->pk.Z[3][1].Y.len=0x4;
    cred_key->pk.Z[3][1].Y.w[0]=0x117e6e46df7f1b37;
    cred_key->pk.Z[3][1].Y.w[1]=0xaeac79af386bb458;
    cred_key->pk.Z[3][1].Y.w[2]=0x3fb105319f0ddfb3;
    cred_key->pk.Z[3][1].Y.w[3]=0x1e9a2ca373ea0f4;

    cred_key->pk.Z[3][1].Z.len=0x4;
    cred_key->pk.Z[3][1].Z.w[0]=0xca4608bfb4d0a79f;
    cred_key->pk.Z[3][1].Z.w[1]=0x330b52ab7d1d47e0;
    cred_key->pk.Z[3][1].Z.w[2]=0xaa49931168ef382;
    cred_key->pk.Z[3][1].Z.w[3]=0x1982b93c40bd12e9;


    cred_key->pk.Z[3][2].X.len=0x4;
    cred_key->pk.Z[3][2].X.w[0]=0xf04acac566e91021;
    cred_key->pk.Z[3][2].X.w[1]=0x1fbea5c2ec4e60bb;
    cred_key->pk.Z[3][2].X.w[2]=0xb4cec4376b3405a1;
    cred_key->pk.Z[3][2].X.w[3]=0x12b51c43a984c806;

    cred_key->pk.Z[3][2].Y.len=0x4;
    cred_key->pk.Z[3][2].Y.w[0]=0x8893c2e878790037;
    cred_key->pk.Z[3][2].Y.w[1]=0xb43bdac21910f38;
    cred_key->pk.Z[3][2].Y.w[2]=0x50ac2ed935903b43;
    cred_key->pk.Z[3][2].Y.w[3]=0xc28b54b41108db5;

    cred_key->pk.Z[3][2].Z.len=0x4;
    cred_key->pk.Z[3][2].Z.w[0]=0x5a01a827f05ba931;
    cred_key->pk.Z[3][2].Z.w[1]=0x7ad1648540cdd62a;
    cred_key->pk.Z[3][2].Z.w[2]=0xa63036f537a0af38;
    cred_key->pk.Z[3][2].Z.w[3]=0x7de024162257269;

    cred_key->pk.Z[3][3].X.len=0x4;
    cred_key->pk.Z[3][3].X.w[0]=0xdc6033c18e7213b7;
    cred_key->pk.Z[3][3].X.w[1]=0x85afbc4b09ed5259;
    cred_key->pk.Z[3][3].X.w[2]=0x181abb4634eb43d6;
    cred_key->pk.Z[3][3].X.w[3]=0xe6c4f936e3e87d4;

    cred_key->pk.Z[3][3].Y.len=0x4;
    cred_key->pk.Z[3][3].Y.w[0]=0x20e7ab6d03023540;
    cred_key->pk.Z[3][3].Y.w[1]=0x50797bd1f9241b2e;
    cred_key->pk.Z[3][3].Y.w[2]=0xb352386928491f81;
    cred_key->pk.Z[3][3].Y.w[3]=0xf50c153e4ec3a2;

    cred_key->pk.Z[3][3].Z.len=0x1;
    cred_key->pk.Z[3][3].Z.w[0]=0x1;

    cred_key->pk.Z[3][4].X.len=0x4;
    cred_key->pk.Z[3][4].X.w[0]=0xb659020540575ffe;
    cred_key->pk.Z[3][4].X.w[1]=0x709ffedb56a48b72;
    cred_key->pk.Z[3][4].X.w[2]=0x530ccf75c3ca1439;
    cred_key->pk.Z[3][4].X.w[3]=0x9992f0ff668bbb7;

    cred_key->pk.Z[3][4].Y.len=0x4;
    cred_key->pk.Z[3][4].Y.w[0]=0x7c13b11bbadfda88;
    cred_key->pk.Z[3][4].Y.w[1]=0x7d5e3508aeb0402f;
    cred_key->pk.Z[3][4].Y.w[2]=0xed9ec842efadf82a;
    cred_key->pk.Z[3][4].Y.w[3]=0x11190594a52172b1;

    cred_key->pk.Z[3][4].Z.len=0x4;
    cred_key->pk.Z[3][4].Z.w[0]=0xc5e0afc42e94b84a;
    cred_key->pk.Z[3][4].Z.w[1]=0x109c53916167e189;
    cred_key->pk.Z[3][4].Z.w[2]=0xbb5eafbf584319f0;
    cred_key->pk.Z[3][4].Z.w[3]=0x1ce7286d18d89191;


    cred_key->pk.Z[3][5].X.len=0x4;
    cred_key->pk.Z[3][5].X.w[0]=0x6fcb9efd4f94cdaf;
    cred_key->pk.Z[3][5].X.w[1]=0x327b18e66d9a1161;
    cred_key->pk.Z[3][5].X.w[2]=0xa3a1618a7cc51204;
    cred_key->pk.Z[3][5].X.w[3]=0x1e45840cce97564c;

    cred_key->pk.Z[3][5].Y.len=0x4;
    cred_key->pk.Z[3][5].Y.w[0]=0xab9c9114d62eb438;
    cred_key->pk.Z[3][5].Y.w[1]=0xb6af482af9f5cb51;
    cred_key->pk.Z[3][5].Y.w[2]=0xc0ac591e36d711d4;
    cred_key->pk.Z[3][5].Y.w[3]=0x8c63d98690f0a79;

    cred_key->pk.Z[3][5].Z.len=0x4;
    cred_key->pk.Z[3][5].Z.w[0]=0x63d445dc61c32930;
    cred_key->pk.Z[3][5].Z.w[1]=0x4ada8fdc3a05a1b2;
    cred_key->pk.Z[3][5].Z.w[2]=0xc80422148d9f83ae;
    cred_key->pk.Z[3][5].Z.w[3]=0x1cd3527fafb6810e;

    cred_key->pk.Z[3][6].X.len=0x4;
    cred_key->pk.Z[3][6].X.w[0]=0xb1000ca1a61da662;
    cred_key->pk.Z[3][6].X.w[1]=0x861f9a89723aa69f;
    cred_key->pk.Z[3][6].X.w[2]=0x24ce82407a428be7;
    cred_key->pk.Z[3][6].X.w[3]=0x16ec244270752612;

    cred_key->pk.Z[3][6].Y.len=0x4;
    cred_key->pk.Z[3][6].Y.w[0]=0xd6ba2b96b4b8e8b2;
    cred_key->pk.Z[3][6].Y.w[1]=0x10fd3ceba909d69c;
    cred_key->pk.Z[3][6].Y.w[2]=0xa3888f51ef3bd66;
    cred_key->pk.Z[3][6].Y.w[3]=0x1f77fc275138eb2b;

    cred_key->pk.Z[3][6].Z.len=0x4;
    cred_key->pk.Z[3][6].Z.w[0]=0x9c6e41dea23c07b6;
    cred_key->pk.Z[3][6].Z.w[1]=0x9b70f0ae085a479e;
    cred_key->pk.Z[3][6].Z.w[2]=0x460d6e777c1fd055;
    cred_key->pk.Z[3][6].Z.w[3]=0x228c136c9f21ea0e;
    /***********************4***/

    cred_key->pk.Z[4][0].X.len=0x4;
    cred_key->pk.Z[4][0].X.w[0]=0x35972a4d3510f251;
    cred_key->pk.Z[4][0].X.w[1]=0xcff362331d7f27d6;
    cred_key->pk.Z[4][0].X.w[2]=0x74b95ad413368a43;
    cred_key->pk.Z[4][0].X.w[3]=0x1efee6bed31766a6;

    cred_key->pk.Z[4][0].Y.len=0x4;
    cred_key->pk.Z[4][0].Y.w[0]=0xc7057d59485ec736;
    cred_key->pk.Z[4][0].Y.w[1]=0xe903ddd552e80a5d;
    cred_key->pk.Z[4][0].Y.w[2]=0xea47c64c1b74f136;
    cred_key->pk.Z[4][0].Y.w[3]=0xcfa1815d2428c2d;

    cred_key->pk.Z[4][0].Z.len=0x4;
    cred_key->pk.Z[4][0].Z.w[0]=0xba964bfcd9c9d2c1;
    cred_key->pk.Z[4][0].Z.w[1]=0x5fb19be09f14494f;
    cred_key->pk.Z[4][0].Z.w[2]=0xf72c9a00522fb479;
    cred_key->pk.Z[4][0].Z.w[3]=0x2200d9045c0877b4;

    cred_key->pk.Z[4][1].X.len=0x4;
    cred_key->pk.Z[4][1].X.w[0]=0x49905b5718ef627b;
    cred_key->pk.Z[4][1].X.w[1]=0x7ea0b6aba51945f2;
    cred_key->pk.Z[4][1].X.w[2]=0xf6f5c7af01d76dee;
    cred_key->pk.Z[4][1].X.w[3]=0xc7a2686f72b4e1b;

    cred_key->pk.Z[4][1].Y.len=0x4;
    cred_key->pk.Z[4][1].Y.w[0]=0xde2c37affed422a2;
    cred_key->pk.Z[4][1].Y.w[1]=0xe4dc2af7108da02c;
    cred_key->pk.Z[4][1].Y.w[2]=0x2f068e6d08d44744;
    cred_key->pk.Z[4][1].Y.w[3]=0x3b9c5116089a93d;

    cred_key->pk.Z[4][1].Z.len=0x4;
    cred_key->pk.Z[4][1].Z.w[0]=0x1f61f0d9d68c42ed;
    cred_key->pk.Z[4][1].Z.w[1]=0x7abbb38693f48083;
    cred_key->pk.Z[4][1].Z.w[2]=0x25c234ce68162ba3;
    cred_key->pk.Z[4][1].Z.w[3]=0x710835d86d0cfe1;

    cred_key->pk.Z[4][2].X.len=0x4;
    cred_key->pk.Z[4][2].X.w[0]=0x1970570465c22649;
    cred_key->pk.Z[4][2].X.w[1]=0x1198cba8a29c2502;
    cred_key->pk.Z[4][2].X.w[2]=0x5adcb20cc7ed4472;
    cred_key->pk.Z[4][2].X.w[3]=0x12b1c05736d87ee3;

    cred_key->pk.Z[4][2].Y.len=0x4;
    cred_key->pk.Z[4][2].Y.w[0]=0xce201d8a7ed39163;
    cred_key->pk.Z[4][2].Y.w[1]=0xa4361a4399fb3e37;
    cred_key->pk.Z[4][2].Y.w[2]=0xdefe21634fc1c97b;
    cred_key->pk.Z[4][2].Y.w[3]=0x10d5e7f66cf2dccf;

    cred_key->pk.Z[4][2].Z.len=0x4;
    cred_key->pk.Z[4][2].Z.w[0]=0x9116daab40e38324;
    cred_key->pk.Z[4][2].Z.w[1]=0xbdf5beffb4ac675e;
    cred_key->pk.Z[4][2].Z.w[2]=0xffc6b95229d14ae2;
    cred_key->pk.Z[4][2].Z.w[3]=0x1879beb80cafb90a;

    cred_key->pk.Z[4][3].X.len=0x4;
    cred_key->pk.Z[4][3].X.w[0]=0x903f1127cc45f2fc;
    cred_key->pk.Z[4][3].X.w[1]=0x4b16f4a52e059a88;
    cred_key->pk.Z[4][3].X.w[2]=0xd69af5fb9a0c6886;
    cred_key->pk.Z[4][3].X.w[3]=0x1a1cce85ac8e09f9;

    cred_key->pk.Z[4][3].Y.len=0x4;
    cred_key->pk.Z[4][3].Y.w[0]=0xd64d15786f883666;
    cred_key->pk.Z[4][3].Y.w[1]=0x3ef5cfe89a68d654;
    cred_key->pk.Z[4][3].Y.w[2]=0xb220a58f73f06c29;
    cred_key->pk.Z[4][3].Y.w[3]=0xd24241fcd892b78;

    cred_key->pk.Z[4][3].Z.len=0x4;
    cred_key->pk.Z[4][3].Z.w[0]=0x6b7e52b42f7eca19;
    cred_key->pk.Z[4][3].Z.w[1]=0xbe0ff29d9d87ad04;
    cred_key->pk.Z[4][3].Z.w[2]=0x4e92e1f251cf551a;
    cred_key->pk.Z[4][3].Z.w[3]=0x11085d50a362aea5;


    cred_key->pk.Z[4][4].X.len=0x4;
    cred_key->pk.Z[4][4].X.w[0]=0xdc6033c18e7213b7;
    cred_key->pk.Z[4][4].X.w[1]=0x85afbc4b09ed5259;
    cred_key->pk.Z[4][4].X.w[2]=0x181abb4634eb43d6;
    cred_key->pk.Z[4][4].X.w[3]=0xe6c4f936e3e87d4;

    cred_key->pk.Z[4][4].Y.len=0x4;
    cred_key->pk.Z[4][4].Y.w[0]=0x20e7ab6d03023540;
    cred_key->pk.Z[4][4].Y.w[1]=0x50797bd1f9241b2e;
    cred_key->pk.Z[4][4].Y.w[2]=0xb352386928491f81;
    cred_key->pk.Z[4][4].Y.w[3]=0xf50c153e4ec3a2;

    cred_key->pk.Z[4][4].Z.len=0x1;
    cred_key->pk.Z[4][4].Z.w[0]=0x1;

    cred_key->pk.Z[4][5].X.len=0x4;
    cred_key->pk.Z[4][5].X.w[0]=0x33e742b7d624aa8d;
    cred_key->pk.Z[4][5].X.w[1]=0xe252a6cb9374cba6;
    cred_key->pk.Z[4][5].X.w[2]=0x4948d3bc3abd4f8f;
    cred_key->pk.Z[4][5].X.w[3]=0x179b839aa558077c;

    cred_key->pk.Z[4][5].Y.len=0x4;
    cred_key->pk.Z[4][5].Y.w[0]=0x87f5fe0a812385a6;
    cred_key->pk.Z[4][5].Y.w[1]=0x36a84fc0cad1e63b;
    cred_key->pk.Z[4][5].Y.w[2]=0x1e28eee486a0bc5f;
    cred_key->pk.Z[4][5].Y.w[3]=0x160162e48c90c59c;

    cred_key->pk.Z[4][5].Z.len=0x4;
    cred_key->pk.Z[4][5].Z.w[0]=0x63d84bb7f01b80d6;
    cred_key->pk.Z[4][5].Z.w[1]=0x410f0ee581041afd;
    cred_key->pk.Z[4][5].Z.w[2]=0x25dacd53910dc053;
    cred_key->pk.Z[4][5].Z.w[3]=0x249190fbc914b6b6;

    cred_key->pk.Z[4][6].X.len=0x4;
    cred_key->pk.Z[4][6].X.w[0]=0x39631f577c086e04;
    cred_key->pk.Z[4][6].X.w[1]=0x8ed8b365a72864df;
    cred_key->pk.Z[4][6].X.w[2]=0xd6e8d96ccaff5a69;
    cred_key->pk.Z[4][6].X.w[3]=0x8f430faef3a620a;

    cred_key->pk.Z[4][6].Y.len=0x4;
    cred_key->pk.Z[4][6].Y.w[0]=0x30f5ab685a26921a;
    cred_key->pk.Z[4][6].Y.w[1]=0xa3b476d2893d77fc;
    cred_key->pk.Z[4][6].Y.w[2]=0x23065e6ba66bf706;
    cred_key->pk.Z[4][6].Y.w[3]=0x747534a518512d4;

    cred_key->pk.Z[4][6].Z.len=0x4;
    cred_key->pk.Z[4][6].Z.w[0]=0x82e2824c55a84460;
    cred_key->pk.Z[4][6].Z.w[1]=0x8c6b3d30399e5b9a;
    cred_key->pk.Z[4][6].Z.w[2]=0xb6654704f7350d70;
    cred_key->pk.Z[4][6].Z.w[3]=0x247bc9f2a9391720;
    /********************/

    cred_key->pk.Z[5][0].X.len=0x4;
    cred_key->pk.Z[5][0].X.w[0]=0x640b12c3bb521924;
    cred_key->pk.Z[5][0].X.w[1]=0xca1a3c47f25409e;
    cred_key->pk.Z[5][0].X.w[2]=0x1067ed32eda201bf;
    cred_key->pk.Z[5][0].X.w[3]=0x1c0b691eeb907f25;

    cred_key->pk.Z[5][0].Y.len=0x4;
    cred_key->pk.Z[5][0].Y.w[0]=0x5027d404ae89db2d;
    cred_key->pk.Z[5][0].Y.w[1]=0x895d8c99970ea20c;
    cred_key->pk.Z[5][0].Y.w[2]=0xe664b62b556bfbc3;
    cred_key->pk.Z[5][0].Y.w[3]=0x964916d580aa89;

    cred_key->pk.Z[5][0].Z.len=0x4;
    cred_key->pk.Z[5][0].Z.w[0]=0xf4ae5b1a4bf158dd;
    cred_key->pk.Z[5][0].Z.w[1]=0xc8acac94bcd52a57;
    cred_key->pk.Z[5][0].Z.w[2]=0x4a388a3706fc4631;
    cred_key->pk.Z[5][0].Z.w[3]=0x23f534799ce1520d;

    cred_key->pk.Z[5][1].X.len=0x4;
    cred_key->pk.Z[5][1].X.w[0]=0x5bd999dc85a243d5;
    cred_key->pk.Z[5][1].X.w[1]=0xd50e5c38d397ec23;
    cred_key->pk.Z[5][1].X.w[2]=0x96bf650a3e823c23;
    cred_key->pk.Z[5][1].X.w[3]=0xe051f2aae694d3;

    cred_key->pk.Z[5][1].Y.len=0x4;
    cred_key->pk.Z[5][1].Y.w[0]=0x361b93c7278705f8;
    cred_key->pk.Z[5][1].Y.w[1]=0xa50ff498aa33ce0d;
    cred_key->pk.Z[5][1].Y.w[2]=0x724915db06091fcf;
    cred_key->pk.Z[5][1].Y.w[3]=0x552ae9fa7d53d74;

    cred_key->pk.Z[5][1].Z.len=0x4;
    cred_key->pk.Z[5][1].Z.w[0]=0xdef70617a9b5f24f;
    cred_key->pk.Z[5][1].Z.w[1]=0x14fecc79133e365b;
    cred_key->pk.Z[5][1].Z.w[2]=0xdb70dbba72755594;
    cred_key->pk.Z[5][1].Z.w[3]=0x1f589877a20b14d0;

    cred_key->pk.Z[5][2].X.len=0x4;
    cred_key->pk.Z[5][2].X.w[0]=0x6e40d13a5f52f603;
    cred_key->pk.Z[5][2].X.w[1]=0xf9956242964f6d77;
    cred_key->pk.Z[5][2].X.w[2]=0x1fbdba0585bfc2b8;
    cred_key->pk.Z[5][2].X.w[3]=0x1e29ea3a30966fb7;

    cred_key->pk.Z[5][2].Y.len=0x4;
    cred_key->pk.Z[5][2].Y.w[0]=0x2a65e5b158252090;
    cred_key->pk.Z[5][2].Y.w[1]=0xafcbf4ada177f394;
    cred_key->pk.Z[5][2].Y.w[2]=0xbca76c5dc8c5fc5c;
    cred_key->pk.Z[5][2].Y.w[3]=0x1ab17262803a6ae1;

    cred_key->pk.Z[5][2].Z.len=0x4;
    cred_key->pk.Z[5][2].Z.w[0]=0xa0c82778d302f0f6;
    cred_key->pk.Z[5][2].Z.w[1]=0x916e52864a17c61b;
    cred_key->pk.Z[5][2].Z.w[2]=0x1e0920389e4aa592;
    cred_key->pk.Z[5][2].Z.w[3]=0x1cb80916ee6719ee;

    cred_key->pk.Z[5][3].X.len=0x4;
    cred_key->pk.Z[5][3].X.w[0]=0x83b8e1f6d85ec0c3;
    cred_key->pk.Z[5][3].X.w[1]=0xb082d7d8ef62f13;
    cred_key->pk.Z[5][3].X.w[2]=0xf6bc3804a7a43283;
    cred_key->pk.Z[5][3].X.w[3]=0x17da105273c90ca4;

    cred_key->pk.Z[5][3].Y.len=0x4;
    cred_key->pk.Z[5][3].Y.w[0]=0xee1964b7a5ddd602;
    cred_key->pk.Z[5][3].Y.w[1]=0x533c16c410730fdd;
    cred_key->pk.Z[5][3].Y.w[2]=0x7200cf72ade637bc;
    cred_key->pk.Z[5][3].Y.w[3]=0x10a918ef0f9ace5c;

    cred_key->pk.Z[5][3].Z.len=0x4;
    cred_key->pk.Z[5][3].Z.w[0]=0x68c6de69646da532;
    cred_key->pk.Z[5][3].Z.w[1]=0xc88aaf55e1a5e742;
    cred_key->pk.Z[5][3].Z.w[2]=0x21e1d256b23f0fb5;
    cred_key->pk.Z[5][3].Z.w[3]=0x109ec364e9af27d;

    cred_key->pk.Z[5][4].X.len=0x4;
    cred_key->pk.Z[5][4].X.w[0]=0xe55e98e7f7ea381d;
    cred_key->pk.Z[5][4].X.w[1]=0x3e1450ce39185027;
    cred_key->pk.Z[5][4].X.w[2]=0xa756b01e5dc36065;
    cred_key->pk.Z[5][4].X.w[3]=0x193b5dcc7273d602;

    cred_key->pk.Z[5][4].Y.len=0x4;
    cred_key->pk.Z[5][4].Y.w[0]=0xa8801601c912d79a;
    cred_key->pk.Z[5][4].Y.w[1]=0x75f7f6ca103013a4;
    cred_key->pk.Z[5][4].Y.w[2]=0xe2f64017c5eebc4c;
    cred_key->pk.Z[5][4].Y.w[3]=0x20e7f3e871975ed6;

    cred_key->pk.Z[5][4].Z.len=0x4;
    cred_key->pk.Z[5][4].Z.w[0]=0x1f70d9f534132882;
    cred_key->pk.Z[5][4].Z.w[1]=0xbf143f18f58a4cc;
    cred_key->pk.Z[5][4].Z.w[2]=0x6d9dba1249e8355e;
    cred_key->pk.Z[5][4].Z.w[3]=0x7d6ac50af6a4268;

    cred_key->pk.Z[5][5].X.len=0x4;
    cred_key->pk.Z[5][5].X.w[0]=0xdc6033c18e7213b7;
    cred_key->pk.Z[5][5].X.w[1]=0x85afbc4b09ed5259;
    cred_key->pk.Z[5][5].X.w[2]=0x181abb4634eb43d6;
    cred_key->pk.Z[5][5].X.w[3]=0xe6c4f936e3e87d4;

    cred_key->pk.Z[5][5].Y.len=0x4;
    cred_key->pk.Z[5][5].Y.w[0]=0x20e7ab6d03023540;
    cred_key->pk.Z[5][5].Y.w[1]=0x50797bd1f9241b2e;
    cred_key->pk.Z[5][5].Y.w[2]=0xb352386928491f81;
    cred_key->pk.Z[5][5].Y.w[3]=0xf50c153e4ec3a2;

    cred_key->pk.Z[5][5].Z.len=0x1;
    cred_key->pk.Z[5][5].Z.w[0]=0x1;

    cred_key->pk.Z[5][6].X.len=0x4;
    cred_key->pk.Z[5][6].X.w[0]=0xbdb10b6e5f46bc33;
    cred_key->pk.Z[5][6].X.w[1]=0x3a2022d86cdbb21c;
    cred_key->pk.Z[5][6].X.w[2]=0x81a902e58ac6b96e;
    cred_key->pk.Z[5][6].X.w[3]=0x8b0ff9efd26166c;

    cred_key->pk.Z[5][6].Y.len=0x4;
    cred_key->pk.Z[5][6].Y.w[0]=0x3b2ab37c242dac9c;
    cred_key->pk.Z[5][6].Y.w[1]=0xd4ff32c033e78835;
    cred_key->pk.Z[5][6].Y.w[2]=0xb6d9a60d73cfee3f;
    cred_key->pk.Z[5][6].Y.w[3]=0xb6a006acf4aae0c;

    cred_key->pk.Z[5][6].Z.len=0x4;
    cred_key->pk.Z[5][6].Z.w[0]=0xf238e02865fdb08b;
    cred_key->pk.Z[5][6].Z.w[1]=0xa525deeb795b89f2;
    cred_key->pk.Z[5][6].Z.w[2]=0x3ff429231d6f48ea;
    cred_key->pk.Z[5][6].Z.w[3]=0x23d7dc6e289f01d1;
    /***************************/

    cred_key->pk.Z[6][0].X.len=0x4;
    cred_key->pk.Z[6][0].X.w[0]=0x13e460e9a0a8095f;
    cred_key->pk.Z[6][0].X.w[1]=0xfb6495a3de29511d;
    cred_key->pk.Z[6][0].X.w[2]=0xdac542d35ac0f06e;
    cred_key->pk.Z[6][0].X.w[3]=0x920cba81066d092;

    cred_key->pk.Z[6][0].Y.len=0x4;
    cred_key->pk.Z[6][0].Y.w[0]=0x64fe395359c5730a;
    cred_key->pk.Z[6][0].Y.w[1]=0x2d056b26cf6174e6;
    cred_key->pk.Z[6][0].Y.w[2]=0xde5e6e985ac38b3c;
    cred_key->pk.Z[6][0].Y.w[3]=0x5f36701389ead4a;

    cred_key->pk.Z[6][0].Z.len=0x4;
    cred_key->pk.Z[6][0].Z.w[0]=0xe0cc6df6d806667e;
    cred_key->pk.Z[6][0].Z.w[1]=0xda2ee45c3c173283;
    cred_key->pk.Z[6][0].Z.w[2]=0x605b832e95c7d61f;
    cred_key->pk.Z[6][0].Z.w[3]=0x225fd77859d71b21;

    cred_key->pk.Z[6][1].X.len=0x4;
    cred_key->pk.Z[6][1].X.w[0]=0xc18d86edf88a9806;
    cred_key->pk.Z[6][1].X.w[1]=0xc358b420417cef23;
    cred_key->pk.Z[6][1].X.w[2]=0xbaeceda06805c77f;
    cred_key->pk.Z[6][1].X.w[3]=0x4124942b6e71919;

    cred_key->pk.Z[6][1].Y.len=0x4;
    cred_key->pk.Z[6][1].Y.w[0]=0x51e4e4f41e795eef;
    cred_key->pk.Z[6][1].Y.w[1]=0xde03abeaaf207e9b;
    cred_key->pk.Z[6][1].Y.w[2]=0xf8107f44e94d28ec;
    cred_key->pk.Z[6][1].Y.w[3]=0x1b463e13796ac09;

    cred_key->pk.Z[6][1].Z.len=0x4;
    cred_key->pk.Z[6][1].Z.w[0]=0x13f0d8e5b064a152;
    cred_key->pk.Z[6][1].Z.w[1]=0x656bae82e350d9f4;
    cred_key->pk.Z[6][1].Z.w[2]=0xf14e74de04b06b28;
    cred_key->pk.Z[6][1].Z.w[3]=0x13d0085474aa9654;

    cred_key->pk.Z[6][2].X.len=0x4;
    cred_key->pk.Z[6][2].X.w[0]=0xf5a17757dd1df6c6;
    cred_key->pk.Z[6][2].X.w[1]=0x59ce516659043a68;
    cred_key->pk.Z[6][2].X.w[2]=0x559543a77260b6ee;
    cred_key->pk.Z[6][2].X.w[3]=0x2262bb47d7b86b0d;

    cred_key->pk.Z[6][2].Y.len=0x4;
    cred_key->pk.Z[6][2].Y.w[0]=0xcdbe46910d3840e3;
    cred_key->pk.Z[6][2].Y.w[1]=0xbacb574c13bad523;
    cred_key->pk.Z[6][2].Y.w[2]=0xad8f5a6ff854b65f;
    cred_key->pk.Z[6][2].Y.w[3]=0x210ec9e28877915e;

    cred_key->pk.Z[6][2].Z.len=0x4;
    cred_key->pk.Z[6][2].Z.w[0]=0x6f34b2903f362bfa;
    cred_key->pk.Z[6][2].Z.w[1]=0xd841e6290d50f3db;
    cred_key->pk.Z[6][2].Z.w[2]=0x3f0b5257454c6570;
    cred_key->pk.Z[6][2].Z.w[3]=0x10e16ee10feec222;

    cred_key->pk.Z[6][3].X.len=0x4;
    cred_key->pk.Z[6][3].X.w[0]=0x37fc82d8dbe5de89;
    cred_key->pk.Z[6][3].X.w[1]=0x65f306801089c7dd;
    cred_key->pk.Z[6][3].X.w[2]=0xb0bbe972ffb7b7c3;
    cred_key->pk.Z[6][3].X.w[3]=0x1dfc86758c2a4105;

    cred_key->pk.Z[6][3].Y.len=0x4;
    cred_key->pk.Z[6][3].Y.w[0]=0xbbc8815f9bc2c45d;
    cred_key->pk.Z[6][3].Y.w[1]=0xa486af7fc8b75fa8;
    cred_key->pk.Z[6][3].Y.w[2]=0xf5186eea8ea473dc;
    cred_key->pk.Z[6][3].Y.w[3]=0x197f38b508e6b398;

    cred_key->pk.Z[6][3].Z.len=0x4;
    cred_key->pk.Z[6][3].Z.w[0]=0x6a42b1611201c230;
    cred_key->pk.Z[6][3].Z.w[1]=0xe99d2cac5bf6f463;
    cred_key->pk.Z[6][3].Z.w[2]=0x7136efc232e06c4e;
    cred_key->pk.Z[6][3].Z.w[3]=0xa9514461193e4bd;

    cred_key->pk.Z[6][4].X.len=0x4;
    cred_key->pk.Z[6][4].X.w[0]=0x906dde36e431fea6;
    cred_key->pk.Z[6][4].X.w[1]=0x5b9cde0761c60b38;
    cred_key->pk.Z[6][4].X.w[2]=0x650b0082cfde40e;
    cred_key->pk.Z[6][4].X.w[3]=0xe004ea3fa128071;

    cred_key->pk.Z[6][4].Y.len=0x4;
    cred_key->pk.Z[6][4].Y.w[0]=0x599f0183d489f4f3;
    cred_key->pk.Z[6][4].Y.w[1]=0xc5b440a5e0b05079;
    cred_key->pk.Z[6][4].Y.w[2]=0xeea108789ccf5e1d;
    cred_key->pk.Z[6][4].Y.w[3]=0x1325e4fe43102472;

    cred_key->pk.Z[6][4].Z.len=0x4;
    cred_key->pk.Z[6][4].Z.w[0]=0xc575142a3024241b;
    cred_key->pk.Z[6][4].Z.w[1]=0x49ba77d321ca6586;
    cred_key->pk.Z[6][4].Z.w[2]=0xcac50554d7d2558c;
    cred_key->pk.Z[6][4].Z.w[3]=0x1bedaa332d5a8abd;

    cred_key->pk.Z[6][5].X.len=0x4;
    cred_key->pk.Z[6][5].X.w[0]=0x93a6deeef7c9c51;
    cred_key->pk.Z[6][5].X.w[1]=0x9195db43684a56fc;
    cred_key->pk.Z[6][5].X.w[2]=0x1ab462d76a365fc2;
    cred_key->pk.Z[6][5].X.w[3]=0xe0304c14b779db6;

    cred_key->pk.Z[6][5].Y.len=0x4;
    cred_key->pk.Z[6][5].Y.w[0]=0x7aa95cda4dcf9b67;
    cred_key->pk.Z[6][5].Y.w[1]=0x608d6476339e9826;
    cred_key->pk.Z[6][5].Y.w[2]=0xf907332a999c3870;
    cred_key->pk.Z[6][5].Y.w[3]=0x1472f349ed892ff8;

    cred_key->pk.Z[6][5].Z.len=0x4;
    cred_key->pk.Z[6][5].Z.w[0]=0x6b99c81e56547c22;
    cred_key->pk.Z[6][5].Z.w[1]=0xdc0781239cc65218;
    cred_key->pk.Z[6][5].Z.w[2]=0x129bc8eef746c40c;
    cred_key->pk.Z[6][5].Z.w[3]=0x14d450a2504e119e;

    cred_key->pk.Z[6][6].X.len=0x4;
    cred_key->pk.Z[6][6].X.w[0]=0xdc6033c18e7213b7;
    cred_key->pk.Z[6][6].X.w[1]=0x85afbc4b09ed5259;
    cred_key->pk.Z[6][6].X.w[2]=0x181abb4634eb43d6;
    cred_key->pk.Z[6][6].X.w[3]=0xe6c4f936e3e87d4;

    cred_key->pk.Z[6][6].Y.len=0x4;
    cred_key->pk.Z[6][6].Y.w[0]=0x20e7ab6d03023540;
    cred_key->pk.Z[6][6].Y.w[1]=0x50797bd1f9241b2e;
    cred_key->pk.Z[6][6].Y.w[2]=0xb352386928491f81;
    cred_key->pk.Z[6][6].Y.w[3]=0xf50c153e4ec3a2;

    cred_key->pk.Z[6][6].Z.len=0x1;
    cred_key->pk.Z[6][6].Z.w[0]=0x1;



#endif

    return ret;
}
int UserKeyGen(struct ACME_USER_KEY_C *user_key)
{
    int ret=0;
    ACME_USER_KEY user_key2;
    ret = prisrv.UserKeyGen(user_key2);
    if (ret !=0) return ret;
#if 0
    cout<<"usk"<<endl;
    cout<<user_key2.user_key.usk.usk<<endl;

#endif
    //trans
    BNT.Trf_Big_to_Char(user_key2.user_key.usk.usk,user_key->usk.usk);
    BNT.Trf_G2_to_Char(user_key2.user_key.upk.upk1,user_key->upk.upk1);
    BNT.Trf_G1_to_Char(user_key2.user_key.upk.upk2,user_key->upk.upk2);
    return ret;
}
int Issue_Send(struct ACME_USER_KEY_C *user_key,struct USER_ATTR_C *attr,struct Big_C *uid,struct ACME_SPK1_C *spk1)
{
    int ret=0;
    ACME_USER_KEY user_key2;
    USER_ATTR attr2;
    Big uid2;
    ACME_SPK1 spk12;
    //ACME_USER_KEY_C to ACME_USER_KEY
    BNT.Trf_Char_to_Big(user_key->usk.usk,user_key2.user_key.usk.usk);
    BNT.Trf_Char_to_G2(user_key->upk.upk1,user_key2.user_key.upk.upk1);
    BNT.Trf_Char_to_G1(user_key->upk.upk2,user_key2.user_key.upk.upk2);
    //
    ret = prisrv.Issue_Send(user_key2,attr2,uid2,spk12);
    if (ret !=0) return ret;
    //USER_ATTR to USER_ATTR_C
    BNT.Trf_Big_to_Char(uid2,*uid);
    for(int i=1;i<FAC_PARA_N+1;i++)
        BNT.Trf_Big_to_Char(attr2.x[i],attr->x[i]);
    //ACME_SPK1 to ACME_SPK1_C
    BNT.Trf_Big_to_Char(spk12.spk1.c,spk1->c);
    BNT.Trf_Big_to_Char(spk12.spk1.s,spk1->s);
    BNT.Trf_G1_to_Char(spk12.spk1.gam2,spk1->gam2);
    BNT.Trf_G2_to_Char(spk12.spk1.gam1,spk1->gam1);
    return ret;
}
int Issue_Issuer(struct ACME_CRED_KEY_C *cred_key,struct USER_ATTR_C *attr,struct Big_C *uid,struct ACME_SPK1_C *spk1,
                 struct ACME_USER_PK_C *upk,struct ACME_CRED_U_C *cred_u)
{
    int ret=0;
    ACME_CRED_KEY cred_key2;
    USER_ATTR attr2;
    Big uid2;
    ACME_SPK1 spk12;
    ACME_USER_PK upk2;
    ACME_CRED_U cred_u2;

    // ACME_CRED_KEY_C to ACME_CRED_KEY
    BNT.Trf_Char_to_Big(cred_key->sk.x,cred_key2.cred_key.sk.x);
    BNT.Trf_Char_to_G1(cred_key->pk.W,cred_key2.cred_key.pk.W);

    for(int i=0;i<FAC_PARA_N+2;i++)
    {
        BNT.Trf_Char_to_Big(cred_key->sk.y[i],cred_key2.cred_key.sk.y[i]);
        BNT.Trf_Char_to_G2(cred_key->pk.X[i],cred_key2.cred_key.pk.X[i]);
        BNT.Trf_Char_to_G1(cred_key->pk.Y[i],cred_key2.cred_key.pk.Y[i]);
    }

    for(int i=0;i<FAC_PARA_N+2;i++)
    {
        for(int j=0;j<FAC_PARA_N+2;j++)
        {
            BNT.Trf_Char_to_G1(cred_key->pk.Z[i][j],cred_key2.cred_key.pk.Z[i][j]);
        }
    }

    //USER_ATTR_C to USER_ATTR
    BNT.Trf_Char_to_Big(*uid,uid2);
    for(int i=1;i<FAC_PARA_N+1;i++)
        BNT.Trf_Char_to_Big(attr->x[i],attr2.x[i]);

    //ACME_SPK1_C to ACME_SPK1
    BNT.Trf_Char_to_Big(spk1->c,spk12.spk1.c);
    BNT.Trf_Char_to_Big(spk1->s,spk12.spk1.s);
    BNT.Trf_Char_to_G1(spk1->gam2,spk12.spk1.gam2);
    BNT.Trf_Char_to_G2(spk1->gam1,spk12.spk1.gam1);
    //ACME_USER_PK_C to ACME_USER_PK
    BNT.Trf_Char_to_G2(upk->upk.upk1,upk2.upk.upk1);
    BNT.Trf_Char_to_G1(upk->upk.upk2,upk2.upk.upk2);


    ret = prisrv.Issue_Issuer(cred_key2,attr2,uid2,spk12,upk2,cred_u2);
    if(ret !=0) return -1;

    //ACME_CRED_U to ACME_CRED_U_C
    BNT.Trf_G2_to_Char(cred_u2.cred_u.sigma1,cred_u->sigma1);
    BNT.Trf_G2_to_Char(cred_u2.cred_u.sigma2,cred_u->sigma2);

    return ret;
}
int Issue_Verify(struct ACME_CRED_KEY_PK_C *pk,struct ACME_CRED_U_C *cred_u,struct USER_ATTR_C *attr,struct Big_C *uid,
                 struct ACME_USER_KEY_C *user_key)
{
    int ret=0;
    ACME_CRED_KEY_PK pk2;
    ACME_CRED_U cred_u2;
    USER_ATTR attr2;
    Big uid2;
    ACME_USER_KEY user_key2;

    //ACME_CRED_KEY_PK_C to ACME_CRED_KEY_PK
    BNT.Trf_Char_to_G1(pk->pk.W,pk2.pk.W);
    for(int i=0;i<FAC_PARA_N+2;i++)
    {
        BNT.Trf_Char_to_G2(pk->pk.X[i],pk2.pk.X[i]);
        BNT.Trf_Char_to_G1(pk->pk.Y[i],pk2.pk.Y[i]);
    }
    for(int i=0;i<FAC_PARA_N+2;i++)
    {
        for(int j=0;j<FAC_PARA_N+2;j++)
        {
            BNT.Trf_Char_to_G1(pk->pk.Z[i][j],pk2.pk.Z[i][j]);
        }
    }

    //ACME_CRED_U_C to ACME_CRED_U
    BNT.Trf_Char_to_G2(cred_u->sigma1,cred_u2.cred_u.sigma1);
    BNT.Trf_Char_to_G2(cred_u->sigma2,cred_u2.cred_u.sigma2);


    //USER_ATTR_C  to USER_ATTR
    BNT.Trf_Char_to_Big(*uid,uid2);
    for(int i=1;i<FAC_PARA_N+1;i++)
        BNT.Trf_Char_to_Big(attr->x[i],attr2.x[i]);

    //ACME_USER_KEY_C to ACME_USER_KEY
    BNT.Trf_Char_to_Big(user_key->usk.usk,user_key2.user_key.usk.usk);
    BNT.Trf_Char_to_G2(user_key->upk.upk1,user_key2.user_key.upk.upk1);
    BNT.Trf_Char_to_G1(user_key->upk.upk2,user_key2.user_key.upk.upk2);

    ret = prisrv.Issue_Verify(pk2,cred_u2,attr2,uid2,user_key2);
    if(ret !=0) return ret;
    return ret;
}
int DKeyGen(struct ACME_MSK_C *msk,struct  ACME_X_C *X_rcv,struct  ACME_ABE_DK_X_REC_C *Dk_xrec)
{
    int ret=0;
    ACME_MSK msk2;
    ACME_X X_rcv2;
    ACME_ABE_DK_X_REC Dk_xrec2;
    //default
    X_rcv2.X.x[0]=X_rcv2.X.x[2]=1;
    X_rcv2.X.x[1]=0;
    //ACME_MSK_C ACME_MSK
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        for(int j=0;j<2*CP_ABE_PARA_K;j++)
        {
            BNT.Trf_Char_to_Big(msk->A[i][j],msk2.msk.A[i][j]);
        }
    }
    //B,k*k
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        for(int j=0;j<CP_ABE_PARA_K;j++)
        {
            BNT.Trf_Char_to_Big(msk->B[i][j],msk2.msk.B[i][j]);

        }
    }
    //U0,2k*k
    for(int i=0;i<2*CP_ABE_PARA_K;i++)
    {
        for(int j=0;j<CP_ABE_PARA_K;j++)
        {
            BNT.Trf_Char_to_Big(msk->U0[i][j],msk2.msk.U0[i][j]);
        }
    }
    //Wi N*2k*k
    for(int i=0;i<CP_ABE_PARA_N;i++)
    {
        for(int j=0;j<2*CP_ABE_PARA_K;j++)
        {
            for(int k=0;k<CP_ABE_PARA_K;k++)
            {
                BNT.Trf_Char_to_Big(msk->W[i][j][k],msk2.msk.W[i][j][k]);
            }
        }
    }
    for(int i=0;i<2*CP_ABE_PARA_K;i++)
    {
        BNT.Trf_Char_to_Big(msk->V[i],msk2.msk.V[i]);
    }
    //
    ret=prisrv.DKeyGen(msk2,X_rcv2,Dk_xrec2);
    if(ret !=0) return ret;

    //ACME_X to ACME_X_C
    X_rcv->x[0]=X_rcv2.X.x[0];
    X_rcv->x[1]=X_rcv2.X.x[1];
    X_rcv->x[2]=X_rcv2.X.x[2];

    //ACME_ABE_DK_X_REC to ACME_ABE_DK_X_REC_C
    for(int i=0;i<2*CP_ABE_PARA_K;i++)
    {
        BNT.Trf_G2_to_Char(Dk_xrec2.sk.sk1[i],Dk_xrec->sk.sk1[i]);
        BNT.Trf_G2_to_Char(Dk_xrec2.sk.sk3[i],Dk_xrec->sk.sk3[i]);
    }
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        BNT.Trf_G2_to_Char(Dk_xrec2.sk.sk2[i],Dk_xrec->sk.sk2[i]);
    }
    return ret;
}
int PolGen(struct ACME_MSK_C *msk,struct ACME_ABE_DK_f_REC_C *DK_frec)
{
    int ret=0;
    ACME_MSK msk2;
    ACME_ABE_DK_f_REC DK_frec2;

    //ACME_MSK_C ACME_MSK
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        for(int j=0;j<2*CP_ABE_PARA_K;j++)
        {
            BNT.Trf_Char_to_Big(msk->A[i][j],msk2.msk.A[i][j]);
        }
    }
    //B,k*k
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        for(int j=0;j<CP_ABE_PARA_K;j++)
        {
            BNT.Trf_Char_to_Big(msk->B[i][j],msk2.msk.B[i][j]);

        }
    }
    //U0,2k*k
    for(int i=0;i<2*CP_ABE_PARA_K;i++)
    {
        for(int j=0;j<CP_ABE_PARA_K;j++)
        {
            BNT.Trf_Char_to_Big(msk->U0[i][j],msk2.msk.U0[i][j]);
        }
    }
    //Wi N*2k*k
    for(int i=0;i<CP_ABE_PARA_N;i++)
    {
        for(int j=0;j<2*CP_ABE_PARA_K;j++)
        {
            for(int k=0;k<CP_ABE_PARA_K;k++)
            {
                BNT.Trf_Char_to_Big(msk->W[i][j][k],msk2.msk.W[i][j][k]);
            }
        }
    }
    for(int i=0;i<2*CP_ABE_PARA_K;i++)
    {
        BNT.Trf_Char_to_Big(msk->V[i],msk2.msk.V[i]);
    }

    ret=prisrv.PolGen(msk2,DK_frec2);
    if(ret !=0) return ret;

    //ACME_ABE_DK_f_REC to ACME_ABE_DK_f_REC_C

    for(int i=0;i<LSS_NC_SHARE_NUM;i++)
    {
        for(int j=0;j<CP_ABE_PARA_K;j++)
        {
            BNT.Trf_G2_to_Char(DK_frec2.dk[i][j],DK_frec->dk[i][j]);
        }
    }
    for(int i=0;i<CP_ABE_PARA_N+1;i++)
    {
        for(int j=0;j<LSS_NC_SHARE_NUM;j++)
        {
            for(int k=0;k<2*CP_ABE_PARA_K;k++)
            {
                BNT.Trf_G2_to_Char(DK_frec2.dk_rou[i][j][k],DK_frec->dk_rou[i][j][k]);
            }
        }
    }
    memcpy(&DK_frec->share,&DK_frec2.share,sizeof(CP_ABE_SHARE_INFO));

    return ret;
}
int Broadcast(struct ACME_MPK_C *mpk,struct  ACME_CRED_KEY_C *cred_key_pk,struct  ACME_CRED_U_C *cred_s,
              struct  ACME_USER_KEY_C *service_key,struct  USER_ATTR_C *service_attr,struct  Big_C *bid,struct  ACME_X_C *X_s,
              struct ACME_CIPHER_C *cipher,struct  PriSrv_MSG_B_C *msg_b,struct  Big_C *service_z)
{
    int ret=0;
    ACME_MPK mpk2;
    ACME_CRED_KEY cred_key_pk2;
    ACME_CRED_U cred_s2;
    ACME_USER_KEY service_key2;
    USER_ATTR service_attr2;
    Big bid2;
    ACME_X X_s2;
    ACME_CIPHER cipher2;
    PriSrv_MSG_B msg_b2;
    Big service_z2;
    //ACME_MPK_C to ACME_MPK
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        for(int j=0;j<2*CP_ABE_PARA_K;j++)
        {
            BNT.Trf_Char_to_G1(mpk->A1[i][j],mpk2.mpk.A1[i][j]);
        }
    }
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        for(int j=0;j<CP_ABE_PARA_K;j++)
        {
            BNT.Trf_Char_to_G1(mpk->AU01[i][j],mpk2.mpk.AU01[i][j]);
        }
    }
    for(int t=0;t<CP_ABE_PARA_N;t++)
    {
        for(int i=0;i<CP_ABE_PARA_K;i++)
        {
            for(int j=0;j<CP_ABE_PARA_K;j++)
            {
                BNT.Trf_Char_to_G1(mpk->AW1[t][i][j],mpk2.mpk.AW1[t][i][j]);
            }
        }
    }
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        BNT.Trf_Char_to_GT(mpk->eAV[i],mpk2.mpk.eAV[i]);
    }

    // ACME_CRED_KEY_C to ACME_CRED_KEY
    BNT.Trf_Char_to_Big(cred_key_pk->sk.x,cred_key_pk2.cred_key.sk.x);
    BNT.Trf_Char_to_G1(cred_key_pk->pk.W,cred_key_pk2.cred_key.pk.W);

    for(int i=0;i<FAC_PARA_N+2;i++)
    {
        BNT.Trf_Char_to_Big(cred_key_pk->sk.y[i],cred_key_pk2.cred_key.sk.y[i]);
        BNT.Trf_Char_to_G2(cred_key_pk->pk.X[i],cred_key_pk2.cred_key.pk.X[i]);
        BNT.Trf_Char_to_G1(cred_key_pk->pk.Y[i],cred_key_pk2.cred_key.pk.Y[i]);
    }
    for(int i=0;i<FAC_PARA_N+2;i++)
    {
        for(int j=0;j<FAC_PARA_N+2;j++)
        {
            BNT.Trf_Char_to_G1(cred_key_pk->pk.Z[i][j],cred_key_pk2.cred_key.pk.Z[i][j]);
        }
    }

    //ACME_CRED_U_C to ACME_CRED_U
    BNT.Trf_Char_to_G2(cred_s->sigma1,cred_s2.cred_u.sigma1);
    BNT.Trf_Char_to_G2(cred_s->sigma2,cred_s2.cred_u.sigma2);
    //ACME_USER_KEY_C to ACME_USER_KEY

    BNT.Trf_Char_to_Big(service_key->usk.usk,service_key2.user_key.usk.usk);
    BNT.Trf_Char_to_G2(service_key->upk.upk1,service_key2.user_key.upk.upk1);
    BNT.Trf_Char_to_G1(service_key->upk.upk2,service_key2.user_key.upk.upk2);


    //USER_ATTR_C  to USER_ATTR
    BNT.Trf_Char_to_Big(*bid,bid2);
    for(int i=1;i<FAC_PARA_N+1;i++)
        BNT.Trf_Char_to_Big(service_attr->x[i],service_attr2.x[i]);

    //ACME_X_C to ACME_X
    X_s2.X.x[0]=X_s->x[0];X_s2.X.x[1]=X_s->x[1];X_s2.X.x[2]=X_s->x[2];


    ret=prisrv.Broadcast(mpk2,cred_key_pk2,cred_s2,service_key2,\
                         service_attr2,bid2,X_s2,cipher2,msg_b2,service_z2);
    if(ret !=0) return ret;
#if 0 //test
    cout<<"\\---------服务端令牌信息show token ------------\\"<<endl;
    cout<<"T1"<<endl;
    cout<<cipher2.cipher_tok.T1.g<<endl;
    cout<<"T2"<<endl;
    cout<<cipher2.cipher_tok.T2.g<<endl;
    cout<<"sigma1"<<endl;
    cout<<cipher2.cipher_tok.sigma1.g<<endl;
    cout<<"sigma2"<<endl;
    cout<<cipher2.cipher_tok.sigma2.g<<endl;
    cout<<"服务端知识签名 spk2"<<endl;

    cout<<"c"<<endl;
    cout<<cipher2.cipher_tok.spk2.c<<endl;
    cout<<"usk'"<<endl;
    cout<<cipher2.cipher_tok.spk2.sk<<endl;
    cout<<"uid'"<<endl;
    cout<<cipher2.cipher_tok.spk2.sd<<endl;
    cout<<"Gama'"<<endl;
    cout<<cipher2.cipher_tok.spk2.gama.g<<endl;

    cout<<"\\--------- disclose attributes ---------\\"<<endl;
    for(int i=0;i<FAC_PARA_D;i++)
    {
        cout<<cipher2.disclose.x[i]<<endl;
    }



#endif


    //ACME_CIPHER to ACME_CIPHER_C

    BNT.Trf_GT_to_Char(cipher2.ct0,cipher->ct0);
    for(int i=0;i<2*CP_ABE_PARA_K;i++)
    {
        BNT.Trf_G1_to_Char(cipher2.ct1_[i],cipher->ct1_[i]);
        BNT.Trf_G1_to_Char(cipher2.ct1[i],cipher->ct1[i]);
    }
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        BNT.Trf_G1_to_Char(cipher2.ct2_[i],cipher->ct2_[i]);
    }
    for(int i=0;i<LSS_NC_SHARE_NUM;i++)
    {
        for(int j=0;j<2*CP_ABE_PARA_K;j++)
            BNT.Trf_G1_to_Char(cipher2.ct2[i][j],cipher->ct2[i][j]);
    }
    for(int i=0;i<CP_ABE_PARA_N+1;i++)
    {
        for(int j=0;j<LSS_NC_SHARE_NUM;j++)
        {
            for(int k=0;k<CP_ABE_PARA_K;k++)
                BNT.Trf_G1_to_Char(cipher2.ct_rou[i][j][k],cipher->ct_rou[i][j][k]);
        }
    }
#if 0 //test

    cout<<"ct_rou[i,j]"<<endl;

    for(int i=0;i<CP_ABE_PARA_N+1;i++)
    {
        for(int j=0;j<LSS_NC_SHARE_NUM;j++)
        {
            for(int k=0;k<CP_ABE_PARA_K;k++)
            {
                cout<<"pre"<<endl;
                cout<<cipher2.ct_rou[i][j][k].g<<endl;
                cout<<"bak"<<endl;
                cout<<cipher->ct_rou[i][j][k].X.len<<endl;
                cout<<cipher->ct_rou[i][j][k].X.w[0]<<endl;
                cout<<cipher->ct_rou[i][j][k].Y.len<<endl;
                cout<<cipher->ct_rou[i][j][k].Y.w[0]<<endl;
                cout<<cipher->ct_rou[i][j][k].Z.len<<endl;
                cout<<cipher->ct_rou[i][j][k].Z.w[0]<<endl;
                break;
            }

        }
        break;

    }


#endif
#if 0
    BNT.Trf_GT_to_Char(cipher2.K,cipher->K);
    BNT.Trf_Big_to_Char(cipher2.cipher_M,cipher->cipher_M);
    //FAC_TOK to FAC_TOK_C
    BNT.Trf_G1_to_Char(cipher2.cipher_tok.T1,cipher->cipher_tok.T1);
    BNT.Trf_G1_to_Char(cipher2.cipher_tok.T2,cipher->cipher_tok.T2);
    BNT.Trf_G2_to_Char(cipher2.cipher_tok.sigma1,cipher->cipher_tok.sigma1);
    BNT.Trf_G2_to_Char(cipher2.cipher_tok.sigma2,cipher->cipher_tok.sigma2);
    //FAC_SPK2 to FAC_SPK2_C
    BNT.Trf_Big_to_Char(cipher2.cipher_tok.spk2.c,cipher->cipher_tok.spk2.c);
    BNT.Trf_Big_to_Char(cipher2.cipher_tok.spk2.sd,cipher->cipher_tok.spk2.sd);
    BNT.Trf_Big_to_Char(cipher2.cipher_tok.spk2.sk,cipher->cipher_tok.spk2.sk);
    BNT.Trf_GT_to_Char(cipher2.cipher_tok.spk2.gama,cipher->cipher_tok.spk2.gama);
#endif
    memcpy(cipher->cipher,cipher2.cipher,cipher2.cipher_len);
    cipher->cipher_len=cipher2.cipher_len;
    //FAC_USER_DISCLOSE_ATTR to FAC_USER_DISCLOSE_ATTR_C
    for(int i=0;i< FAC_PARA_D;i++)
        BNT.Trf_Big_to_Char(cipher2.disclose.x[i],cipher->disclose.x[i]);
    //CP_ABE_SHARE_INFO to CP_ABE_SHARE_INFO_C
    memcpy(&cipher->share,&cipher2.share,sizeof(CP_ABE_SHARE_INFO));

    //PriSrv_MSG_B to PriSrv_MSG_B-C
    BNT.Trf_Big_to_Char(msg_b2.bid,msg_b->bid);
    BNT.Trf_Big_to_Char(msg_b2.Service_type,msg_b->Service_type);
    BNT.Trf_Big_to_Char(msg_b2.Service_par,msg_b->Service_par);
    BNT.Trf_G2_to_Char(msg_b2.Z,msg_b->Z);
    //Big to Big_C
    BNT.Trf_Big_to_Char(service_z2,*service_z);
    return ret;
}
int AMA_Cinit(struct ACME_MPK_C *mpk, struct ACME_CRED_KEY_C *cred_key_pk, struct ACME_CRED_U_C *cred_c, struct ACME_USER_KEY_C *client_key, struct ACME_ABE_DK_X_REC_C *Dk_C_xrec, struct ACME_ABE_DK_f_REC_C *DK_C_frec, struct ACME_X_C *X_s, struct  ACME_X_C *X_c,
              struct USER_ATTR_C *client_attr, struct Big_C *uid, struct ACME_CIPHER_C *cipher, struct PriSrv_MSG_B_C *msg_b, struct PriSrv_C1_C *C1_msg)
{
    int ret=0;


    ACME_MPK mpk2;
    ACME_CRED_KEY cred_key_pk2;
    ACME_CRED_U cred_c2;
    ACME_USER_KEY client_key2;
    ACME_ABE_DK_X_REC Dk_C_xrec2;
    ACME_ABE_DK_f_REC DK_C_frec2;
    ACME_X X_s2;
    ACME_X X_c2;
    USER_ATTR client_attr2;
    Big uid2;
    ACME_CIPHER cipher2;
    PriSrv_MSG_B msg_b2;
    Big x;
    PriSrv_C1 C1_msg2;
#if 1
    //ACME_MPK_C to ACME_MPK
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        for(int j=0;j<2*CP_ABE_PARA_K;j++)
        {
            BNT.Trf_Char_to_G1(mpk->A1[i][j],mpk2.mpk.A1[i][j]);
        }
    }
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        for(int j=0;j<CP_ABE_PARA_K;j++)
        {
            BNT.Trf_Char_to_G1(mpk->AU01[i][j],mpk2.mpk.AU01[i][j]);
        }
    }
    for(int t=0;t<CP_ABE_PARA_N;t++)
    {
        for(int i=0;i<CP_ABE_PARA_K;i++)
        {
            for(int j=0;j<CP_ABE_PARA_K;j++)
            {
                BNT.Trf_Char_to_G1(mpk->AW1[t][i][j],mpk2.mpk.AW1[t][i][j]);
            }
        }
    }
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        BNT.Trf_Char_to_GT(mpk->eAV[i],mpk2.mpk.eAV[i]);
    }

    // ACME_CRED_KEY_C to ACME_CRED_KEY
    BNT.Trf_Char_to_Big(cred_key_pk->sk.x,cred_key_pk2.cred_key.sk.x);
    BNT.Trf_Char_to_G1(cred_key_pk->pk.W,cred_key_pk2.cred_key.pk.W);

    for(int i=0;i<FAC_PARA_N+2;i++)
    {
        BNT.Trf_Char_to_Big(cred_key_pk->sk.y[i],cred_key_pk2.cred_key.sk.y[i]);
        BNT.Trf_Char_to_G2(cred_key_pk->pk.X[i],cred_key_pk2.cred_key.pk.X[i]);
        BNT.Trf_Char_to_G1(cred_key_pk->pk.Y[i],cred_key_pk2.cred_key.pk.Y[i]);
    }
    for(int i=0;i<FAC_PARA_N+2;i++)
    {
        for(int j=0;j<FAC_PARA_N+2;j++)
        {
            BNT.Trf_Char_to_G1(cred_key_pk->pk.Z[i][j],cred_key_pk2.cred_key.pk.Z[i][j]);
        }
    }
    //ACME_CRED_U_C to ACME_CRED_U
    BNT.Trf_Char_to_G2(cred_c->sigma1,cred_c2.cred_u.sigma1);
    BNT.Trf_Char_to_G2(cred_c->sigma2,cred_c2.cred_u.sigma2);

    //ACME_USER_KEY_C to ACME_USER_KEY
    BNT.Trf_Char_to_Big(client_key->usk.usk,client_key2.user_key.usk.usk);
    BNT.Trf_Char_to_G2(client_key->upk.upk1,client_key2.user_key.upk.upk1);
    BNT.Trf_Char_to_G1(client_key->upk.upk2,client_key2.user_key.upk.upk2);

    //ACME_ABE_DK_X_REC_C to ACME_ABE_DK_X_REC
    for(int i=0;i<2*CP_ABE_PARA_K;i++)
    {
        BNT.Trf_Char_to_G2(Dk_C_xrec->sk.sk1[i],Dk_C_xrec2.sk.sk1[i]);
        BNT.Trf_Char_to_G2(Dk_C_xrec->sk.sk3[i],Dk_C_xrec2.sk.sk3[i]);
    }
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        BNT.Trf_Char_to_G2(Dk_C_xrec->sk.sk2[i],Dk_C_xrec2.sk.sk2[i]);
    }
    //ACME_ABE_DK_f_REC_C to ACME_ABE_DK_f_REC

    for(int i=0;i<LSS_NC_SHARE_NUM;i++)
    {
        for(int j=0;j<CP_ABE_PARA_K;j++)
        {
            BNT.Trf_Char_to_G2(DK_C_frec->dk[i][j],DK_C_frec2.dk[i][j]);
        }
    }
    for(int i=0;i<CP_ABE_PARA_N+1;i++)
    {
        for(int j=0;j<LSS_NC_SHARE_NUM;j++)
        {
            for(int k=0;k<2*CP_ABE_PARA_K;k++)
            {
                BNT.Trf_Char_to_G2(DK_C_frec->dk_rou[i][j][k],DK_C_frec2.dk_rou[i][j][k]);
            }
        }
    }
    memcpy(&DK_C_frec2.share,&DK_C_frec->share,sizeof(CP_ABE_SHARE_INFO));

    //ACME_X_C to ACME_X
    X_s2.X.x[0]=X_s->x[0];X_s2.X.x[1]=X_s->x[1];X_s2.X.x[2]=X_s->x[2];
    X_c2.X.x[0]=X_c->x[0];X_c2.X.x[1]=X_c->x[1];X_c2.X.x[2]=X_c->x[2];
    //USER_ATTR_C  to USER_ATTR
    BNT.Trf_Char_to_Big(*uid,uid2);
    for(int i=1;i<FAC_PARA_N+1;i++)
        BNT.Trf_Char_to_Big(client_attr->x[i],client_attr2.x[i]);

    //ACME_CIPHER to ACME_CIPHER_C
    BNT.Trf_Char_to_GT(cipher->ct0,cipher2.ct0);
    for(int i=0;i<2*CP_ABE_PARA_K;i++)
    {
        BNT.Trf_Char_to_G1(cipher->ct1_[i],cipher2.ct1_[i]);
        BNT.Trf_Char_to_G1(cipher->ct1[i],cipher2.ct1[i]);
    }
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        BNT.Trf_Char_to_G1(cipher->ct2_[i],cipher2.ct2_[i]);
    }
    for(int i=0;i<LSS_NC_SHARE_NUM;i++)
    {
        for(int j=0;j<2*CP_ABE_PARA_K;j++)
            BNT.Trf_Char_to_G1(cipher->ct2[i][j],cipher2.ct2[i][j]);
    }
    //BNT.Trf_Char_to_GT(cipher->K,cipher2.K);
#endif


    for(int i=0;i<CP_ABE_PARA_N+1;i++)
    {
        for(int j=0;j<LSS_NC_SHARE_NUM;j++)
        {
            for(int k=0;k<CP_ABE_PARA_K;k++)
                BNT.Trf_Char_to_G1(cipher->ct_rou[i][j][k],cipher2.ct_rou[i][j][k]);
        }
    }
#if 0 //test

    cout<<"ct_rou[i,j]"<<endl;

    for(int i=0;i<CP_ABE_PARA_N+1;i++)
    {
        for(int j=0;j<LSS_NC_SHARE_NUM;j++)
            for(int k=0;k<CP_ABE_PARA_K;k++)
            {
                cout<<"bak"<<endl;
                cout<<cipher->ct_rou[i][j][k].X.len<<endl;
                cout<<cipher->ct_rou[i][j][k].Y.len<<endl;
                cout<<cipher->ct_rou[i][j][k].Z.len<<endl;
                cout<<"pre"<<endl;
                cout<<cipher2.ct_rou[i][j][k].g<<endl;

            }
    }


#endif
#if 1
    //BNT.Trf_Char_to_GT(cipher->K,cipher2.K);
    #if 0
    BNT.Trf_Char_to_Big(cipher->cipher_M,cipher2.cipher_M);
    //FAC_TOK to FAC_TOK_C
    BNT.Trf_Char_to_G1(cipher->cipher_tok.T1,cipher2.cipher_tok.T1);
    BNT.Trf_Char_to_G1(cipher->cipher_tok.T2,cipher2.cipher_tok.T2);
    BNT.Trf_Char_to_G2(cipher->cipher_tok.sigma1,cipher2.cipher_tok.sigma1);
    BNT.Trf_Char_to_G2(cipher->cipher_tok.sigma2,cipher2.cipher_tok.sigma2);
    //FAC_SPK2 to FAC_SPK2_C
    BNT.Trf_Char_to_Big(cipher->cipher_tok.spk2.c,cipher2.cipher_tok.spk2.c);
    BNT.Trf_Char_to_Big(cipher->cipher_tok.spk2.sd,cipher2.cipher_tok.spk2.sd);
    BNT.Trf_Char_to_Big(cipher->cipher_tok.spk2.sk,cipher2.cipher_tok.spk2.sk);
    BNT.Trf_Char_to_GT(cipher->cipher_tok.spk2.gama,cipher2.cipher_tok.spk2.gama);
    #endif
    memcpy(cipher2.cipher,cipher->cipher,cipher->cipher_len);
    cipher2.cipher_len=cipher->cipher_len;

    //FAC_USER_DISCLOSE_ATTR to FAC_USER_DISCLOSE_ATTR_C
    for(int i=0;i< FAC_PARA_D;i++)
        BNT.Trf_Char_to_Big(cipher->disclose.x[i],cipher2.disclose.x[i]);

    //CP_ABE_SHARE_INFO to CP_ABE_SHARE_INFO_C
    memcpy(&cipher->share,&cipher2.share,sizeof(CP_ABE_SHARE_INFO));

    //PriSrv_MSG_B to PriSrv_MSG_B-C
    BNT.Trf_Char_to_Big(msg_b->bid,msg_b2.bid);
    BNT.Trf_Char_to_Big(msg_b->Service_type,msg_b2.Service_type);
    BNT.Trf_Char_to_Big(msg_b->Service_par,msg_b2.Service_par);
    BNT.Trf_Char_to_G2(msg_b->Z,msg_b2.Z);

#endif
    //
#if 0 //test
    cout<<"\\---------服务端令牌信息verify token ------------\\"<<endl;
    cout<<"T1"<<endl;
    cout<<cipher2.cipher_tok.T1.g<<endl;
    cout<<"T2"<<endl;
    cout<<cipher2.cipher_tok.T2.g<<endl;
    cout<<"sigma1"<<endl;
    cout<<cipher2.cipher_tok.sigma1.g<<endl;
    cout<<"sigma2"<<endl;
    cout<<cipher2.cipher_tok.sigma2.g<<endl;
    cout<<"服务端知识签名 spk2"<<endl;

    cout<<"c"<<endl;
    cout<<cipher2.cipher_tok.spk2.c<<endl;
    cout<<"usk'"<<endl;
    cout<<cipher2.cipher_tok.spk2.sk<<endl;
    cout<<"uid'"<<endl;
    cout<<cipher2.cipher_tok.spk2.sd<<endl;
    cout<<"Gama'"<<endl;
    cout<<cipher2.cipher_tok.spk2.gama.g<<endl;

    cout<<"\\--------- disclose attributes ---------\\"<<endl;
    for(int i=0;i<FAC_PARA_D;i++)
    {
        cout<<cipher2.disclose.x[i]<<endl;
    }
    cout<<"\\--------- 签证公钥 cred_key.pk ------------\\"<<endl;
    cout<<"W:"<<endl;
    cout<<cred_key_pk2.cred_key.pk.W.g<<endl;
    cout<<"X:"<<endl;
    for(int i=0;i<FAC_PARA_N+2;i++)
    {
        cout<<cred_key_pk2.cred_key.pk.X[i].g<<endl;
    }
    cout<<"Y:"<<endl;
    for(int i=0;i<FAC_PARA_N+2;i++)
    {
        cout<<cred_key_pk2.cred_key.pk.Y[i].g<<endl;
    }
    cout<<"Z:"<<endl;
    for(int i=0;i<FAC_PARA_N+2;i++)
    {
        for(int j=0;j<FAC_PARA_N+2;j++)
        {
            cout<<cred_key_pk2.cred_key.pk.Z[i][j].g<<endl;
        }
    }


#endif
    ret=prisrv.AMA_Cinit(mpk2,cred_key_pk2,cred_c2,client_key2,Dk_C_xrec2,DK_C_frec2,\
                         X_s2,X_c2,client_attr2,uid2,cipher2,msg_b2,x,C1_msg2);
    if(ret !=0) return ret;
    //PriSrv_C1 to PriSrv_C1_C

    //
    BNT.Trf_Big_to_Char(C1_msg2.x1,C1_msg->x1);
    BNT.Trf_Big_to_Char(C1_msg2.x2,C1_msg->x2);
    //ACME_CIPHER to ACME_CIPHER_C

    BNT.Trf_GT_to_Char(C1_msg2.CT.ct0,C1_msg->CT.ct0);
    for(int i=0;i<2*CP_ABE_PARA_K;i++)
    {
        BNT.Trf_G1_to_Char(C1_msg2.CT.ct1_[i],C1_msg->CT.ct1_[i]);
        BNT.Trf_G1_to_Char(C1_msg2.CT.ct1[i],C1_msg->CT.ct1[i]);
    }
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        BNT.Trf_G1_to_Char(C1_msg2.CT.ct2_[i],C1_msg->CT.ct2_[i]);
    }
    for(int i=0;i<LSS_NC_SHARE_NUM;i++)
    {
        for(int j=0;j<2*CP_ABE_PARA_K;j++)
            BNT.Trf_G1_to_Char(C1_msg2.CT.ct2[i][j],C1_msg->CT.ct2[i][j]);
    }
    for(int i=0;i<CP_ABE_PARA_N+1;i++)
    {
        for(int j=0;j<LSS_NC_SHARE_NUM;j++)
        {
            for(int k=0;k<CP_ABE_PARA_K;k++)
                BNT.Trf_G1_to_Char(C1_msg2.CT.ct_rou[i][j][k],C1_msg->CT.ct_rou[i][j][k]);
        }
    }
#if 0//test
    cout<<"!!!!!!!!!!!!C1_msg2.CT.cipher_M!!!!!!!!"<<endl;
    cout<<C1_msg2.CT.cipher_M<<endl;

#endif
#if 0
    BNT.Trf_Big_to_Char(C1_msg2.CT.cipher_M,C1_msg->CT.cipher_M);
    //FAC_TOK to FAC_TOK_C
    BNT.Trf_G1_to_Char(C1_msg2.CT.cipher_tok.T1,C1_msg->CT.cipher_tok.T1);
    BNT.Trf_G1_to_Char(C1_msg2.CT.cipher_tok.T2,C1_msg->CT.cipher_tok.T2);
    BNT.Trf_G2_to_Char(C1_msg2.CT.cipher_tok.sigma1,C1_msg->CT.cipher_tok.sigma1);
    BNT.Trf_G2_to_Char(C1_msg2.CT.cipher_tok.sigma2,C1_msg->CT.cipher_tok.sigma2);
    //FAC_SPK2 to FAC_SPK2_C
    BNT.Trf_Big_to_Char(C1_msg2.CT.cipher_tok.spk2.c,C1_msg->CT.cipher_tok.spk2.c);
    BNT.Trf_Big_to_Char(C1_msg2.CT.cipher_tok.spk2.sd,C1_msg->CT.cipher_tok.spk2.sd);
    BNT.Trf_Big_to_Char(C1_msg2.CT.cipher_tok.spk2.sk,C1_msg->CT.cipher_tok.spk2.sk);
    BNT.Trf_GT_to_Char(C1_msg2.CT.cipher_tok.spk2.gama,C1_msg->CT.cipher_tok.spk2.gama);
#endif
    memcpy(C1_msg->CT.cipher,C1_msg2.CT.cipher,C1_msg2.CT.cipher_len);
    C1_msg->CT.cipher_len=C1_msg2.CT.cipher_len;
    
    //FAC_USER_DISCLOSE_ATTR to FAC_USER_DISCLOSE_ATTR_C
    for(int i=0;i< FAC_PARA_D;i++)
        BNT.Trf_Big_to_Char(C1_msg2.CT.disclose.x[i],C1_msg->CT.disclose.x[i]);
    //CP_ABE_SHARE_INFO to CP_ABE_SHARE_INFO_C
    memcpy(&C1_msg->CT.share,&C1_msg2.CT.share,sizeof(CP_ABE_SHARE_INFO));
    //PriSrv_MSG_B to PriSrv_MSG_B-C
    //MACddh_SK to MACddh_SK_C
    for(int i=0;i<MACddh_PARA_N+1;i++)
    {
        BNT.Trf_Big_to_Char(C1_msg2.msg_c.K_c.x[i],C1_msg->msg_c.K_c.x[i]);
        BNT.Trf_Big_to_Char(C1_msg2.msg_c.K_c.y[i],C1_msg->msg_c.K_c.y[i]);
    }
    BNT.Trf_Big_to_Char(C1_msg2.msg_c.K_c.z,C1_msg->msg_c.K_c.z);
    //FAC_TOK yo FAC_TOK_C
    BNT.Trf_G1_to_Char(C1_msg2.msg_c.tok_c.T1,C1_msg->msg_c.tok_c.T1);
    BNT.Trf_G1_to_Char(C1_msg2.msg_c.tok_c.T2,C1_msg->msg_c.tok_c.T2);
    BNT.Trf_G2_to_Char(C1_msg2.msg_c.tok_c.sigma1,C1_msg->msg_c.tok_c.sigma1);
    BNT.Trf_G2_to_Char(C1_msg2.msg_c.tok_c.sigma2,C1_msg->msg_c.tok_c.sigma2);
    //FAC_USER_DISCLOSE_ATTR to FAC_USER_DISCLOSE_ATTR_C
    for(int i=0;i< FAC_PARA_D;i++)
        BNT.Trf_Big_to_Char(C1_msg2.msg_c.Disclose_c.x[i],C1_msg->msg_c.Disclose_c.x[i]);
    //PriSrv_M_C to PriSrv_M_C_C
    BNT.Trf_Big_to_Char(C1_msg2.msg_c.M_c.sid,C1_msg->msg_c.M_c.sid);
    BNT.Trf_Big_to_Char(C1_msg2.msg_c.M_c.bid,C1_msg->msg_c.M_c.bid);
    BNT.Trf_G1_to_Char(C1_msg2.msg_c.M_c.X1,C1_msg->msg_c.M_c.X1);
    BNT.Trf_G2_to_Char(C1_msg2.msg_c.M_c.X2,C1_msg->msg_c.M_c.X2);
    BNT.Trf_G2_to_Char(C1_msg2.msg_c.M_c.Z,C1_msg->msg_c.M_c.Z);
    //MACddh_MAC to MACddh_MAC_C
    BNT.Trf_G1_to_Char(C1_msg2.sigma_c.sig_w,C1_msg->sigma_c.sig_w);
    BNT.Trf_G1_to_Char(C1_msg2.sigma_c.sig_x,C1_msg->sigma_c.sig_x);
    BNT.Trf_G1_to_Char(C1_msg2.sigma_c.sig_y,C1_msg->sigma_c.sig_y);
    BNT.Trf_G1_to_Char(C1_msg2.sigma_c.sig_z,C1_msg->sigma_c.sig_z);

  //  BNT.Trf_GT_to_Char(C1_msg2.CT.K,C1_msg->CT.K);
    return ret;
}
int AMA_S(struct ACME_MPK_C *mpk,struct  ACME_CRED_KEY_C *cred_key_pk,struct  ACME_CRED_U_C *cred_s,struct  ACME_USER_KEY_C *service_key,struct  Big_C *service_z, struct USER_ATTR_C *service_attr, struct Big_C *sid,
          struct ACME_ABE_DK_X_REC_C *Dk_S_xrec,struct  ACME_ABE_DK_f_REC_C *DK_S_frec,struct  ACME_X_C *X_s,struct  ACME_X_C *X_c,struct  PriSrv_C1_C *C1_msg,struct  PriSrv_S_C *S_msg,struct  PriSrv_SSK_C *ssk)
{
    int ret=0;
    ACME_MPK mpk2;
    ACME_CRED_KEY cred_key_pk2;
    ACME_CRED_U cred_s2;
    ACME_USER_KEY service_key2;
    Big service_z2;
    USER_ATTR service_attr2;
    Big sid2;
    ACME_ABE_DK_X_REC Dk_S_xrec2;
    ACME_ABE_DK_f_REC DK_S_frec2;
    ACME_X X_s2;
    ACME_X X_c2;
    PriSrv_C1 C1_msg2;
    PriSrv_S S_msg2;
    PriSrv_SSK ssk2;
    //ACME_MPK_C to ACME_MPK
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        for(int j=0;j<2*CP_ABE_PARA_K;j++)
        {
            BNT.Trf_Char_to_G1(mpk->A1[i][j],mpk2.mpk.A1[i][j]);
        }
    }
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        for(int j=0;j<CP_ABE_PARA_K;j++)
        {
            BNT.Trf_Char_to_G1(mpk->AU01[i][j],mpk2.mpk.AU01[i][j]);
        }
    }
    for(int t=0;t<CP_ABE_PARA_N;t++)
    {
        for(int i=0;i<CP_ABE_PARA_K;i++)
        {
            for(int j=0;j<CP_ABE_PARA_K;j++)
            {
                BNT.Trf_Char_to_G1(mpk->AW1[t][i][j],mpk2.mpk.AW1[t][i][j]);
            }
        }
    }
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        BNT.Trf_Char_to_GT(mpk->eAV[i],mpk2.mpk.eAV[i]);
    }
    // ACME_CRED_KEY_C to ACME_CRED_KEY
    BNT.Trf_Char_to_Big(cred_key_pk->sk.x,cred_key_pk2.cred_key.sk.x);
    BNT.Trf_Char_to_G1(cred_key_pk->pk.W,cred_key_pk2.cred_key.pk.W);

    for(int i=0;i<FAC_PARA_N+2;i++)
    {
        BNT.Trf_Char_to_Big(cred_key_pk->sk.y[i],cred_key_pk2.cred_key.sk.y[i]);
        BNT.Trf_Char_to_G2(cred_key_pk->pk.X[i],cred_key_pk2.cred_key.pk.X[i]);
        BNT.Trf_Char_to_G1(cred_key_pk->pk.Y[i],cred_key_pk2.cred_key.pk.Y[i]);
    }
    for(int i=0;i<FAC_PARA_N+2;i++)
    {
        for(int j=0;j<FAC_PARA_N+2;j++)
        {
            BNT.Trf_Char_to_G1(cred_key_pk->pk.Z[i][j],cred_key_pk2.cred_key.pk.Z[i][j]);
        }
    }

    //ACME_CRED_U_C to ACME_CRED_U
    BNT.Trf_Char_to_G2(cred_s->sigma1,cred_s2.cred_u.sigma1);
    BNT.Trf_Char_to_G2(cred_s->sigma2,cred_s2.cred_u.sigma2);

    //ACME_USER_KEY_C to ACME_USER_KEY
    BNT.Trf_Char_to_Big(service_key->usk.usk,service_key2.user_key.usk.usk);
    BNT.Trf_Char_to_G2(service_key->upk.upk1,service_key2.user_key.upk.upk1);
    BNT.Trf_Char_to_G1(service_key->upk.upk2,service_key2.user_key.upk.upk2);

    BNT.Trf_Char_to_Big(*service_z,service_z2);


    //USER_ATTR_C  to USER_ATTR
    BNT.Trf_Char_to_Big(*sid,sid2);
    for(int i=1;i<FAC_PARA_N+1;i++)
        BNT.Trf_Char_to_Big(service_attr->x[i],service_attr2.x[i]);

    //ACME_ABE_DK_X_REC_C to ACME_ABE_DK_X_REC
    for(int i=0;i<2*CP_ABE_PARA_K;i++)
    {
        BNT.Trf_Char_to_G2(Dk_S_xrec->sk.sk1[i],Dk_S_xrec2.sk.sk1[i]);
        BNT.Trf_Char_to_G2(Dk_S_xrec->sk.sk3[i],Dk_S_xrec2.sk.sk3[i]);
    }
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        BNT.Trf_Char_to_G2(Dk_S_xrec->sk.sk2[i],Dk_S_xrec2.sk.sk2[i]);
    }
    //ACME_ABE_DK_f_REC_C to ACME_ABE_DK_f_REC

    for(int i=0;i<LSS_NC_SHARE_NUM;i++)
    {
        for(int j=0;j<CP_ABE_PARA_K;j++)
        {
            BNT.Trf_Char_to_G2(DK_S_frec->dk[i][j],DK_S_frec2.dk[i][j]);
        }
    }
    for(int i=0;i<CP_ABE_PARA_N+1;i++)
    {
        for(int j=0;j<LSS_NC_SHARE_NUM;j++)
        {
            for(int k=0;k<2*CP_ABE_PARA_K;k++)
            {
                BNT.Trf_Char_to_G2(DK_S_frec->dk_rou[i][j][k],DK_S_frec2.dk_rou[i][j][k]);
            }
        }
    }
    memcpy(&DK_S_frec2.share,&DK_S_frec->share,sizeof(CP_ABE_SHARE_INFO));

    //ACME_X_C to ACME_X
    X_s2.X.x[0]=X_s->x[0];X_s2.X.x[1]=X_s->x[1];X_s2.X.x[2]=X_s->x[2];
    X_c2.X.x[0]=X_c->x[0];X_c2.X.x[1]=X_c->x[1];X_c2.X.x[2]=X_c->x[2];
    //////// PriSrv_C1_C to PriSrv_C1
    BNT.Trf_Char_to_Big(C1_msg->x1,C1_msg2.x1);
    BNT.Trf_Char_to_Big(C1_msg->x2,C1_msg2.x2);
    //ACME_CIPHER to ACME_CIPHER_C

    BNT.Trf_Char_to_GT(C1_msg->CT.ct0,C1_msg2.CT.ct0);
    for(int i=0;i<2*CP_ABE_PARA_K;i++)
    {
        BNT.Trf_Char_to_G1(C1_msg->CT.ct1_[i],C1_msg2.CT.ct1_[i]);
        BNT.Trf_Char_to_G1(C1_msg->CT.ct1[i],C1_msg2.CT.ct1[i]);
    }
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        BNT.Trf_Char_to_G1(C1_msg->CT.ct2_[i],C1_msg2.CT.ct2_[i]);
    }
    for(int i=0;i<LSS_NC_SHARE_NUM;i++)
    {
        for(int j=0;j<2*CP_ABE_PARA_K;j++)
            BNT.Trf_Char_to_G1(C1_msg->CT.ct2[i][j],C1_msg2.CT.ct2[i][j]);
    }
    for(int i=0;i<CP_ABE_PARA_N+1;i++)
    {
        for(int j=0;j<LSS_NC_SHARE_NUM;j++)
        {
            for(int k=0;k<CP_ABE_PARA_K;k++)
                BNT.Trf_Char_to_G1(C1_msg->CT.ct_rou[i][j][k],C1_msg2.CT.ct_rou[i][j][k]);
        }
    }
    #if 0
    BNT.Trf_Char_to_Big(C1_msg->CT.cipher_M,C1_msg2.CT.cipher_M);
    //FAC_TOK to FAC_TOK_C
    BNT.Trf_Char_to_G1(C1_msg->CT.cipher_tok.T1,C1_msg2.CT.cipher_tok.T1);
    BNT.Trf_Char_to_G1(C1_msg->CT.cipher_tok.T2,C1_msg2.CT.cipher_tok.T2);
    BNT.Trf_Char_to_G2(C1_msg->CT.cipher_tok.sigma1,C1_msg2.CT.cipher_tok.sigma1);
    BNT.Trf_Char_to_G2(C1_msg->CT.cipher_tok.sigma2,C1_msg2.CT.cipher_tok.sigma2);
    //FAC_SPK2 to FAC_SPK2_C
    BNT.Trf_Char_to_Big(C1_msg->CT.cipher_tok.spk2.c,C1_msg2.CT.cipher_tok.spk2.c);
    BNT.Trf_Char_to_Big(C1_msg->CT.cipher_tok.spk2.sd,C1_msg2.CT.cipher_tok.spk2.sd);
    BNT.Trf_Char_to_Big(C1_msg->CT.cipher_tok.spk2.sk,C1_msg2.CT.cipher_tok.spk2.sk);
    BNT.Trf_Char_to_GT(C1_msg->CT.cipher_tok.spk2.gama,C1_msg2.CT.cipher_tok.spk2.gama);
    #endif
    memcpy(C1_msg2.CT.cipher,C1_msg->CT.cipher,C1_msg->CT.cipher_len);
    C1_msg2.CT.cipher_len=C1_msg->CT.cipher_len;
    //FAC_USER_DISCLOSE_ATTR to FAC_USER_DISCLOSE_ATTR_C
    for(int i=0;i< FAC_PARA_D;i++)
        BNT.Trf_Char_to_Big(C1_msg->CT.disclose.x[i],C1_msg2.CT.disclose.x[i]);
    //CP_ABE_SHARE_INFO to CP_ABE_SHARE_INFO_C
    memcpy(&C1_msg2.CT.share,&C1_msg->CT.share,sizeof(CP_ABE_SHARE_INFO));
    //PriSrv_MSG_B to PriSrv_MSG_B-C
    //MACddh_SK to MACddh_SK_C
    for(int i=0;i<MACddh_PARA_N+1;i++)
    {
        BNT.Trf_Char_to_Big(C1_msg->msg_c.K_c.x[i],C1_msg2.msg_c.K_c.x[i]);
        BNT.Trf_Char_to_Big(C1_msg->msg_c.K_c.y[i],C1_msg2.msg_c.K_c.y[i]);
    }
    BNT.Trf_Char_to_Big(C1_msg->msg_c.K_c.z,C1_msg2.msg_c.K_c.z);
    //FAC_TOK yo FAC_TOK_C
    BNT.Trf_Char_to_G1(C1_msg->msg_c.tok_c.T1,C1_msg2.msg_c.tok_c.T1);
    BNT.Trf_Char_to_G1(C1_msg->msg_c.tok_c.T2,C1_msg2.msg_c.tok_c.T2);
    BNT.Trf_Char_to_G2(C1_msg->msg_c.tok_c.sigma1,C1_msg2.msg_c.tok_c.sigma1);
    BNT.Trf_Char_to_G2(C1_msg->msg_c.tok_c.sigma2,C1_msg2.msg_c.tok_c.sigma2);
    //FAC_USER_DISCLOSE_ATTR to FAC_USER_DISCLOSE_ATTR_C
    for(int i=0;i< FAC_PARA_D;i++)
        BNT.Trf_Char_to_Big(C1_msg->msg_c.Disclose_c.x[i],C1_msg2.msg_c.Disclose_c.x[i]);
    //PriSrv_M_C to PriSrv_M_C_C
    BNT.Trf_Char_to_Big(C1_msg->msg_c.M_c.sid,C1_msg2.msg_c.M_c.sid);
    BNT.Trf_Char_to_Big(C1_msg->msg_c.M_c.bid,C1_msg2.msg_c.M_c.bid);
    BNT.Trf_Char_to_G1(C1_msg->msg_c.M_c.X1,C1_msg2.msg_c.M_c.X1);
    BNT.Trf_Char_to_G2(C1_msg->msg_c.M_c.X2,C1_msg2.msg_c.M_c.X2);
    BNT.Trf_Char_to_G2(C1_msg->msg_c.M_c.Z,C1_msg2.msg_c.M_c.Z);
    //MACddh_MAC to MACddh_MAC_C
    BNT.Trf_Char_to_G1(C1_msg->sigma_c.sig_w,C1_msg2.sigma_c.sig_w);
    BNT.Trf_Char_to_G1(C1_msg->sigma_c.sig_x,C1_msg2.sigma_c.sig_x);
    BNT.Trf_Char_to_G1(C1_msg->sigma_c.sig_y,C1_msg2.sigma_c.sig_y);
    BNT.Trf_Char_to_G1(C1_msg->sigma_c.sig_z,C1_msg2.sigma_c.sig_z);

   // BNT.Trf_Char_to_GT(C1_msg->CT.K,C1_msg2.CT.K);

    //
    ret = prisrv.AMA_S(mpk2,cred_key_pk2,cred_s2,service_key2,service_z2,service_attr2,\
                       sid2,Dk_S_xrec2,DK_S_frec2,X_s2,X_c2,C1_msg2,S_msg2,ssk2);
    if(ret !=0) return ret;

    //PriSrv_S to PriSrv_S-C
    BNT.Trf_Big_to_Char(S_msg2.bid,S_msg->bid);
    BNT.Trf_Big_to_Char(S_msg2.sid,S_msg->sid);
    BNT.Trf_G1_to_Char(S_msg2.Y,S_msg->Y);
    //ACME_CIPHER to ACME_CIPHER_C
    BNT.Trf_GT_to_Char(S_msg2.CT.ct0,S_msg->CT.ct0);
    for(int i=0;i<2*CP_ABE_PARA_K;i++)
    {
        BNT.Trf_G1_to_Char(S_msg2.CT.ct1_[i],S_msg->CT.ct1_[i]);
        BNT.Trf_G1_to_Char(S_msg2.CT.ct1[i],S_msg->CT.ct1[i]);
    }
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        BNT.Trf_G1_to_Char(S_msg2.CT.ct2_[i],S_msg->CT.ct2_[i]);
    }
    for(int i=0;i<LSS_NC_SHARE_NUM;i++)
    {
        for(int j=0;j<2*CP_ABE_PARA_K;j++)
            BNT.Trf_G1_to_Char(S_msg2.CT.ct2[i][j],S_msg->CT.ct2[i][j]);
    }
    for(int i=0;i<CP_ABE_PARA_N+1;i++)
    {
        for(int j=0;j<LSS_NC_SHARE_NUM;j++)
        {
            for(int k=0;k<CP_ABE_PARA_K;k++)
                BNT.Trf_G1_to_Char(S_msg2.CT.ct_rou[i][j][k],S_msg->CT.ct_rou[i][j][k]);
        }
    }
#if 0
    BNT.Trf_Big_to_Char(S_msg2.CT.cipher_M,S_msg->CT.cipher_M);
    //FAC_TOK to FAC_TOK_C
    BNT.Trf_G1_to_Char(S_msg2.CT.cipher_tok.T1,S_msg->CT.cipher_tok.T1);
    BNT.Trf_G1_to_Char(S_msg2.CT.cipher_tok.T2,S_msg->CT.cipher_tok.T2);
    BNT.Trf_G2_to_Char(S_msg2.CT.cipher_tok.sigma1,S_msg->CT.cipher_tok.sigma1);
    BNT.Trf_G2_to_Char(S_msg2.CT.cipher_tok.sigma2,S_msg->CT.cipher_tok.sigma2);
    //FAC_SPK2 to FAC_SPK2_C
    BNT.Trf_Big_to_Char(S_msg2.CT.cipher_tok.spk2.c,S_msg->CT.cipher_tok.spk2.c);
    BNT.Trf_Big_to_Char(S_msg2.CT.cipher_tok.spk2.sd,S_msg->CT.cipher_tok.spk2.sd);
    BNT.Trf_Big_to_Char(S_msg2.CT.cipher_tok.spk2.sk,S_msg->CT.cipher_tok.spk2.sk);
    BNT.Trf_GT_to_Char(S_msg2.CT.cipher_tok.spk2.gama,S_msg->CT.cipher_tok.spk2.gama);
#endif

    //FAC_USER_DISCLOSE_ATTR to FAC_USER_DISCLOSE_ATTR_C
    for(int i=0;i< FAC_PARA_D;i++)
        BNT.Trf_Big_to_Char(S_msg2.CT.disclose.x[i],S_msg->CT.disclose.x[i]);
    //CP_ABE_SHARE_INFO to CP_ABE_SHARE_INFO_C
    memcpy(&S_msg->CT.share,&S_msg2.CT.share,sizeof(CP_ABE_SHARE_INFO));

    //MACddh_MAC to MACddh_MAC_C
    BNT.Trf_G1_to_Char(S_msg2.sigma_s.sig_w,S_msg->sigma_s.sig_w);
    BNT.Trf_G1_to_Char(S_msg2.sigma_s.sig_x,S_msg->sigma_s.sig_x);
    BNT.Trf_G1_to_Char(S_msg2.sigma_s.sig_y,S_msg->sigma_s.sig_y);
    BNT.Trf_G1_to_Char(S_msg2.sigma_s.sig_z,S_msg->sigma_s.sig_z);

    //MACddh_SK to MACddh_SK_C
    for(int i=0;i<MACddh_PARA_N+1;i++)
    {
        BNT.Trf_Big_to_Char(S_msg2.msg_s.Ks.x[i],S_msg->msg_s.Ks.x[i]);
        BNT.Trf_Big_to_Char(S_msg2.msg_s.Ks.y[i],S_msg->msg_s.Ks.y[i]);
    }
    BNT.Trf_Big_to_Char(S_msg2.msg_s.Ks.z,S_msg->msg_s.Ks.z);
  //  BNT.Trf_GT_to_Char(S_msg2.CT.K,S_msg->CT.K);


    //PriSrv_SSK to PriSrv_SSK_C
    BNT.Trf_Big_to_Char(ssk2.ssk,ssk->ssk);



    return ret;
}
int AMA_Cverify(struct ACME_MPK_C *mpk,struct  ACME_CRED_KEY_C *cred_key_pk,struct  ACME_CRED_U_C *cred_c,struct  ACME_USER_KEY_C *client_key,struct  ACME_ABE_DK_X_REC_C *Dk_C_xrec,struct  ACME_ABE_DK_f_REC_C *DK_C_frec,
                struct ACME_X_C *X_s,struct  ACME_X_C *X_c,struct  USER_ATTR_C *client_attr,struct  Big_C *uid,struct PriSrv_C1_C *C1_msg,struct PriSrv_S_C *S_msg,struct  PriSrv_SSK_C *ssk)
{
    int ret=0;
    ACME_MPK mpk2;
    ACME_CRED_KEY cred_key_pk2;
    ACME_CRED_U cred_c2;
    ACME_USER_KEY client_key2;
    ACME_ABE_DK_X_REC Dk_C_xrec2;
    ACME_ABE_DK_f_REC DK_C_frec2;
    ACME_X X_s2;
    ACME_X X_c2;
    USER_ATTR client_attr2;
    Big uid2;
    Big x;
    PriSrv_C1 C1_msg2;
    PriSrv_S S_msg2;
    PriSrv_SSK ssk2;
    //ACME_MPK_C to ACME_MPK
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        for(int j=0;j<2*CP_ABE_PARA_K;j++)
        {
            BNT.Trf_Char_to_G1(mpk->A1[i][j],mpk2.mpk.A1[i][j]);
        }
    }
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        for(int j=0;j<CP_ABE_PARA_K;j++)
        {
            BNT.Trf_Char_to_G1(mpk->AU01[i][j],mpk2.mpk.AU01[i][j]);
        }
    }
    for(int t=0;t<CP_ABE_PARA_N;t++)
    {
        for(int i=0;i<CP_ABE_PARA_K;i++)
        {
            for(int j=0;j<CP_ABE_PARA_K;j++)
            {
                BNT.Trf_Char_to_G1(mpk->AW1[t][i][j],mpk2.mpk.AW1[t][i][j]);
            }
        }
    }
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        BNT.Trf_Char_to_GT(mpk->eAV[i],mpk2.mpk.eAV[i]);
    }
    // ACME_CRED_KEY_C to ACME_CRED_KEY
    BNT.Trf_Char_to_Big(cred_key_pk->sk.x,cred_key_pk2.cred_key.sk.x);
    BNT.Trf_Char_to_G1(cred_key_pk->pk.W,cred_key_pk2.cred_key.pk.W);

    for(int i=0;i<FAC_PARA_N+2;i++)
    {
        BNT.Trf_Char_to_Big(cred_key_pk->sk.y[i],cred_key_pk2.cred_key.sk.y[i]);
        BNT.Trf_Char_to_G2(cred_key_pk->pk.X[i],cred_key_pk2.cred_key.pk.X[i]);
        BNT.Trf_Char_to_G1(cred_key_pk->pk.Y[i],cred_key_pk2.cred_key.pk.Y[i]);
    }
    for(int i=0;i<FAC_PARA_N+2;i++)
    {
        for(int j=0;j<FAC_PARA_N+2;j++)
        {
            BNT.Trf_Char_to_G1(cred_key_pk->pk.Z[i][j],cred_key_pk2.cred_key.pk.Z[i][j]);
        }
    }

    //ACME_CRED_U_C to ACME_CRED_U
    BNT.Trf_Char_to_G2(cred_c->sigma1,cred_c2.cred_u.sigma1);
    BNT.Trf_Char_to_G2(cred_c->sigma2,cred_c2.cred_u.sigma2);
    //ACME_USER_KEY_C to ACME_USER_KEY
    BNT.Trf_Char_to_Big(client_key->usk.usk,client_key2.user_key.usk.usk);
    BNT.Trf_Char_to_G2(client_key->upk.upk1,client_key2.user_key.upk.upk1);
    BNT.Trf_Char_to_G1(client_key->upk.upk2,client_key2.user_key.upk.upk2);
    //ACME_ABE_DK_X_REC_C to ACME_ABE_DK_X_REC
    for(int i=0;i<2*CP_ABE_PARA_K;i++)
    {
        BNT.Trf_Char_to_G2(Dk_C_xrec->sk.sk1[i],Dk_C_xrec2.sk.sk1[i]);
        BNT.Trf_Char_to_G2(Dk_C_xrec->sk.sk3[i],Dk_C_xrec2.sk.sk3[i]);
    }
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        BNT.Trf_Char_to_G2(Dk_C_xrec->sk.sk2[i],Dk_C_xrec2.sk.sk2[i]);
    }
    //ACME_ABE_DK_f_REC_C to ACME_ABE_DK_f_REC

    for(int i=0;i<LSS_NC_SHARE_NUM;i++)
    {
        for(int j=0;j<CP_ABE_PARA_K;j++)
        {
            BNT.Trf_Char_to_G2(DK_C_frec->dk[i][j],DK_C_frec2.dk[i][j]);
        }
    }
    for(int i=0;i<CP_ABE_PARA_N+1;i++)
    {
        for(int j=0;j<LSS_NC_SHARE_NUM;j++)
        {
            for(int k=0;k<2*CP_ABE_PARA_K;k++)
            {
                BNT.Trf_Char_to_G2(DK_C_frec->dk_rou[i][j][k],DK_C_frec2.dk_rou[i][j][k]);
            }
        }
    }
    memcpy(&DK_C_frec2.share,&DK_C_frec->share,sizeof(CP_ABE_SHARE_INFO));
    //ACME_X_C to ACME_X
    X_s2.X.x[0]=X_s->x[0];X_s2.X.x[1]=X_s->x[1];X_s2.X.x[2]=X_s->x[2];
    X_c2.X.x[0]=X_c->x[0];X_c2.X.x[1]=X_c->x[1];X_c2.X.x[2]=X_c->x[2];
    //USER_ATTR_C  to USER_ATTR
    BNT.Trf_Char_to_Big(*uid,uid2);
    for(int i=1;i<FAC_PARA_N+1;i++)
        BNT.Trf_Char_to_Big(client_attr->x[i],client_attr2.x[i]);
    //////// PriSrv_C1_C to PriSrv_C1
    BNT.Trf_Char_to_Big(C1_msg->x1,C1_msg2.x1);
    BNT.Trf_Char_to_Big(C1_msg->x2,C1_msg2.x2);
    //ACME_CIPHER to ACME_CIPHER_C

    BNT.Trf_Char_to_GT(C1_msg->CT.ct0,C1_msg2.CT.ct0);
    for(int i=0;i<2*CP_ABE_PARA_K;i++)
    {
        BNT.Trf_Char_to_G1(C1_msg->CT.ct1_[i],C1_msg2.CT.ct1_[i]);
        BNT.Trf_Char_to_G1(C1_msg->CT.ct1[i],C1_msg2.CT.ct1[i]);
    }
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        BNT.Trf_Char_to_G1(C1_msg->CT.ct2_[i],C1_msg2.CT.ct2_[i]);
    }
    for(int i=0;i<LSS_NC_SHARE_NUM;i++)
    {
        for(int j=0;j<2*CP_ABE_PARA_K;j++)
            BNT.Trf_Char_to_G1(C1_msg->CT.ct2[i][j],C1_msg2.CT.ct2[i][j]);
    }
    for(int i=0;i<CP_ABE_PARA_N+1;i++)
    {
        for(int j=0;j<LSS_NC_SHARE_NUM;j++)
        {
            for(int k=0;k<CP_ABE_PARA_K;k++)
                BNT.Trf_Char_to_G1(C1_msg->CT.ct_rou[i][j][k],C1_msg2.CT.ct_rou[i][j][k]);
        }
    }
    #if 0
    BNT.Trf_Big_to_Char(C1_msg2.CT.cipher_M,C1_msg->CT.cipher_M);
    //FAC_TOK to FAC_TOK_C
    BNT.Trf_Char_to_G1(C1_msg->CT.cipher_tok.T1,C1_msg2.CT.cipher_tok.T1);
    BNT.Trf_Char_to_G1(C1_msg->CT.cipher_tok.T2,C1_msg2.CT.cipher_tok.T2);
    BNT.Trf_Char_to_G2(C1_msg->CT.cipher_tok.sigma1,C1_msg2.CT.cipher_tok.sigma1);
    BNT.Trf_Char_to_G2(C1_msg->CT.cipher_tok.sigma2,C1_msg2.CT.cipher_tok.sigma2);
    //FAC_SPK2 to FAC_SPK2_C
    BNT.Trf_Char_to_Big(C1_msg->CT.cipher_tok.spk2.c,C1_msg2.CT.cipher_tok.spk2.c);
    BNT.Trf_Char_to_Big(C1_msg->CT.cipher_tok.spk2.sd,C1_msg2.CT.cipher_tok.spk2.sd);
    BNT.Trf_Char_to_Big(C1_msg->CT.cipher_tok.spk2.sk,C1_msg2.CT.cipher_tok.spk2.sk);
    BNT.Trf_Char_to_GT(C1_msg->CT.cipher_tok.spk2.gama,C1_msg2.CT.cipher_tok.spk2.gama);
    #endif
    //FAC_USER_DISCLOSE_ATTR to FAC_USER_DISCLOSE_ATTR_C
    for(int i=0;i< FAC_PARA_D;i++)
        BNT.Trf_Char_to_Big(C1_msg->CT.disclose.x[i],C1_msg2.CT.disclose.x[i]);
    //CP_ABE_SHARE_INFO to CP_ABE_SHARE_INFO_C
    memcpy(&C1_msg2.CT.share,&C1_msg->CT.share,sizeof(CP_ABE_SHARE_INFO));
    //PriSrv_MSG_B to PriSrv_MSG_B-C
    //MACddh_SK to MACddh_SK_C
    for(int i=0;i<MACddh_PARA_N+1;i++)
    {
        BNT.Trf_Char_to_Big(C1_msg->msg_c.K_c.x[i],C1_msg2.msg_c.K_c.x[i]);
        BNT.Trf_Char_to_Big(C1_msg->msg_c.K_c.y[i],C1_msg2.msg_c.K_c.y[i]);
    }
    BNT.Trf_Char_to_Big(C1_msg->msg_c.K_c.z,C1_msg2.msg_c.K_c.z);
    //FAC_TOK yo FAC_TOK_C
    BNT.Trf_Char_to_G1(C1_msg->msg_c.tok_c.T1,C1_msg2.msg_c.tok_c.T1);
    BNT.Trf_Char_to_G1(C1_msg->msg_c.tok_c.T2,C1_msg2.msg_c.tok_c.T2);
    BNT.Trf_Char_to_G2(C1_msg->msg_c.tok_c.sigma1,C1_msg2.msg_c.tok_c.sigma1);
    BNT.Trf_Char_to_G2(C1_msg->msg_c.tok_c.sigma2,C1_msg2.msg_c.tok_c.sigma2);
    //FAC_USER_DISCLOSE_ATTR to FAC_USER_DISCLOSE_ATTR_C
    for(int i=0;i< FAC_PARA_D;i++)
        BNT.Trf_Char_to_Big(C1_msg->msg_c.Disclose_c.x[i],C1_msg2.msg_c.Disclose_c.x[i]);
    //PriSrv_M_C to PriSrv_M_C_C
    BNT.Trf_Char_to_Big(C1_msg->msg_c.M_c.sid,C1_msg2.msg_c.M_c.sid);
    BNT.Trf_Char_to_Big(C1_msg->msg_c.M_c.bid,C1_msg2.msg_c.M_c.bid);
    BNT.Trf_Char_to_G1(C1_msg->msg_c.M_c.X1,C1_msg2.msg_c.M_c.X1);
    BNT.Trf_Char_to_G2(C1_msg->msg_c.M_c.X2,C1_msg2.msg_c.M_c.X2);
    BNT.Trf_Char_to_G2(C1_msg->msg_c.M_c.Z,C1_msg2.msg_c.M_c.Z);
    //MACddh_MAC to MACddh_MAC_C
    BNT.Trf_Char_to_G1(C1_msg->sigma_c.sig_w,C1_msg2.sigma_c.sig_w);
    BNT.Trf_Char_to_G1(C1_msg->sigma_c.sig_x,C1_msg2.sigma_c.sig_x);
    BNT.Trf_Char_to_G1(C1_msg->sigma_c.sig_y,C1_msg2.sigma_c.sig_y);
    BNT.Trf_Char_to_G1(C1_msg->sigma_c.sig_z,C1_msg2.sigma_c.sig_z);
    ////////////////////////////////////
    //PriSrv_S to PriSrv_S-C
    BNT.Trf_Char_to_Big(S_msg->bid,S_msg2.bid);
    BNT.Trf_Char_to_Big(S_msg->sid,S_msg2.sid);
    BNT.Trf_Char_to_G1(S_msg->Y,S_msg2.Y);
    //ACME_CIPHER to ACME_CIPHER_C
    BNT.Trf_Char_to_GT(S_msg->CT.ct0,S_msg2.CT.ct0);
    for(int i=0;i<2*CP_ABE_PARA_K;i++)
    {
        BNT.Trf_Char_to_G1(S_msg->CT.ct1_[i],S_msg2.CT.ct1_[i]);
        BNT.Trf_Char_to_G1(S_msg->CT.ct1[i],S_msg2.CT.ct1[i]);
    }
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        BNT.Trf_Char_to_G1(S_msg->CT.ct2_[i],S_msg2.CT.ct2_[i]);
    }
    for(int i=0;i<LSS_NC_SHARE_NUM;i++)
    {
        for(int j=0;j<2*CP_ABE_PARA_K;j++)
            BNT.Trf_Char_to_G1(S_msg->CT.ct2[i][j],S_msg2.CT.ct2[i][j]);
    }
    for(int i=0;i<CP_ABE_PARA_N+1;i++)
    {
        for(int j=0;j<LSS_NC_SHARE_NUM;j++)
        {
            for(int k=0;k<CP_ABE_PARA_K;k++)
                BNT.Trf_Char_to_G1(S_msg->CT.ct_rou[i][j][k],S_msg2.CT.ct_rou[i][j][k]);
        }
    }
    #if 0
    BNT.Trf_Char_to_Big(S_msg->CT.cipher_M,S_msg2.CT.cipher_M);
    //FAC_TOK to FAC_TOK_C
    BNT.Trf_Char_to_G1(S_msg->CT.cipher_tok.T1,S_msg2.CT.cipher_tok.T1);
    BNT.Trf_Char_to_G1(S_msg->CT.cipher_tok.T2,S_msg2.CT.cipher_tok.T2);
    BNT.Trf_Char_to_G2(S_msg->CT.cipher_tok.sigma1,S_msg2.CT.cipher_tok.sigma1);
    BNT.Trf_Char_to_G2(S_msg->CT.cipher_tok.sigma2,S_msg2.CT.cipher_tok.sigma2);
    //FAC_SPK2 to FAC_SPK2_C
    BNT.Trf_Char_to_Big(S_msg->CT.cipher_tok.spk2.c,S_msg2.CT.cipher_tok.spk2.c);
    BNT.Trf_Char_to_Big(S_msg->CT.cipher_tok.spk2.sd,S_msg2.CT.cipher_tok.spk2.sd);
    BNT.Trf_Char_to_Big(S_msg->CT.cipher_tok.spk2.sk,S_msg2.CT.cipher_tok.spk2.sk);
    BNT.Trf_Char_to_GT(S_msg->CT.cipher_tok.spk2.gama,S_msg2.CT.cipher_tok.spk2.gama);
    #endif
    //FAC_USER_DISCLOSE_ATTR to FAC_USER_DISCLOSE_ATTR_C
    for(int i=0;i< FAC_PARA_D;i++)
        BNT.Trf_Char_to_Big(S_msg->CT.disclose.x[i],S_msg2.CT.disclose.x[i]);
    //CP_ABE_SHARE_INFO to CP_ABE_SHARE_INFO_C
    memcpy(&S_msg2.CT.share,&S_msg->CT.share,sizeof(CP_ABE_SHARE_INFO));

    //MACddh_MAC to MACddh_MAC_C
    BNT.Trf_Char_to_G1(S_msg->sigma_s.sig_w,S_msg2.sigma_s.sig_w);
    BNT.Trf_Char_to_G1(S_msg->sigma_s.sig_x,S_msg2.sigma_s.sig_x);
    BNT.Trf_Char_to_G1(S_msg->sigma_s.sig_y,S_msg2.sigma_s.sig_y);
    BNT.Trf_Char_to_G1(S_msg->sigma_s.sig_z,S_msg2.sigma_s.sig_z);

    //MACddh_SK_c to MACddh_SK
    for(int i=0;i<MACddh_PARA_N+1;i++)
    {
        BNT.Trf_Char_to_Big(S_msg->msg_s.Ks.x[i],S_msg2.msg_s.Ks.x[i]);
        BNT.Trf_Char_to_Big(S_msg->msg_s.Ks.y[i],S_msg2.msg_s.Ks.y[i]);
    }
    BNT.Trf_Char_to_Big(S_msg->msg_s.Ks.z,S_msg2.msg_s.Ks.z);
  //  BNT.Trf_Char_to_GT(S_msg->CT.K,S_msg2.CT.K);

    //
    ret=prisrv.AMA_Cverify(mpk2,cred_key_pk2,cred_c2,client_key2,Dk_C_xrec2,\
                           DK_C_frec2,X_s2,X_c2,client_attr2,uid2,x,C1_msg2,S_msg2,ssk2);
    if(ret !=0) return ret;
    //
    BNT.Trf_Big_to_Char(ssk2.ssk,ssk->ssk);


    return ret;
}
