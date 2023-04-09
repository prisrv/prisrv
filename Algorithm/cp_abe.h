#ifndef CP_ABE_H
#define CP_ABE_H
#include "fac.h"
#include "lss_nc.h"
#include "pairing_3.h"
#define CP_ABE_PARA_K 2
#define CP_ABE_PARA_N 3

struct CP_APE_X
{
    int x[CP_ABE_PARA_N];//={1,0,1};
};

struct CP_ABE_MSK
{
    Big A[CP_ABE_PARA_K][2*CP_ABE_PARA_K];
    Big B[CP_ABE_PARA_K][CP_ABE_PARA_K];
    Big U0[2*CP_ABE_PARA_K][CP_ABE_PARA_K];
    Big W[CP_ABE_PARA_N][2*CP_ABE_PARA_K][CP_ABE_PARA_K];
    Big V[2*CP_ABE_PARA_K];
};
struct CP_ABE_MPK
{
    G1 A1[CP_ABE_PARA_K][2*CP_ABE_PARA_K];
    G1 AU01[CP_ABE_PARA_K][CP_ABE_PARA_K];
    G1 AW1[CP_ABE_PARA_N][CP_ABE_PARA_K][CP_ABE_PARA_K];
    G2 V2[2*CP_ABE_PARA_K];
    GT eAV[CP_ABE_PARA_K];
};
struct CP_ABE_SK
{
    G2 sk1[2*CP_ABE_PARA_K];
    G2 sk2[CP_ABE_PARA_K];
    G2 sk3[2*CP_ABE_PARA_K];
};
struct CP_ABE_CIPHER
{
    GT ct1;
    G1 ct2[2*CP_ABE_PARA_K];
    G1 ct3[LSS_NC_SHARE_NUM][2*CP_ABE_PARA_K];
    G1 ct_rou[CP_ABE_PARA_N+1][LSS_NC_SHARE_NUM][CP_ABE_PARA_K];

};

struct CP_ABE_SHARE_INFO
{
    int rou[LSS_NC_SHARE_NUM];
    int w[LSS_NC_SHARE_NUM];
    int fMatrix[LSS_NC_PARA_N+1][LSS_NC_SHARE_NUM];
#if 0//test
    GT uBr[LSS_NC_SHARE_NUM];
    GT s_Avj[LSS_NC_SHARE_NUM];
    GT s_Av;
    GT sAv;
    LSS_NC_SHARE_INFO share_info[2*CP_ABE_PARA_K];

#endif
};

class CP_ABE
{
private:
    PFC *pfc;
    LSS_NC *lss;
#if 0
    G1 g;
    G2 h;
    GT gt;
#endif
public:
    CP_ABE(PFC *p);
    ~CP_ABE();
    int SetUp(CP_ABE_MSK &msk,CP_ABE_MPK &mpk);
    int KeyGen(CP_ABE_MSK &msk,CP_APE_X &X,CP_ABE_SK &sk);
    int Enc(CP_ABE_MPK &mpk, GT &M, CP_ABE_CIPHER &cipher, CP_ABE_SHARE_INFO &share);
    int Dec(CP_ABE_MPK &mpk,CP_APE_X &X,CP_ABE_SK &sk,CP_ABE_CIPHER &cipher,CP_ABE_SHARE_INFO &share,GT &M);

};

#endif // CP_ABE_H
