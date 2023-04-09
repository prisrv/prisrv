#ifndef BN_STRUCT_H
#define BN_STRUCT_H

#define WLEN 4
struct Big_C
{
    unsigned int len;
    unsigned long w[WLEN];
};
struct G1_C
{
    struct Big_C X;
    struct Big_C Y;
    struct Big_C Z;
};
struct G2_C
{
    struct Big_C Xa,Xb;
    struct Big_C Ya,Yb;
    struct Big_C Za,Zb;
};
struct GT_C
{
    struct Big_C Aaa,Aab,Aba,Abb;
   // bool Aunitary;
    struct Big_C Baa,Bab,Bba,Bbb;
   // bool Bunitary;
    struct Big_C Caa,Cab,Cba,Cbb;
   // bool Cunitary;
};

#define ST_CP_ABE_PARA_K 3 //==CP_ABE_PARA_K
#define ST_CP_ABE_PARA_N 3 //==CP_ABE_PARA_N
#define ST_FAC_PARA_N 5 //parameter n [1,n] == FAC_PARA_N
#define ST_FAC_PARA_D 2 //parameter |I| [1,|I|]  ==FAC_PARA_D
#define ST_LSS_NC_PARA_N 3//== CP_ABE_PARA_N
#define ST_LSS_NC_SHARE_NUM 9 //==LSS_NC_SHARE_NUM
#define ST_MACddh_PARA_N 7 // == MACddh_PARA_N

struct ACME_MPK_C
{
    struct G1_C A1[ST_CP_ABE_PARA_K][2*ST_CP_ABE_PARA_K];
    struct G1_C AU01[ST_CP_ABE_PARA_K][ST_CP_ABE_PARA_K];
    struct G1_C AW1[ST_CP_ABE_PARA_N][ST_CP_ABE_PARA_K][ST_CP_ABE_PARA_K];
    struct G2_C V2[2*ST_CP_ABE_PARA_K];
    struct GT_C eAV[ST_CP_ABE_PARA_K];

};
struct ACME_MSK_C
{
    struct Big_C A[ST_CP_ABE_PARA_K][2*ST_CP_ABE_PARA_K];
    struct Big_C B[ST_CP_ABE_PARA_K][ST_CP_ABE_PARA_K];
    struct Big_C U0[2*ST_CP_ABE_PARA_K][ST_CP_ABE_PARA_K];
    struct Big_C W[ST_CP_ABE_PARA_N][2*ST_CP_ABE_PARA_K][ST_CP_ABE_PARA_K];
    struct Big_C V[2*ST_CP_ABE_PARA_K];

};
struct FAC_CRED_KEY_SK_C
{
    struct Big_C x;
    struct Big_C y[ST_FAC_PARA_N+2];

};
struct FAC_CRED_KEY_PK_C
{
    struct G1_C W;
    struct G2_C X[ST_FAC_PARA_N+2];
    struct G1_C Y[ST_FAC_PARA_N+2];
    struct G1_C Z[ST_FAC_PARA_N+2][ST_FAC_PARA_N+2];
};

struct ACME_CRED_KEY_C
{
    struct FAC_CRED_KEY_SK_C sk;
    struct FAC_CRED_KEY_PK_C pk;

};
struct FAC_USER_SK_C
{
    struct Big_C usk;
};
struct FAC_USER_PK_C
{
    struct G2_C upk1;
    struct G1_C upk2;
};

struct ACME_USER_KEY_C
{
    struct FAC_USER_SK_C usk;
    struct FAC_USER_PK_C upk;
};

struct USER_ATTR_C
{
    struct Big_C x[ST_FAC_PARA_N+2];

};
struct ACME_SPK1_C
{
    struct Big_C c,s;
    struct G2_C gam1;
    struct G1_C gam2;
};

struct ACME_USER_PK_C
{
    struct FAC_USER_PK_C upk;

};
struct ACME_CRED_U_C
{
    struct G2_C sigma1,sigma2;

};
struct ACME_CRED_KEY_PK_C
{
    struct FAC_CRED_KEY_PK_C pk;

};
struct ACME_X_C
{
    int x[ST_CP_ABE_PARA_N];//={1,0,1};
};

struct CP_ABE_SK_C
{
    struct G2_C sk1[2*ST_CP_ABE_PARA_K];
    struct G2_C sk2[ST_CP_ABE_PARA_K];
    struct G2_C sk3[2*ST_CP_ABE_PARA_K];
};
struct ACME_ABE_DK_X_REC_C
{
    struct CP_ABE_SK_C sk;
};
struct CP_ABE_SHARE_INFO_C
{
    int rou[ST_LSS_NC_SHARE_NUM];
    int w[ST_LSS_NC_SHARE_NUM];
    int fMatrix[ST_LSS_NC_PARA_N+1][ST_LSS_NC_SHARE_NUM];
};
struct ACME_ABE_DK_f_REC_C
{
    struct G2_C dk[ST_LSS_NC_SHARE_NUM][ST_CP_ABE_PARA_K];
    struct G2_C dk_rou[ST_CP_ABE_PARA_N+1][ST_LSS_NC_SHARE_NUM][2*ST_CP_ABE_PARA_K];
    struct CP_ABE_SHARE_INFO_C share;

};
struct FAC_SPK2_C
{
    struct Big_C c,sd,sk;
    struct GT_C gama;
};
struct FAC_TOK_C
{
    struct G1_C T1,T2;
    struct G2_C sigma1,sigma2;
    struct FAC_SPK2_C spk2;
};
struct FAC_USER_DISCLOSE_ATTR_C
{
    struct Big_C x[ST_FAC_PARA_D];

};
#if 0
struct ACME_CIPHER_CC
{
    struct GT_C ct0;
    struct G1_C ct1_[2*ST_CP_ABE_PARA_K];
    struct G1_C ct2_[ST_CP_ABE_PARA_K];
    struct G1_C ct1[2*ST_CP_ABE_PARA_K];
    struct G1_C ct2[ST_LSS_NC_SHARE_NUM][2*ST_CP_ABE_PARA_K];
    struct G1_C ct_rou[ST_CP_ABE_PARA_N+1][ST_LSS_NC_SHARE_NUM][ST_CP_ABE_PARA_K];

};
#endif
struct ACME_CIPHER_C
{
    struct GT_C ct0;
    struct G1_C ct1_[2*ST_CP_ABE_PARA_K];
    struct G1_C ct2_[ST_CP_ABE_PARA_K];
    struct G1_C ct1[2*ST_CP_ABE_PARA_K];
    struct G1_C ct2[ST_LSS_NC_SHARE_NUM][2*ST_CP_ABE_PARA_K];
    struct G1_C ct_rou[ST_CP_ABE_PARA_N+1][ST_LSS_NC_SHARE_NUM][ST_CP_ABE_PARA_K];
#if 0 //test
    struct GT_C K;

    struct Big_C cipher_M;
    struct FAC_TOK_C cipher_tok;
#endif
    char cipher[1360];
    unsigned int cipher_len;
    struct FAC_USER_DISCLOSE_ATTR_C disclose;
    struct CP_ABE_SHARE_INFO_C share;

};

struct PriSrv_MSG_B_C
{
    struct Big_C bid;
    struct Big_C Service_type;
    struct Big_C Service_par;
    struct G2_C Z;

};
struct MACddh_SK_C
{
    struct Big_C x[ST_MACddh_PARA_N+1];
    struct Big_C y[ST_MACddh_PARA_N+1];
    struct Big_C z;
};
struct PriSrv_M_C_C
{
    struct Big_C bid;
    struct Big_C sid;
    struct G1_C X1;
    struct G2_C X2,Z;
};
struct PriSrv_MSG_C_C
{
    struct MACddh_SK_C K_c;
    struct FAC_TOK_C tok_c;
    struct FAC_USER_DISCLOSE_ATTR_C Disclose_c;
    struct PriSrv_M_C_C M_c;
};
struct MACddh_MAC_C
{
    struct G1_C sig_x,sig_y,sig_z,sig_w;
};
struct PriSrv_C1_C
{
    struct Big_C x1,x2;
    struct ACME_CIPHER_C CT;
    struct PriSrv_MSG_C_C msg_c;
    struct MACddh_MAC_C sigma_c;
};
struct PriSrv_MSG_S_C
{
    struct MACddh_SK_C Ks;
    struct FAC_TOK_C toks;
    struct FAC_USER_DISCLOSE_ATTR_C Disclose_s;
};
struct PriSrv_S_C
{
    struct Big_C bid;
    struct Big_C sid;
    struct G1_C Y;
    struct ACME_CIPHER_C CT;
    struct PriSrv_MSG_S_C msg_s;
    struct MACddh_MAC_C sigma_s;

};

struct PriSrv_SSK_C
{
    struct Big_C ssk;

};
struct ACME_TOK_C
{
    struct FAC_TOK_C tok;

};

#endif // BN_STRUCT_H
