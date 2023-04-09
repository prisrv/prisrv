#ifndef ACME_H
#define ACME_H
#include"pairing_3.h"
#include "fac.h"
#include "cp_abe.h"

struct ACME_MSK
{
    CP_ABE_MSK msk;

};
struct ACME_MPK
{
    CP_ABE_MPK mpk;
};
struct ACME_CRED_KEY
{
    FAC_CRED_KEY cred_key;

};

struct ACME_USER_KEY
{
    FAC_USER_KEY user_key;
};
struct ACME_CRED_KEY_PK
{
    FAC_CRED_KEY_PK pk;
};
struct ACME_SPK1
{
    FAC_SPK1 spk1;
};
struct ACME_USER_PK
{
    FAC_USER_PK upk;
};
struct ACME_CRED_U
{
    FAC_CRED_U cred_u;
};
struct ACME_ABE_DK_X_REC
{
    CP_ABE_SK sk;
};
struct ACME_X
{
    CP_APE_X X;
};
struct ACME_ABE_DK_f_REC
{
    G2 dk[LSS_NC_SHARE_NUM][CP_ABE_PARA_K];
    G2 dk_rou[CP_ABE_PARA_N+1][LSS_NC_SHARE_NUM][2*CP_ABE_PARA_K];
    CP_ABE_SHARE_INFO share;
#if 0//test
    Big V[2*CP_ABE_PARA_K];

#endif
};
struct ACME_CIPHER
{
    GT ct0;
    G1 ct1_[2*CP_ABE_PARA_K];
    G1 ct2_[CP_ABE_PARA_K];
    G1 ct1[2*CP_ABE_PARA_K];
    G1 ct2[LSS_NC_SHARE_NUM][2*CP_ABE_PARA_K];
    G1 ct_rou[CP_ABE_PARA_N+1][LSS_NC_SHARE_NUM][CP_ABE_PARA_K];
#if 0 //test
    GT K;
    Big cipher_M;
    FAC_TOK cipher_tok;
#endif
    char cipher[1360];
    unsigned int cipher_len;
    

    FAC_USER_DISCLOSE_ATTR disclose;
    CP_ABE_SHARE_INFO share;
};

struct ACME_TOK
{
    FAC_TOK tok;
};
struct ACME_PLAIN
{
    ACME_TOK tok;
    Big M;

};
class ACME
{
private:
    LSS_NC lss;
    PFC *pfc;
    FAC fac;
    CP_ABE cp_abe;
public:
    ACME(PFC *p);
    ~ACME();
    int SetUp(ACME_MSK &msk,ACME_MPK &mpk);
    int CredKeyGen(ACME_CRED_KEY &cred_key);
    int UserKeyGen(ACME_USER_KEY &user_key);
    int IssueUser_Send(ACME_USER_KEY &user_key,USER_ATTR &attr,Big &uid,ACME_SPK1 &spk1);
    int IssueIssuer(ACME_CRED_KEY &cred_key,USER_ATTR &attr,Big &uid,ACME_SPK1 &spk1,ACME_USER_PK &upk,ACME_CRED_U &cred_u);
    int IssueUser_Verify(ACME_CRED_KEY_PK &pk,ACME_CRED_U &cred_u,USER_ATTR &attr,Big &uid,ACME_USER_KEY &user_key);
    int DKeyGen(ACME_MSK &msk, ACME_X &X_rcv, ACME_ABE_DK_X_REC &Dk_xrec);
    int PolGen(ACME_MSK &msk,ACME_ABE_DK_f_REC &DK_f_rec);
    int Enc(ACME_MPK &mpk, ACME_CRED_KEY cred_key_pk, ACME_CRED_U &cred_snd, ACME_USER_KEY &user_key, USER_ATTR &attr, Big &uid, ACME_X &X_snd, Big &M, ACME_CIPHER &cipher);
    int Den(ACME_CRED_KEY cred_key_pk,ACME_ABE_DK_X_REC &Dk_xrec,ACME_ABE_DK_f_REC &DK_f_rec,ACME_X &X_snd,ACME_X &X_rcv,ACME_CIPHER &cipher,ACME_PLAIN &plain);
    int Trace(ACME_CRED_KEY &cred_key, ACME_TOK &tok, Big &uid);

};

#endif // ACME_H
