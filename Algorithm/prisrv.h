#ifndef PRISRV_H
#define PRISRV_H
#include "acme.h"
#include "macddh.h"
#include <fstream>
#include <iostream>
using namespace std;

struct PriSrv_MSG_B
{
    Big bid;
    Big Service_type;
    Big Service_par;
    G2 Z;
};
struct PriSrv_M_C
{
    Big bid;
    Big sid;
    G1 X1;
    G2 X2,Z;
};
struct PriSrv_MSG_C
{
    MACddh_SK K_c;
    FAC_TOK tok_c;
    FAC_USER_DISCLOSE_ATTR Disclose_c;
    PriSrv_M_C M_c;
};
struct PriSrv_MSG_S
{
    MACddh_SK Ks;
    FAC_TOK toks;
    FAC_USER_DISCLOSE_ATTR Disclose_s;
};
struct PriSrv_C1
{
    Big x1,x2;
    ACME_CIPHER CT;
    PriSrv_MSG_C msg_c;
    MACddh_MAC sigma_c;
};
struct PriSrv_S
{
    Big bid;
    Big sid;
    G1 Y;
    ACME_CIPHER CT;
    PriSrv_MSG_S msg_s;
    MACddh_MAC sigma_s;
};
struct PriSrv_SSK
{
    Big ssk;
};
class PriSrv
{
private:
    PFC *pfc;

    MACddh mac_ddh;
    ACME acme;
    FAC fac;

public:

    PriSrv(PFC *p);
    ~PriSrv();
    int SetUp(ACME_MPK &mpk, ACME_MSK &msk);
    int CredKeyGen(ACME_CRED_KEY &cred_key);
    int UserKeyGen(ACME_USER_KEY &user_key);
    int Issue_Send(ACME_USER_KEY &user_key,USER_ATTR &attr,Big &uid,ACME_SPK1 &spk1);
    int Issue_Issuer(ACME_CRED_KEY &cred_key,USER_ATTR &attr,Big &uid,ACME_SPK1 &spk1,ACME_USER_PK &upk,ACME_CRED_U &cred_u);
    int Issue_Verify(ACME_CRED_KEY_PK &pk,ACME_CRED_U &cred_u,USER_ATTR &attr,Big &uid,ACME_USER_KEY &user_key);
    int DKeyGen(ACME_MSK &msk, ACME_X &X_rcv, ACME_ABE_DK_X_REC &Dk_xrec);
    int PolGen(ACME_MSK &msk,ACME_ABE_DK_f_REC &DK_frec);
    int Broadcast(ACME_MPK &mpk, ACME_CRED_KEY &cred_key_pk, ACME_CRED_U &cred_s, ACME_USER_KEY &service_key, USER_ATTR &service_attr, Big &bid, ACME_X &X_s, ACME_CIPHER &cipher, PriSrv_MSG_B &msg_b, Big &service_z);
    int AMA_Cinit(ACME_MPK &mpk,ACME_CRED_KEY &cred_key_pk,ACME_CRED_U &cred_c,ACME_USER_KEY &client_key,ACME_ABE_DK_X_REC &Dk_C_xrec,ACME_ABE_DK_f_REC &DK_C_frec,ACME_X &X_s, ACME_X &X_c,USER_ATTR &client_attr,Big &uid,ACME_CIPHER &cipher,PriSrv_MSG_B &msg_b,Big &x,PriSrv_C1 &C1_msg);
    int AMA_S(ACME_MPK &mpk, ACME_CRED_KEY &cred_key_pk, ACME_CRED_U &cred_s, ACME_USER_KEY &service_key, Big &service_z, USER_ATTR &service_attr, Big &sid, ACME_ABE_DK_X_REC &Dk_S_xrec, ACME_ABE_DK_f_REC &DK_S_frec, ACME_X &X_s, ACME_X &X_c, PriSrv_C1 &C1_msg, PriSrv_S &S_msg, PriSrv_SSK &ssk);
    int AMA_Cverify(ACME_MPK &mpk, ACME_CRED_KEY &cred_key_pk, ACME_CRED_U &cred_c, ACME_USER_KEY &client_key, ACME_ABE_DK_X_REC &Dk_C_xrec, ACME_ABE_DK_f_REC &DK_C_frec, ACME_X &X_s, ACME_X &X_c, USER_ATTR &client_attr, Big &uid, Big &x,PriSrv_C1 &C1_msg,PriSrv_S &S_msg, PriSrv_SSK &ssk);
    int Trace(ACME_CRED_KEY &cred_key, ACME_TOK &tok, Big &uid);
};

#endif // PRISRV_H
