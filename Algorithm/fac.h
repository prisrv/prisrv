#ifndef FAC_H
#define FAC_H
#include <list>
#include <iostream>
#include "pairing_3.h"

#define FAC_PARA_N 5 //parameter n [1,n]
#define FAC_PARA_D 2 //parameter |I| [1,|I|]
struct FAC_PP
{

};
struct FAC_CRED_KEY_SK
{
    Big x;
    Big y[FAC_PARA_N+2];

};
struct FAC_CRED_KEY_PK
{
    G1 W;
    G2 X[FAC_PARA_N+2];
    G1 Y[FAC_PARA_N+2];
    G1 Z[FAC_PARA_N+2][FAC_PARA_N+2];

};

struct FAC_USER_SK
{
    Big usk;
};
struct FAC_USER_PK
{
    G2 upk1;
    G1 upk2;
};
struct USER_ATTR
{
    Big x[FAC_PARA_N+2];

};
struct FAC_USER_DISCLOSE_ATTR
{
    Big x[FAC_PARA_D];

};
struct FAC_USER_KEY
{
    FAC_USER_SK usk;
    FAC_USER_PK upk;
};
struct FAC_SPK1
{
    Big c,s;
    G2 gam1;
    G1 gam2;
};
struct FAC_USER_OWN
{
    FAC_USER_KEY user_key;
    USER_ATTR attr;
    Big uid;
    FAC_SPK1 spk1;
};
struct FAC_CRED_U
{
    G2 sigma1,sigma2;
};
struct FAC_SPK2
{
    Big c,sd,sk;
    GT gama;
};
struct FAC_TOK
{
    G1 T1,T2;
    G2 sigma1,sigma2;
    FAC_SPK2 spk2;
};
struct FAC_ST_UNIT
{
    Big uid;
    USER_ATTR attr;
    FAC_USER_PK upk;
    FAC_CRED_U cred_u;
};
typedef list <FAC_ST_UNIT> FAC_ST;
//typedef list <FAC_ST_UNIT*> FAC_ST;
struct FAC_CRED_KEY
{
    FAC_CRED_KEY_SK sk;
    FAC_CRED_KEY_PK pk;
    FAC_ST st;
};

class FAC
{
private:
    PFC *pfc;
#if 0
    G1 g;
    G2 h;
#endif


public:
    FAC(PFC *p);
    ~FAC();
//    int SetUp(FAC_PP &fac_pp);
    //key generate
    int CredKeyGen(FAC_CRED_KEY &cred_key);
    int UserKeyGen(FAC_USER_KEY &user_key);
    //issuecred_u
    int IssueUser_Send(FAC_USER_KEY &user_key,USER_ATTR &attr,Big &uid,FAC_SPK1 &spk1);
    int IssueIssuer(FAC_CRED_KEY &cred_key,USER_ATTR &attr,Big &uid,FAC_SPK1 &spk1,FAC_USER_PK &upk,FAC_CRED_U &cred_u);
    int IssueUser_Verify(FAC_CRED_KEY_PK &pk,FAC_CRED_U &cred_u,USER_ATTR &attr,Big &uid,FAC_USER_KEY &user_key);
    //Show
    int Show(FAC_CRED_KEY_PK &pk,FAC_CRED_U &cred_u,USER_ATTR &attr,FAC_USER_DISCLOSE_ATTR &disclose,Big &uid,FAC_USER_KEY &user_key,FAC_TOK &tok,Big &m);
    int Verify(FAC_CRED_KEY_PK &pk,FAC_TOK &tok,Big &m,FAC_USER_DISCLOSE_ATTR &disclose);
    //Trace
    int Trace(FAC_CRED_KEY &cred_key,FAC_TOK &tok,Big &uid);


};
#endif // FAC_H
