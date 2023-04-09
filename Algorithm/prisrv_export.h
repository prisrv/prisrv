#ifndef PRISRV_EXPORT_H
#define PRISRV_EXPORT_H
#include"stdio.h"
#include"string.h"
#include"stdlib.h"
#include"bn_struct.h"

#ifdef __cplusplus
extern "C" {

//////////////////////////////////////////////////
/// \brief SetUp
/// \param output: mpk
/// \param output: msk
/// \return correct 0/ erro !0
int SetUp(ACME_MPK_C *mpk, ACME_MSK_C *msk);

///////////////////////////////////////////////////
/// \brief CredKeyGen
/// \param output: cred_key
/// \return correct 0/ erro !0
int CredKeyGen(ACME_CRED_KEY_C *cred_key);

//////////////////////////////////////////////////
/// \brief UserKeyGen
/// \param output: user_key
/// \return correct 0/ erro !0
int UserKeyGen(ACME_USER_KEY_C *user_key);

///////////////////////////////////////////////////////
/// \brief Issue_Send
/// \param input: user_key
/// \param output: attr
/// \param output: uid
/// \param output: spk1
/// \return correct 0/ erro !0
int Issue_Send(ACME_USER_KEY_C *user_key,USER_ATTR_C *attr,Big_C *uid,\
               ACME_SPK1_C *spk1);

///////////////////////////////////////////////////////
/// \brief Issue_Issuer
/// \param input: cred_key
/// \param input: attr
/// \param input: uid
/// \param input: spk1
/// \param input： upk
/// \param output: cred_u
/// \return correct 0/ erro !0
int Issue_Issuer(ACME_CRED_KEY_C *cred_key,USER_ATTR_C *attr,Big_C *uid,\
                 ACME_SPK1_C *spk1,ACME_USER_PK_C *upk,ACME_CRED_U_C *cred_u);

///////////////////////////////////////////////////////////
/// \brief Issue_Verify
/// \param input: pk
/// \param input: cred_u
/// \param input: attr
/// \param input: uid
/// \param input: user_key
/// \return correct 0/ erro !0
int Issue_Verify(ACME_CRED_KEY_PK_C *pk,ACME_CRED_U_C *cred_u,USER_ATTR_C *attr,\
                 Big_C *uid,ACME_USER_KEY_C *user_key);

/////////////////////////////////////////////////////////////
/// \brief DKeyGen
/// \param input: msk
/// \param output: X_rcv
/// \param output: Dk_xrec
/// \return correct 0/ erro !0
int DKeyGen(ACME_MSK_C *msk, ACME_X_C *X_rcv, ACME_ABE_DK_X_REC_C *Dk_xrec);

////////////////////////////////////////////////////////////
/// \brief PolGen
/// \param input: msk
/// \param output: DK_frec
/// \return correct 0/ erro !0
int PolGen(ACME_MSK_C *msk,ACME_ABE_DK_f_REC_C *DK_frec);
///////////////////////////////////////////////////////////
/// \brief Broadcast
/// \param input: mpk
/// \param input: cred_key_pk
/// \param input: cred_s
/// \param input: service_key
/// \param input: service_attr
/// \param input: bid
/// \param input: X_s
/// \param out: cipher
/// \param out: msg_b
/// \param out: service_z
/// \return correct 0/ erro !0
int Broadcast(ACME_MPK_C *mpk, ACME_CRED_KEY_C *cred_key_pk, ACME_CRED_U_C *cred_s,\
              ACME_USER_KEY_C *service_key, USER_ATTR_C *service_attr, Big_C *bid,\
              ACME_X_C *X_s, ACME_CIPHER_C *cipher, PriSrv_MSG_B_C *msg_b, \
              Big_C *service_z);

////////////////////////////////////////////////////////////
/// \brief AMA_Cinit
/// \param input: mpk
/// \param input: cred_key_pk
/// \param input: cred_c
/// \param input: client_key
/// \param input: Dk_C_xrec
/// \param input: DK_C_frec
/// \param input: X_s
/// \param input: X_c
/// \param input: client_attr
/// \param input: uid
/// \param input: cipher
/// \param input: msg_b
/// \param output: C1_msg
/// \return correct 0/ erro !0
int AMA_Cinit(ACME_MPK_C *mpk,ACME_CRED_KEY_C *cred_key_pk,ACME_CRED_U_C *cred_c,\
              ACME_USER_KEY_C *client_key,ACME_ABE_DK_X_REC_C *Dk_C_xrec,\
              ACME_ABE_DK_f_REC_C *DK_C_frec,ACME_X_C *X_s, ACME_X_C *X_c,\
              USER_ATTR_C *client_attr,Big_C *uid,ACME_CIPHER_C *cipher,\
              PriSrv_MSG_B_C *msg_b,PriSrv_C1_C *C1_msg);

///////////////////////////////////////////////////////
/// \brief AMA_S
/// \param input: mpk
/// \param input: cred_key_pk
/// \param input: cred_s
/// \param input: service_key
/// \param input: service_z
/// \param input: service_attr
/// \param input: sid
/// \param input: Dk_S_xrec
/// \param input: DK_S_frec
/// \param input: X_s
/// \param input: X_c
/// \param input: C1_msg
/// \param output: S_msg
/// \param output: ssk
/// \return correct 0/ erro !0
int AMA_S(ACME_MPK_C *mpk, ACME_CRED_KEY_C *cred_key_pk, ACME_CRED_U_C *cred_s,\
          ACME_USER_KEY_C *service_key, Big_C *service_z, USER_ATTR_C *service_attr, \
          Big_C *sid, ACME_ABE_DK_X_REC_C *Dk_S_xrec, ACME_ABE_DK_f_REC_C *DK_S_frec,\
          ACME_X_C *X_s, ACME_X_C *X_c, PriSrv_C1_C *C1_msg, PriSrv_S_C *S_msg,\
          PriSrv_SSK_C *ssk);

///////////////////////////////////////////////////////////
/// \brief AMA_Cverify
/// \param input: mpk
/// \param input: cred_key_pk
/// \param input: cred_c
/// \param input: client_key
/// \param input: Dk_C_xrec
/// \param input: DK_C_frec
/// \param input: X_s
/// \param input: X_c
/// \param input: client_attr
/// \param input: uid
/// \param input: C1_msg
/// \param input: S_msg
/// \param input: ssk
/// \return 0/ erro !0
int AMA_Cverify(ACME_MPK_C *mpk, ACME_CRED_KEY_C *cred_key_pk, ACME_CRED_U_C *cred_c,\
                ACME_USER_KEY_C *client_key, ACME_ABE_DK_X_REC_C *Dk_C_xrec, \
                ACME_ABE_DK_f_REC_C *DK_C_frec, ACME_X_C *X_s, ACME_X_C *X_c,\
                USER_ATTR_C *client_attr, Big_C *uid, PriSrv_C1_C *C1_msg,\
                PriSrv_S_C *S_msg, PriSrv_SSK_C *ssk);

}
#endif //__cplusplus
#endif // PRISRV_EXPORT_H
