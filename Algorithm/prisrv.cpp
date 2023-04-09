#include "prisrv.h"
#include "bn_transfer.h"
#include "bn_struct.h"
PriSrv::PriSrv(PFC *p):fac(p),acme(p),mac_ddh(p)
{
    pfc=p;
}
PriSrv::~PriSrv()
{

}
int PriSrv::SetUp(ACME_MPK &mpk,ACME_MSK &msk)
{
#if 0
    streambuf* coutBuf = cout.rdbuf();
    ofstream of("setup_data.txt");
    streambuf* fileBuf = of.rdbuf();
    cout.rdbuf(fileBuf);
#endif
    BN_transfer BNT;
    G1_C gg;
    G1_C gg1;
    G2_C hh;
    GT_C gt;
#if 0
    BNT.Trf_G1_to_Char(*pfc->gg,gg);
    BNT.Trf_G1_to_Char(*pfc->gg1,gg1);
    BNT.Trf_G2_to_Char(*pfc->hh,hh);
    BNT.Trf_GT_to_Char(*pfc->gt,gt);
    BNT.bn_printfG1("gg",gg);
    BNT.bn_printfG1("gg1",gg1);
    BNT.bn_printfG2("hh",hh);
    BNT.bn_printfGT("gt",gt);
#endif

    gg.X.len=0x4;
    gg.X.w[0]=0xdc6033c18e7213b7;
    gg.X.w[1]=0x85afbc4b09ed5259;
    gg.X.w[2]=0x181abb4634eb43d6;
    gg.X.w[3]=0xe6c4f936e3e87d4;

    gg.Y.len=0x4;
    gg.Y.w[0]=0x20e7ab6d03023540;
    gg.Y.w[1]=0x50797bd1f9241b2e;
    gg.Y.w[2]=0xb352386928491f81;
    gg.Y.w[3]=0xf50c153e4ec3a2;

    gg.Z.len=0x1;
    gg.Z.w[0]=0x1;

    gg1.X.len=0x4;
    gg1.X.w[0]=0x140a33d7a07b0c08;
    gg1.X.w[1]=0x57bf40523f004c58;
    gg1.X.w[2]=0x804bbc211c85d9bc;
    gg1.X.w[3]=0x1b370c02969140f4;

    gg1.Y.len=0x4;
    gg1.Y.w[0]=0x434dc7ce94c1ca7a;
    gg1.Y.w[1]=0x4e4c891a60fb89f;
    gg1.Y.w[2]=0xeae3a400822b7052;
    gg1.Y.w[3]=0x1f6c6191736503bf;

    gg1.Z.len=0x1;
    gg1.Z.w[0]=0x1;


    hh.Xa.len=0x4;
    hh.Xa.w[0]=0xb33948cb312a3067;
    hh.Xa.w[1]=0xa9026898d23a3b10;
    hh.Xa.w[2]=0x9a927d03e54d8c49;
    hh.Xa.w[3]=0x1217487f6cdd75ac;

    hh.Xb.len=0x4;
    hh.Xb.w[0]=0xf82d5e69f934dc68;
    hh.Xb.w[1]=0x722924dba90272f7;
    hh.Xb.w[2]=0x708c4946395de1d8;
    hh.Xb.w[3]=0x187fbe43e5be26d0;

    hh.Ya.len=0x4;
    hh.Ya.w[0]=0x25a95c782cfe3fe9;
    hh.Ya.w[1]=0xe7bb6d65bab49b0d;
    hh.Ya.w[2]=0xd1200174bc67725a;
    hh.Ya.w[3]=0x1013e332300f04b1;

    hh.Yb.len=0x4;
    hh.Yb.w[0]=0xbf1e5328a776b41b;
    hh.Yb.w[1]=0xa34e670ba9f15406;
    hh.Yb.w[2]=0xe60a83c4400c4a71;
    hh.Yb.w[3]=0x2437c7fe36bfbc05;

    hh.Za.len=0x1;
    hh.Za.w[0]=0x1;

    hh.Zb.len=0x0;

    gt.Aaa.len=0x4;
    gt.Aaa.w[0]=0x4080f49963ffe737;
    gt.Aaa.w[1]=0xfb2b551513a5321e;
    gt.Aaa.w[2]=0x9a555ceaeb5eebfe;
    gt.Aaa.w[3]=0x65856e324b8d8c5;

    gt.Aab.len=0x4;
    gt.Aab.w[0]=0x8d6189a82ef388a3;
    gt.Aab.w[1]=0x395f68327392cee8;
    gt.Aab.w[2]=0xc0c65bedfd3a468f;
    gt.Aab.w[3]=0x129828fbff23208f;

    gt.Aba.len=0x4;
    gt.Aba.w[0]=0x106ae31f744f8a54;
    gt.Aba.w[1]=0x79647a9360b9796a;
    gt.Aba.w[2]=0xdea050b137774215;
    gt.Aba.w[3]=0x2063b6bc7324d714;

    gt.Abb.len=0x4;
    gt.Abb.w[0]=0xca0868b6d22b5127;
    gt.Abb.w[1]=0x3bd5be7c740d5274;
    gt.Abb.w[2]=0xbac7cb3f3d9a3d00;
    gt.Abb.w[3]=0x163e569f54bd577d;

    gt.Baa.len=0x4;
    gt.Baa.w[0]=0x522ac9f0e3081e59;
    gt.Baa.w[1]=0x7c54f3175952ef0a;
    gt.Baa.w[2]=0x6b585caf227d09fa;
    gt.Baa.w[3]=0x7f418a2cdbc5dfa;

    gt.Bab.len=0x4;
    gt.Bab.w[0]=0xffb415d8589f9ff4;
    gt.Bab.w[1]=0xb882460ee58eec50;
    gt.Bab.w[2]=0x46545b1227c4f053;
    gt.Bab.w[3]=0x14abc6a23a78cef2;

    gt.Bba.len=0x4;
    gt.Bba.w[0]=0x3e76c14959182142;
    gt.Bba.w[1]=0xc554fe31c4b04c56;
    gt.Bba.w[2]=0x2e5dddd596747346;
    gt.Bba.w[3]=0x23d44c5aa46cab1e;

    gt.Bbb.len=0x4;
    gt.Bbb.w[0]=0x7d6a194f70315e51;
    gt.Bbb.w[1]=0x162b8376c43412a1;
    gt.Bbb.w[2]=0xda1da268a0dc7a69;
    gt.Bbb.w[3]=0x1398797c8b2099aa;

    gt.Caa.len=0x4;
    gt.Caa.w[0]=0x1594b64dc6ca42ea;
    gt.Caa.w[1]=0x8ca1c8beceff1135;
    gt.Caa.w[2]=0xaa378cf584cb7bed;
    gt.Caa.w[3]=0x18c66ac5acd3f9b3;

    gt.Cab.len=0x4;
    gt.Cab.w[0]=0xb121fae9a6794b0f;
    gt.Cab.w[1]=0xfa502298c8e40f91;
    gt.Cab.w[2]=0xd547474d40031c53;
    gt.Cab.w[3]=0x16504b7092228f1e;

    gt.Cba.len=0x4;
    gt.Cba.w[0]=0xbcb267b39a586096;
    gt.Cba.w[1]=0xcbca3fd109fa8b59;
    gt.Cba.w[2]=0x2ded9c76514bb72c;
    gt.Cba.w[3]=0x1d60676b8ff317c;

    gt.Cbb.len=0x4;
    gt.Cbb.w[0]=0xb63738016c3b7ea7;
    gt.Cbb.w[1]=0x7e29b112bcac5a51;
    gt.Cbb.w[2]=0x37a340c5b4236377;
    gt.Cbb.w[3]=0x1da078a1a0e7c3a3;

    BNT.Trf_Char_to_G1(gg,*pfc->gg);
    BNT.Trf_Char_to_G1(gg1,*pfc->gg1);
    BNT.Trf_Char_to_G2(hh,*pfc->hh);
    BNT.Trf_Char_to_GT(gt,*pfc->gt);



 //   return 0;
   return acme.SetUp(msk,mpk);
}
int PriSrv::CredKeyGen(ACME_CRED_KEY &cred_key)
{
    return acme.CredKeyGen(cred_key);
}
int PriSrv::UserKeyGen(ACME_USER_KEY &user_key)
{
    return acme.UserKeyGen(user_key);
}
int PriSrv::Issue_Send(ACME_USER_KEY &user_key,USER_ATTR &attr,Big &uid,ACME_SPK1 &spk1)
{
    return acme.IssueUser_Send(user_key,attr,uid,spk1);
}
int PriSrv::Issue_Issuer(ACME_CRED_KEY &cred_key,USER_ATTR &attr,Big &uid,ACME_SPK1 &spk1,ACME_USER_PK &upk,ACME_CRED_U &cred_u)
{
    return acme.IssueIssuer(cred_key, attr, uid, spk1, upk, cred_u);
}
int PriSrv::Issue_Verify(ACME_CRED_KEY_PK &pk,ACME_CRED_U &cred_u,USER_ATTR &attr,Big &uid,ACME_USER_KEY &user_key)
{
    return acme.IssueUser_Verify(pk,cred_u,attr,uid,user_key);
}
int PriSrv::DKeyGen(ACME_MSK &msk, ACME_X &X_rcv, ACME_ABE_DK_X_REC &Dk_xrec)
{
    return acme.DKeyGen(msk,  X_rcv, Dk_xrec);
}
int PriSrv::PolGen(ACME_MSK &msk,ACME_ABE_DK_f_REC &DK_frec)
{
    return acme.PolGen(msk,DK_frec);
}
int PriSrv::Broadcast(ACME_MPK &mpk, ACME_CRED_KEY &cred_key_pk, ACME_CRED_U &cred_s, ACME_USER_KEY &service_key, USER_ATTR &service_attr,Big &bid, ACME_X &X_s, ACME_CIPHER &cipher, PriSrv_MSG_B &msg_b,Big &service_z)
{
    msg_b.bid=bid;
    pfc->random(msg_b.Service_par);
    pfc->random(msg_b.Service_type);

    pfc->random(service_z);
    msg_b.Z=pfc->mult(*pfc->hh,service_z);
    Big M;
    pfc->random(M);
    return acme.Enc(mpk, cred_key_pk, cred_s, service_key, service_attr, msg_b.bid, X_s, M, cipher);
}
int PriSrv::AMA_Cinit(ACME_MPK &mpk, ACME_CRED_KEY &cred_key_pk, ACME_CRED_U &cred_c, ACME_USER_KEY &client_key, ACME_ABE_DK_X_REC &Dk_C_xrec, ACME_ABE_DK_f_REC &DK_C_frec, ACME_X &X_s, ACME_X &X_c, USER_ATTR &client_attr, Big &uid,\
                      ACME_CIPHER &cipher, PriSrv_MSG_B &msg_b, Big &x, PriSrv_C1 &C1_msg)
{
    ACME_PLAIN plain;
//    int ret=0;
#if 1
    int ret = acme.Den(cred_key_pk, Dk_C_xrec, DK_C_frec, X_s, X_c, cipher, plain);
    if(ret != 0)
    {
        printf("acme.Den erro! ret=%d\n",ret);
        return -1;
    }
#endif
    C1_msg.msg_c.M_c.Z=msg_b.Z;
    pfc->random(C1_msg.x1);
    pfc->random(C1_msg.x2);
    C1_msg.msg_c.M_c.X1=pfc->mult(*pfc->gg,C1_msg.x1);
    C1_msg.msg_c.M_c.X2=pfc->mult(*pfc->hh,C1_msg.x2);
    MACddh_PK pk;
    mac_ddh.KeyGen(C1_msg.msg_c.K_c,pk);
    //MacDDH
    Big CS,X1,X2,Z;
    pfc->start_hash();
    pfc->add_to_hash(C1_msg.msg_c.M_c.X1);
    X1=pfc->finish_hash_to_group();
    pfc->start_hash();
    pfc->add_to_hash(C1_msg.msg_c.M_c.X2);
    X2=pfc->finish_hash_to_group();
    pfc->start_hash();
    pfc->add_to_hash(C1_msg.msg_c.M_c.Z);
    Z=pfc->finish_hash_to_group();
    char C_S[]="C to S";
    pfc->start_hash();
    pfc->add_to_hash(C_S);
    CS=pfc->finish_hash_to_group();
    MACddh_M M;
    M.N=6;
    M.m[0]=CS;
    M.m[1]=C1_msg.msg_c.M_c.bid=msg_b.bid;
    M.m[2]=C1_msg.msg_c.M_c.sid=uid;
    M.m[3]=X1;
    M.m[4]=X2;
    M.m[5]=Z;
    ret = mac_ddh.MAC(C1_msg.msg_c.K_c,M,C1_msg.sigma_c);
    if(ret != 0) return -2;
    Big m;
    pfc->random(m);
    ret = acme.Enc(mpk,  cred_key_pk, cred_c, client_key, client_attr, uid, X_c, m, C1_msg.CT);
    if(ret != 0) return -3;
    return 0;

}
int PriSrv::AMA_S(ACME_MPK &mpk, ACME_CRED_KEY &cred_key_pk, ACME_CRED_U &cred_s, ACME_USER_KEY &service_key, Big &service_z,USER_ATTR &service_attr, Big &sid, ACME_ABE_DK_X_REC &Dk_S_xrec, ACME_ABE_DK_f_REC &DK_S_frec, ACME_X &X_s, ACME_X &X_c, PriSrv_C1 &C1_msg, PriSrv_S &S_msg, PriSrv_SSK &ssk)
{
    ACME_PLAIN plain;
    //int ret =0;
#if 1
    int ret =acme.Den(cred_key_pk, Dk_S_xrec, DK_S_frec, X_c, X_s, C1_msg.CT, plain);
    if(ret !=0) return -1;
#endif
    //MacDDH
    MACddh_M Mc;
    Big CS,X1,X2,Z;
    pfc->start_hash();
    pfc->add_to_hash(C1_msg.msg_c.M_c.X1);
    X1=pfc->finish_hash_to_group();
    pfc->start_hash();
    pfc->add_to_hash(C1_msg.msg_c.M_c.X2);
    X2=pfc->finish_hash_to_group();
    pfc->start_hash();
    pfc->add_to_hash(C1_msg.msg_c.M_c.Z);
    Z=pfc->finish_hash_to_group();
    char C_S[]="C to S";
    pfc->start_hash();
    pfc->add_to_hash(C_S);
    CS=pfc->finish_hash_to_group();
    Mc.m[1]=C1_msg.msg_c.M_c.bid;
    Mc.m[2]=C1_msg.msg_c.M_c.sid;
    Mc.N=6;
    Mc.m[0]=CS;
    Mc.m[3]=X1;
    Mc.m[4]=X2;
    Mc.m[5]=Z;

    ret = mac_ddh.Verify(C1_msg.msg_c.K_c,Mc,C1_msg.sigma_c);
    if(ret !=0) return -2;
    Big y;
    pfc->random(y);
    S_msg.Y=pfc->mult(*pfc->gg,y);
    MACddh_PK pk;
    ret = mac_ddh.KeyGen(S_msg.msg_s.Ks,pk);
    if(ret !=0) return -3;
    char S_C[]="S to C";
    pfc->start_hash();
    pfc->add_to_hash(S_C);
    Big SC=pfc->finish_hash_to_group();
    pfc->start_hash();
    pfc->add_to_hash(S_msg.Y);
    Big Y=pfc->finish_hash_to_group();
    Mc.N=7;
    Mc.m[0]=SC;
    Mc.m[1]=C1_msg.msg_c.M_c.bid;
    Mc.m[2]=C1_msg.msg_c.M_c.sid;
    Mc.m[3]=X1;
    Mc.m[4]=X2;
    Mc.m[5]=Y;
    Mc.m[5]=Z;
    ret = mac_ddh.MAC(S_msg.msg_s.Ks,Mc,S_msg.sigma_s);
    if(ret != 0) return -2;

#if 0 //delete
    Big M;
    pfc->random(M);
    ret = acme.Enc(mpk,  cred_key_pk, cred_s, service_key, service_attr, sid, X_s, M, S_msg.CT);
    if(ret !=0) return -4;
#endif

    G1 X1y=pfc->mult(C1_msg.msg_c.M_c.X1,y);
    G2 X2z=pfc->mult(C1_msg.msg_c.M_c.X2,service_z);
    pfc->start_hash();
    pfc->add_to_hash(X1y);
    pfc->add_to_hash(X2z);
    pfc->add_to_hash(C1_msg.sigma_c.sig_w);
    pfc->add_to_hash(C1_msg.sigma_c.sig_x);
    pfc->add_to_hash(C1_msg.sigma_c.sig_y);
    pfc->add_to_hash(C1_msg.sigma_c.sig_z);
    pfc->add_to_hash(S_msg.sigma_s.sig_w);
    pfc->add_to_hash(S_msg.sigma_s.sig_x);
    pfc->add_to_hash(S_msg.sigma_s.sig_y);
    pfc->add_to_hash(S_msg.sigma_s.sig_z);
    ssk.ssk=pfc->finish_hash_to_group();
    return 0;
}
int PriSrv::AMA_Cverify(ACME_MPK &mpk, ACME_CRED_KEY &cred_key_pk, ACME_CRED_U &cred_c, ACME_USER_KEY &client_key, ACME_ABE_DK_X_REC &Dk_C_xrec, ACME_ABE_DK_f_REC &DK_C_frec,\
                        ACME_X &X_s, ACME_X &X_c, USER_ATTR &client_attr, Big &uid,Big &x, \
                        PriSrv_C1 &C1_msg, PriSrv_S &S_msg,PriSrv_SSK &ssk)
{
#if 0 //delete
    ACME_PLAIN plain;
    //int ret =0;

    int ret = acme.Den(cred_key_pk, Dk_C_xrec, DK_C_frec, X_s, X_c, S_msg.CT, plain);
    if(ret != 0) return -1;
#endif
    MACddh_M Mc;
    char S_C[]="S to C";
    Big X1,X2,Z;
    pfc->start_hash();
    pfc->add_to_hash(C1_msg.msg_c.M_c.X1);
    X1=pfc->finish_hash_to_group();
    pfc->start_hash();
    pfc->add_to_hash(C1_msg.msg_c.M_c.X2);
    X2=pfc->finish_hash_to_group();
    pfc->start_hash();
    pfc->add_to_hash(C1_msg.msg_c.M_c.Z);
    Z=pfc->finish_hash_to_group();
    pfc->start_hash();
    pfc->add_to_hash(S_C);
    Big SC=pfc->finish_hash_to_group();
    pfc->start_hash();
    pfc->add_to_hash(S_msg.Y);
    Big Y=pfc->finish_hash_to_group();
    Mc.N=7;
    Mc.m[0]=SC;
    Mc.m[1]=C1_msg.msg_c.M_c.bid;
    Mc.m[2]=C1_msg.msg_c.M_c.sid;
    Mc.m[3]=X1;
    Mc.m[4]=X2;
    Mc.m[5]=Y;
    Mc.m[5]=Z;
    int ret = mac_ddh.Verify(S_msg.msg_s.Ks,Mc,S_msg.sigma_s);
    if(ret !=0) return -2;
    G1 Yx1=pfc->mult(S_msg.Y,C1_msg.x1);
    G2 Zx2=pfc->mult(C1_msg.msg_c.M_c.Z,C1_msg.x2);
    pfc->start_hash();
    pfc->add_to_hash(Yx1);
    pfc->add_to_hash(Zx2);
    pfc->add_to_hash(C1_msg.sigma_c.sig_w);
    pfc->add_to_hash(C1_msg.sigma_c.sig_x);
    pfc->add_to_hash(C1_msg.sigma_c.sig_y);
    pfc->add_to_hash(C1_msg.sigma_c.sig_z);
    pfc->add_to_hash(S_msg.sigma_s.sig_w);
    pfc->add_to_hash(S_msg.sigma_s.sig_x);
    pfc->add_to_hash(S_msg.sigma_s.sig_y);
    pfc->add_to_hash(S_msg.sigma_s.sig_z);
    ssk.ssk=pfc->finish_hash_to_group();
    return 0;
}
int PriSrv::Trace(ACME_CRED_KEY &cred_key, ACME_TOK &tok, Big &uid)
{
    return acme.Trace(cred_key,tok,uid);
}
