#include"prisrv.h"

#define AES_SECURITY 128
int correct()
{
    PFC pfc(AES_SECURITY);
    streambuf* coutBuf = cout.rdbuf();
    ofstream of("test_data.txt");
    streambuf* fileBuf = of.rdbuf();
    cout.rdbuf(fileBuf);
    cout<<"\\********** 系统参数 pp***********\\"<<endl;
    cout<<"B:"<<endl;
    cout<<*(pfc.B)<<endl;
    cout<<"x:"<<endl;
    cout<<*(pfc.x)<<endl;
    cout<<"mod:"<<endl;
    cout<<*(pfc.mod)<<endl;
    cout<<"ord:"<<endl;
    cout<<*(pfc.ord)<<endl;
    cout<<"cof:"<<endl;
    cout<<*(pfc.cof)<<endl;
    cout<<"trace:"<<endl;
    cout<<*(pfc.trace)<<endl;

    cout<<"g:"<<endl;
    cout<<pfc.gg->g<<endl;
    cout<<"g':"<<endl;
    cout<<pfc.gg1->g<<endl;
    cout<<"h:"<<endl;
    cout<<pfc.hh->g<<endl;

    cout<<"CP_ABE parameter K:"<<endl;
    cout<<CP_ABE_PARA_K<<endl;

    cout<<"CP_ABE parameter  N:"<<endl;
    cout<<CP_ABE_PARA_N<<endl;

    cout<<"FAC parameter N:"<<endl;
    cout<<FAC_PARA_N<<endl;

    cout<<"FAC parameter D:"<<endl;
    cout<<FAC_PARA_D<<endl;


    PriSrv prisrv(&pfc);
    int ret=0;
    ACME_MPK mpk;
    ACME_MSK msk;
    ret =prisrv.SetUp(mpk,msk);
    if(ret != 0)
    {
        printf("prisrv.SetUp Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisrv.SetUp pass\n");
    cout<<"\\********** 加密主私钥 msk **********\\"<<endl;
    cout<<"A:"<<endl;
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        for(int j=0;j<2*CP_ABE_PARA_K;j++)
        {
            cout<<msk.msk.A[i][j]<<endl;
        }
    }
    cout<<"B:"<<endl;
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        for(int j=0;j<CP_ABE_PARA_K;j++)
        {
            cout<<msk.msk.B[i][j]<<endl;
        }
    }

    cout<<"U0:"<<endl;
    for(int i=0;i<2*CP_ABE_PARA_K;i++)
    {
        for(int j=0;j<CP_ABE_PARA_K;j++)
        {
            cout<<msk.msk.U0[i][j]<<endl;
        }
    }

    cout<<"W:"<<endl;
    for(int i=0;i<CP_ABE_PARA_N;i++)
    {
        for(int j=0;j<2*CP_ABE_PARA_K;j++)
        {
            for(int k=0;k<CP_ABE_PARA_K;k++)
            {
                cout<<msk.msk.W[i][j][k]<<endl;
            }
        }
    }
    cout<<"V:"<<endl;
    for(int i=0;i<2*CP_ABE_PARA_K;i++)
    {
        cout<<msk.msk.V[i]<<endl;
    }




    cout<<"\\********** 加密主公钥 mpk ***********\\"<<endl;

    cout<<"[A]1:"<<endl;
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        for(int j=0;j<2*CP_ABE_PARA_K;j++)
        {
            cout<<mpk.mpk.A1[i][j].g<<endl;
        }
    }

    cout<<"[A]_1:"<<endl;
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        for(int j=0;j<2*CP_ABE_PARA_K;j++)
        {
            cout<<mpk.mpk.A1[i][j].g<<endl;
        }
    }
    cout<<"[AU0]_1:"<<endl;
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        for(int j=0;j<CP_ABE_PARA_K;j++)
        {
            cout<<mpk.mpk.AU01[i][j].g<<endl;
        }
    }

    cout<<"[AW]_1:"<<endl;
    for(int i=0;i<CP_ABE_PARA_N;i++)
    {
        for(int j=0;j<CP_ABE_PARA_K;j++)
        {
            for(int k=0;k<CP_ABE_PARA_K;k++)
            {
                cout<<mpk.mpk.AW1[i][j][k].g<<endl;
            }
        }
    }

    cout<<"[e(A,V)]_T:"<<endl;
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        cout<<mpk.mpk.eAV[i].g<<endl;
    }


    ACME_CRED_KEY cred_key;
    ret =prisrv.CredKeyGen(cred_key);
    if(ret != 0)
    {
        printf("prisrv.CredKeyGen Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisrv.CredKeyGen pass\n");
    cout<<"\\********** 签发证书密钥 cred_key ***********\\"<<endl;
    cout<<"\\--------- 签证私钥 cred_key.sk -----------\\"<<endl;
    cout<<"x:"<<endl;
    cout<<cred_key.cred_key.sk.x<<endl;
    cout<<"y:"<<endl;
    for(int i=0;i<FAC_PARA_N+2;i++)
    {
        cout<<cred_key.cred_key.sk.y[i]<<endl;
    }

    cout<<"\\--------- 签证公钥 cred_key.pk ------------\\"<<endl;
    cout<<"W:"<<endl;
    cout<<cred_key.cred_key.pk.W.g<<endl;
    cout<<"X:"<<endl;
    for(int i=0;i<FAC_PARA_N+2;i++)
    {
        cout<<cred_key.cred_key.pk.X[i].g<<endl;
    }
    cout<<"Y:"<<endl;
    for(int i=0;i<FAC_PARA_N+2;i++)
    {
        cout<<cred_key.cred_key.pk.Y[i].g<<endl;
    }
    cout<<"Z:"<<endl;
    for(int i=0;i<FAC_PARA_N+2;i++)
    {
        for(int j=0;j<FAC_PARA_N+2;j++)
        {
            cout<<cred_key.cred_key.pk.Z[i][j].g<<endl;
        }
    }

    ACME_CRED_KEY_PK cred_key_pk;
    cred_key_pk.pk=cred_key.cred_key.pk;
    //////////////////////////////////////service
    ACME_USER_KEY service_key;
    ret =prisrv.UserKeyGen(service_key);
    if(ret != 0)
    {
        printf("prisrv.service_key KeyGen Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisrv.service_key KeyGen pass\n");
    cout<<"\\********** 服务端信息  **********\\"<<endl;
    cout<<"\\--------- 服务端私钥 service_key.usk ------------\\"<<endl;
    cout<<service_key.user_key.usk.usk<<endl;
    cout<<"\\--------- 服务端公钥 service_key.upk ------------\\"<<endl;
    cout<<"upk1:"<<endl;
    cout<<service_key.user_key.upk.upk1.g<<endl;
    cout<<"upk2:"<<endl;
    cout<<service_key.user_key.upk.upk2.g<<endl;

    USER_ATTR service_attr;
    Big bid;
    ACME_SPK1 spk1;
    ret =prisrv.Issue_Send(service_key,service_attr,bid,spk1);
    if(ret != 0)
    {
        printf("prisrv.Issue_Send service Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisrv.Issue_Send service pass\n");
    cout<<"\\--------- 服务端属性 service_attr ------------\\"<<endl;
    for(int i=1;i<FAC_PARA_N+1;i++)
    {
        cout<<service_attr.x[i]<<endl;
    }
    cout<<"\\--------- 服务端身份 bid ------------\\"<<endl;
    cout<<bid<<endl;
    cout<<"\\--------- 服务端知识证明 spk1 ------------\\"<<endl;
    cout<<"c:"<<endl;
    cout<<spk1.spk1.c<<endl;
    cout<<"s:"<<endl;
    cout<<spk1.spk1.s<<endl;
    cout<<"gama_1:"<<endl;
    cout<<spk1.spk1.gam1.g<<endl;
    cout<<"gama_2:"<<endl;
    cout<<spk1.spk1.gam2.g<<endl;


    ACME_CRED_U cred_s;
    ACME_USER_PK service_upk;
    service_upk.upk=service_key.user_key.upk;
    ret =prisrv.Issue_Issuer(cred_key,service_attr,bid,spk1,service_upk,cred_s);
    if(ret != 0)
    {
        printf("prisrv.Issue_Issuer service Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisrv.Issue_Issuer service pass\n");
    cout<<"\\--------- 服务端证书 cred_s ------------\\"<<endl;
    cout<<"sigma_1:"<<endl;
    cout<<cred_s.cred_u.sigma1.g<<endl;
    cout<<"sigma_2:"<<endl;
    cout<<cred_s.cred_u.sigma2.g<<endl;

    ret =prisrv.Issue_Verify(cred_key_pk,cred_s,service_attr,bid,service_key);
    if(ret != 0)
    {
        printf("prisrv.Issue_Verify service Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisrv.Issue_Verify service pass\n");
    ACME_X X_s;
    for(int i=0;i<CP_ABE_PARA_N;i++)
    {
        X_s.X.x[i]=0;
    }
    X_s.X.x[0]=X_s.X.x[2]=1;
    ACME_ABE_DK_X_REC Dk_S_xrec;
    cout<<"\\--------- 服务端加密属性 X_s ------------\\"<<endl;
    for(int i=0;i<CP_ABE_PARA_N;i++)
    {
        cout<<X_s.X.x[i]<<endl;
    }
    ret =prisrv.DKeyGen(msk, X_s, Dk_S_xrec);
    if(ret != 0)
    {
        printf("prisrv.DKeyGen service Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisrv.DKeyGen service pass\n");
    cout<<"\\--------- 服务端属性密钥 Dk_S_xrec ------------\\"<<endl;
    cout<<"dk1:"<<endl;
    for(int i=0;i<2*CP_ABE_PARA_K;i++)
        cout<<Dk_S_xrec.sk.sk1[i].g<<endl;
    cout<<"dk2:"<<endl;
    for(int i=0;i<CP_ABE_PARA_K;i++)
        cout<<Dk_S_xrec.sk.sk2[i].g<<endl;
    cout<<"dk3:"<<endl;
    for(int i=0;i<2*CP_ABE_PARA_K;i++)
        cout<<Dk_S_xrec.sk.sk3[i].g<<endl;

    ACME_ABE_DK_f_REC DK_S_frec;
    ret =prisrv.PolGen(msk,DK_S_frec);
    if(ret != 0)
    {
        printf("prisrv.PolGen service Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisrv.PolGen service pass\n");
    cout<<"\\--------- 服务端策略密钥 DK_S_frec ------------\\"<<endl;
    cout<<"dk:"<<endl;
    for(int i=0;i<LSS_NC_SHARE_NUM;i++)
    {
        for(int j=0;j<CP_ABE_PARA_K;j++)
        {
            cout<<DK_S_frec.dk[i][j].g<<endl;
        }
    }
    cout<<"dk_[i,j]:"<<endl;
    for(int i=0;i<CP_ABE_PARA_N+1;i++)
    {
        for(int j=0;j<LSS_NC_SHARE_NUM;j++)
        {
            for(int k=0;k<2*CP_ABE_PARA_K;k++)
            {
                cout<<DK_S_frec.dk_rou[i][j][k].g<<endl;
            }
        }
    }
    //////////////////////////////////////////client
    ACME_USER_KEY client_key;
    ret =prisrv.UserKeyGen(client_key);
    if(ret != 0)
    {
        printf("prisrv.client_key KeyGen Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisrv.client_key KeyGen pass\n");
    cout<<"\\********** 客户端信息  **********\\"<<endl;
    cout<<"\\--------- 客户端私钥 client_key.usk ------------\\"<<endl;
    cout<<client_key.user_key.usk.usk<<endl;
    cout<<"\\--------- 客户端公钥 client_key.upk ------------\\"<<endl;
    cout<<"upk1:"<<endl;
    cout<<client_key.user_key.upk.upk1.g<<endl;
    cout<<"upk2:"<<endl;
    cout<<client_key.user_key.upk.upk2.g<<endl;

    USER_ATTR client_attr;
    Big sid;
    //ACME_SPK1 spk1;
    ret =prisrv.Issue_Send(client_key,client_attr,sid,spk1);
    if(ret != 0)
    {
        printf("prisrv.Issue_Send client Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisrv.Issue_Send client pass\n");
    cout<<"\\--------- 客户端属性 client_attr ------------\\"<<endl;
    for(int i=1;i<FAC_PARA_N+1;i++)
    {
        cout<<client_attr.x[i]<<endl;
    }
    cout<<"\\--------- 客户端身份 sid ------------\\"<<endl;
    cout<<sid<<endl;
    cout<<"\\--------- 客户端知识证明 spk1 ------------\\"<<endl;
    cout<<"c:"<<endl;
    cout<<spk1.spk1.c<<endl;
    cout<<"s:"<<endl;
    cout<<spk1.spk1.s<<endl;
    cout<<"gama_1:"<<endl;
    cout<<spk1.spk1.gam1.g<<endl;
    cout<<"gama_2:"<<endl;
    cout<<spk1.spk1.gam2.g<<endl;
    ACME_CRED_U cred_c;
    ACME_USER_PK client_upk;
    client_upk.upk=client_key.user_key.upk;
    ret =prisrv.Issue_Issuer(cred_key,client_attr,sid,spk1,client_upk,cred_c);
    if(ret != 0)
    {
        printf("prisrv.Issue_Issuer client Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisrv.Issue_Issuer client pass\n");
    //ACME_CRED_KEY_PK cred_key_pk;
    //cred_key_pk.pk=cred_key.cred_key.pk;


    cout<<"\\--------- 客户端证书 cred_c ------------\\"<<endl;
    cout<<"sigma_1:"<<endl;
    cout<<cred_c.cred_u.sigma1.g<<endl;
    cout<<"sigma_2:"<<endl;
    cout<<cred_c.cred_u.sigma2.g<<endl;

    ret =prisrv.Issue_Verify(cred_key_pk,cred_c,client_attr,sid,client_key);
    if(ret != 0)
    {
        printf("prisrv.Issue_Verify client Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisrv.Issue_Verify client pass\n");
    ACME_X X_c;
    ACME_ABE_DK_X_REC Dk_C_xrec;
    for(int i=0;i<CP_ABE_PARA_N;i++)
    {
        X_c.X.x[i]=0;
    }
    X_c.X.x[0]=X_c.X.x[2]=1;
    cout<<"\\--------- 客户端加密属性 X_c ------------\\"<<endl;
    for(int i=0;i<CP_ABE_PARA_N;i++)
    {
        cout<<X_c.X.x[i]<<endl;
    }
    ret =prisrv.DKeyGen(msk, X_c, Dk_C_xrec);
    if(ret != 0)
    {
        printf("prisrv.DKeyGen client Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisrv.DKeyGen client pass\n");
    cout<<"\\--------- 客户端属性密钥 Dk_C_xrec ------------\\"<<endl;
    cout<<"dk1:"<<endl;
    for(int i=0;i<2*CP_ABE_PARA_K;i++)
        cout<<Dk_C_xrec.sk.sk1[i].g<<endl;
    cout<<"dk2:"<<endl;
    for(int i=0;i<CP_ABE_PARA_K;i++)
        cout<<Dk_C_xrec.sk.sk2[i].g<<endl;
    cout<<"dk3:"<<endl;
    for(int i=0;i<2*CP_ABE_PARA_K;i++)
        cout<<Dk_C_xrec.sk.sk3[i].g<<endl;

    ACME_ABE_DK_f_REC DK_C_frec;
    ret =prisrv.PolGen(msk,DK_C_frec);
    if(ret != 0)
    {
        printf("prisrv.PolGen client Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisrv.PolGen client pass\n");
    cout<<"\\--------- 客户端策略密钥 DK_C_frec ------------\\"<<endl;
    cout<<"dk:"<<endl;
    for(int i=0;i<LSS_NC_SHARE_NUM;i++)
    {
        for(int j=0;j<CP_ABE_PARA_K;j++)
        {
            cout<<DK_C_frec.dk[i][j].g<<endl;
        }
    }
    cout<<"dk_[i,j]:"<<endl;
    for(int i=0;i<CP_ABE_PARA_N+1;i++)
    {
        for(int j=0;j<LSS_NC_SHARE_NUM;j++)
        {
            for(int k=0;k<2*CP_ABE_PARA_K;k++)
            {
                cout<<DK_C_frec.dk_rou[i][j][k].g<<endl;
            }
        }
    }
    //////////////////////////broadcast
    ACME_CIPHER cipher;
    PriSrv_MSG_B msg_b;
    Big z;
    ret =prisrv.Broadcast(mpk, cred_key, cred_s, service_key, service_attr,bid, X_s, cipher, msg_b,z);
    if(ret != 0)
    {
        printf("prisrv.Broadcast  Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisrv.Broadcast  pass\n");
    cout<<"\\*********** 服务端广播信息 ***********\\"<<endl;
    #if 0
    cout<<"\\---------服务端令牌信息 token ------------\\"<<endl;
    cout<<"T1"<<endl;
    cout<<cipher.cipher_tok.T1.g<<endl;
    cout<<"T2"<<endl;
    cout<<cipher.cipher_tok.T2.g<<endl;
    cout<<"sigma1"<<endl;
    cout<<cipher.cipher_tok.sigma1.g<<endl;
    cout<<"sigma2"<<endl;
    cout<<cipher.cipher_tok.sigma2.g<<endl;
    cout<<"服务端知识签名 spk2"<<endl;

    cout<<"c"<<endl;
    cout<<cipher.cipher_tok.spk2.c<<endl;
    cout<<"usk'"<<endl;
    cout<<cipher.cipher_tok.spk2.sk<<endl;
    cout<<"uid'"<<endl;
    cout<<cipher.cipher_tok.spk2.sd<<endl;
    cout<<"Gama'"<<endl;
    cout<<cipher.cipher_tok.spk2.gama.g<<endl;
#endif

    cout<<"\\--------- CT ------------\\"<<endl;
    cout<<"ct0"<<endl;
    cout<<cipher.ct0.g<<endl;
    cout<<"ct1_"<<endl;
    for(int i=0;i<2*CP_ABE_PARA_K;i++)
    {
        cout<<cipher.ct1_[i].g<<endl;
    }

    cout<<"ct2_"<<endl;
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        cout<<cipher.ct2_[i].g<<endl;
    }

    cout<<"ct1"<<endl;

    for(int i=0;i<2*CP_ABE_PARA_K;i++)
    {
        cout<<cipher.ct1[i].g<<endl;
    }

    cout<<"ct2"<<endl;
    for(int i=0;i<LSS_NC_SHARE_NUM;i++)
    {
        for(int j=0;j<2*CP_ABE_PARA_K;j++)
            cout<<cipher.ct2[i][j].g<<endl;
    }

    cout<<"ct_[i,j]"<<endl;

    for(int i=0;i<CP_ABE_PARA_N+1;i++)
    {
        for(int j=0;j<LSS_NC_SHARE_NUM;j++)
            for(int k=0;k<CP_ABE_PARA_K;k++)
                cout<<cipher.ct_rou[i][j][k].g<<endl;
    }
#if 0
    cout<<"\\--------- M ---------\\"<<endl;
    cout<<cipher.cipher_M<<endl;
#endif
    cout<<"\\--------- disclose attributes ---------\\"<<endl;
    for(int i=0;i<FAC_PARA_D;i++)
    {
        cout<<cipher.disclose.x[i]<<endl;
    }

    cout<<"\\--------- msg_b ---------\\"<<endl;
    cout<<"bid"<<endl;
    cout<<msg_b.bid<<endl;
    cout<<"Service_type"<<endl;
    cout<<msg_b.Service_type<<endl;
    cout<<"Service_par"<<endl;
    cout<<msg_b.Service_par<<endl;
    cout<<"Z"<<endl;
    cout<<msg_b.Z.g<<endl;
    cout<<"\\--------- z ---------\\"<<endl;
    cout<<z<<endl;

    ////////////////////////////Clint init
    Big x;
    PriSrv_C1 C1_msg;
    ret =prisrv.AMA_Cinit(mpk, cred_key, cred_c, client_key, Dk_C_xrec, DK_C_frec, X_s, X_c, client_attr, sid, cipher, msg_b, x, C1_msg);
    if(ret != 0)
    {
        printf("prisrv.AMA_Cinit  Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisrv.AMA_Cinit  pass\n");

    cout<<"\\*********** 客户端获取广播信息并发起请求 ***********\\"<<endl;
    cout<<"x1"<<endl;
    cout<<C1_msg.x1<<endl;

    cout<<"x2"<<endl;
    cout<<C1_msg.x2<<endl;

    cout<<"\\---------- sigma_c -------------\\"<<endl;
    cout<<"sigma_w"<<endl;
    cout<<C1_msg.sigma_c.sig_w.g<<endl;
    cout<<"sigma_x"<<endl;
    cout<<C1_msg.sigma_c.sig_x.g<<endl;
    cout<<"sigma_y"<<endl;
    cout<<C1_msg.sigma_c.sig_y.g<<endl;
    cout<<"sigma_z"<<endl;
    cout<<C1_msg.sigma_c.sig_z.g<<endl;

    cout<<"\\---------- Kc -------------\\"<<endl;
    cout<<"x:"<<endl;
    for(int i=0;i<MACddh_PARA_N+1;i++)
    {
        cout<<C1_msg.msg_c.K_c.x[i]<<endl;

    }
    cout<<"y:"<<endl;
    for(int i=0;i<MACddh_PARA_N+1;i++)
    {
        cout<<C1_msg.msg_c.K_c.y[i]<<endl;

    }
    cout<<"z:"<<endl;
    cout<<C1_msg.msg_c.K_c.z<<endl;
#if 0
    cout<<"\\---------- tok_c -------------\\"<<endl;
    cout<<"T1"<<endl;
    cout<<C1_msg.CT.cipher_tok.T1.g<<endl;
    cout<<"T2"<<endl;
    cout<<C1_msg.CT.cipher_tok.T2.g<<endl;
    cout<<"sigma1"<<endl;
    cout<<C1_msg.CT.cipher_tok.sigma1.g<<endl;
    cout<<"sigma2"<<endl;
    cout<<C1_msg.CT.cipher_tok.sigma2.g<<endl;
#endif
    cout<<"\\---------- M_c -------------\\"<<endl;
    cout<<"bid"<<endl;
    cout<<C1_msg.msg_c.M_c.bid<<endl;
    cout<<"sid"<<endl;
    cout<<C1_msg.msg_c.M_c.sid<<endl;
    cout<<"X1"<<endl;
    cout<<C1_msg.msg_c.M_c.X1.g<<endl;
    cout<<"X2"<<endl;
    cout<<C1_msg.msg_c.M_c.X2.g<<endl;
    cout<<"Z"<<endl;
    cout<<C1_msg.msg_c.M_c.Z.g<<endl;

    cout<<"\\--------- disclose attributes ---------\\"<<endl;
    for(int i=0;i<FAC_PARA_D;i++)
    {
        cout<<C1_msg.CT.disclose.x[i]<<endl;
    }
    cout<<"\\--------- CT ------------\\"<<endl;
    cout<<"ct0"<<endl;
    cout<<C1_msg.CT.ct0.g<<endl;
    cout<<"ct1_"<<endl;
    for(int i=0;i<2*CP_ABE_PARA_K;i++)
    {
        cout<<C1_msg.CT.ct1_[i].g<<endl;
    }

    cout<<"ct2_"<<endl;
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        cout<<C1_msg.CT.ct2_[i].g<<endl;
    }

    cout<<"ct1"<<endl;

    for(int i=0;i<2*CP_ABE_PARA_K;i++)
    {
        cout<<C1_msg.CT.ct1[i].g<<endl;
    }

    cout<<"ct2"<<endl;
    for(int i=0;i<LSS_NC_SHARE_NUM;i++)
    {
        for(int j=0;j<2*CP_ABE_PARA_K;j++)
            cout<<C1_msg.CT.ct2[i][j].g<<endl;
    }

    cout<<"ct_[i,j]"<<endl;

    for(int i=0;i<CP_ABE_PARA_N+1;i++)
    {
        for(int j=0;j<LSS_NC_SHARE_NUM;j++)
            for(int k=0;k<CP_ABE_PARA_K;k++)
                cout<<C1_msg.CT.ct_rou[i][j][k].g<<endl;
    }

    //////////////////////Service
    PriSrv_S S_msg;
    PriSrv_SSK ssk_s;
    ret =prisrv.AMA_S(mpk, cred_key, cred_s, service_key,z, service_attr, bid, Dk_S_xrec, DK_S_frec, X_s, X_c, C1_msg, S_msg, ssk_s);
    if(ret != 0)
    {
        printf("prisrv.AMA_S  Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisrv.AMA_S  pass\n");
    return 0;
    cout<<"\\*********** 服务端验证请求并响应 ***********\\"<<endl;
    cout<<"Y"<<endl;
    cout<<S_msg.Y.g<<endl;
    cout<<"\\---------- sigma_s -------------\\"<<endl;
    cout<<"sigma_w"<<endl;
    cout<<S_msg.sigma_s.sig_w.g<<endl;
    cout<<"sigma_x"<<endl;
    cout<<S_msg.sigma_s.sig_x.g<<endl;
    cout<<"sigma_y"<<endl;
    cout<<S_msg.sigma_s.sig_y.g<<endl;
    cout<<"sigma_z"<<endl;
    cout<<S_msg.sigma_s.sig_z.g<<endl;

    cout<<"\\---------- Ks -------------\\"<<endl;
    cout<<"x:"<<endl;
    for(int i=0;i<MACddh_PARA_N+1;i++)
    {
        cout<<S_msg.msg_s.Ks.x[i]<<endl;

    }
    cout<<"y:"<<endl;
    for(int i=0;i<MACddh_PARA_N+1;i++)
    {
        cout<<S_msg.msg_s.Ks.y[i]<<endl;

    }
    cout<<"z:"<<endl;
    cout<<S_msg.msg_s.Ks.z<<endl;
#if 0
    cout<<"\\---------- tok_s -------------\\"<<endl;
    cout<<"T1"<<endl;
    cout<<S_msg.CT.cipher_tok.T1.g<<endl;
    cout<<"T2"<<endl;
    cout<<S_msg.CT.cipher_tok.T2.g<<endl;
    cout<<"sigma1"<<endl;
    cout<<S_msg.CT.cipher_tok.sigma1.g<<endl;
    cout<<"sigma2"<<endl;
    cout<<S_msg.CT.cipher_tok.sigma2.g<<endl;
#endif

    cout<<"\\--------- disclose attributes ---------\\"<<endl;
    for(int i=0;i<FAC_PARA_D;i++)
    {
        cout<<S_msg.CT.disclose.x[i]<<endl;
    }
    cout<<"\\--------- CT ------------\\"<<endl;
    cout<<"ct0"<<endl;
    cout<<S_msg.CT.ct0.g<<endl;
    cout<<"ct1_"<<endl;
    for(int i=0;i<2*CP_ABE_PARA_K;i++)
    {
        cout<<S_msg.CT.ct1_[i].g<<endl;
    }

    cout<<"ct2_"<<endl;
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        cout<<S_msg.CT.ct2_[i].g<<endl;
    }

    cout<<"ct1"<<endl;

    for(int i=0;i<2*CP_ABE_PARA_K;i++)
    {
        cout<<S_msg.CT.ct1[i].g<<endl;
    }

    cout<<"ct2"<<endl;
    for(int i=0;i<LSS_NC_SHARE_NUM;i++)
    {
        for(int j=0;j<2*CP_ABE_PARA_K;j++)
            cout<<S_msg.CT.ct2[i][j].g<<endl;
    }

    cout<<"ct_[i,j]"<<endl;

    for(int i=0;i<CP_ABE_PARA_N+1;i++)
    {
        for(int j=0;j<LSS_NC_SHARE_NUM;j++)
            for(int k=0;k<CP_ABE_PARA_K;k++)
                cout<<S_msg.CT.ct_rou[i][j][k].g<<endl;
    }
    cout<<"ssk_s"<<endl;
    cout<<ssk_s.ssk<<endl;


    ///////////////////client rcv
    PriSrv_SSK ssk_c;
    ret =prisrv.AMA_Cverify(mpk, cred_key, cred_c, client_key, Dk_C_xrec, DK_C_frec, X_s, X_c, client_attr, sid,x, C1_msg, S_msg,ssk_c);
    if(ret != 0)
    {
        printf("prisrv.AMA_Cverify  Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisrv.AMA_Cverify  pass\n");
    cout<<"\\*********** 客户端验证响应并获得协商密钥 ***********\\"<<endl;
    cout<<"ssk_c"<<endl;
    cout<<ssk_c.ssk<<endl;
    if(ssk_c.ssk!=ssk_s.ssk)
    {
        printf("prisrv.AMA_C key  Erro ret =%d\n",ret);
        return 1;
    }
    /////////////////////trace
#if 0
    Big bid_1,sid_1;
    ret =prisrv.Trace(cred_key, C1_msg.CT.cipher_tok, bid);

    ret =prisrv.Trace(cred_key, C1_msg.CT.cipher_tok, bid);
#endif

    of.flush();
    of.close();
    return 0;
}
#include <ctime>
#include <time.h>
#define TEST_TIME 1
int speed()
{
    int i;
    clock_t start,finish;
    double sum;
    printf("#################test PriSrv speed start#######################\n");
    printf("The para of FAC `n` is %d \n",FAC_PARA_N);
    printf("The para of FAC  'd' is %d \n",FAC_PARA_D);
    printf("The para of ACME `n` is %d \n",CP_ABE_PARA_N);
    printf("The para of ACME `k` is %d \n",CP_ABE_PARA_K);
    printf("The para of LSS `n` is %d \n",LSS_NC_PARA_N);
    printf("The para of LSS `m` is %d \n",LSS_NC_SHARE_NUM);
    printf("The para of macddh `n` is %d \n",MACddh_PARA_N);


    PFC pfc(AES_SECURITY);
    PriSrv prisrv(&pfc);
    int ret=0;
    ACME_MPK mpk;
    ACME_MSK msk;
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
        ret =prisrv.SetUp(mpk,msk);
        if(ret != 0)
        {
            printf("prisrv.SetUp Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("prisrv.SetUp ret : %d time =%f sec\n",ret,sum);

    ACME_CRED_KEY cred_key;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret =prisrv.CredKeyGen(cred_key);
        if(ret != 0)
        {
            printf("prisrv.CredKeyGen Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("prisrv.CredKeyGen ret : %d time =%f sec\n",ret,sum);
    ACME_CRED_KEY_PK cred_key_pk;
    cred_key_pk.pk=cred_key.cred_key.pk;
    //////////////////////////////////////service
    ACME_USER_KEY service_key;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret =prisrv.UserKeyGen(service_key);
        if(ret != 0)
        {
            printf("prisrv.service_key KeyGen Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("prisrv.service_key KeyGen ret : %d time =%f sec\n",ret,sum);

    USER_ATTR service_attr;
    Big bid;
    ACME_SPK1 spk1;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret =prisrv.Issue_Send(service_key,service_attr,bid,spk1);
        if(ret != 0)
        {
            printf("prisrv.Issue_Send service Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("prisrv.Issue_Send service ret : %d time =%f sec\n",ret,sum);
    ACME_CRED_U cred_s;
    ACME_USER_PK service_upk;
    service_upk.upk=service_key.user_key.upk;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret =prisrv.Issue_Issuer(cred_key,service_attr,bid,spk1,service_upk,cred_s);
        if(ret != 0)
        {
            printf("prisrv.Issue_Issuer service Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("prisrv.Issue_Issuer service ret : %d time =%f sec\n",ret,sum);
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret =prisrv.Issue_Verify(cred_key_pk,cred_s,service_attr,bid,service_key);
        if(ret != 0)
        {
            printf("prisrv.Issue_Verify service Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("prisrv.Issue_Verify service ret : %d time =%f sec\n",ret,sum);
    ACME_X X_s;
    for(int i=0;i<CP_ABE_PARA_N;i++)
    {
        X_s.X.x[i]=0;
    }
    X_s.X.x[0]=X_s.X.x[2]=1;
    ACME_ABE_DK_X_REC Dk_S_xrec;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret =prisrv.DKeyGen(msk, X_s, Dk_S_xrec);
        if(ret != 0)
        {
            printf("prisrv.DKeyGen service Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("prisrv.DKeyGen service ret : %d time =%f sec\n",ret,sum);
    ACME_ABE_DK_f_REC DK_S_frec;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret =prisrv.PolGen(msk,DK_S_frec);
        if(ret != 0)
        {
            printf("prisrv.PolGen service Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("prisrv.PolGen service ret : %d time =%f sec\n",ret,sum);

    //////////////////////////////////////////client
    ACME_USER_KEY client_key;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret =prisrv.UserKeyGen(client_key);
        if(ret != 0)
        {
            printf("prisrv.client_key KeyGen Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("prisrv.client_key KeyGen ret : %d time =%f sec\n",ret,sum);
    USER_ATTR client_attr;
    Big sid;
    //ACME_SPK1 spk1;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret =prisrv.Issue_Send(client_key,client_attr,sid,spk1);
        if(ret != 0)
        {
            printf("prisrv.Issue_Send client Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("prisrv.Issue_Send client ret : %d time =%f sec\n",ret,sum);
    ACME_CRED_U cred_c;
    ACME_USER_PK client_upk;
    client_upk.upk=client_key.user_key.upk;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret =prisrv.Issue_Issuer(cred_key,client_attr,sid,spk1,client_upk,cred_c);
        if(ret != 0)
        {
            printf("prisrv.Issue_Issuer client Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("prisrv.Issue_Issuer client ret : %d time =%f sec\n",ret,sum);
    //ACME_CRED_KEY_PK cred_key_pk;
    //cred_key_pk.pk=cred_key.cred_key.pk;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret =prisrv.Issue_Verify(cred_key_pk,cred_c,client_attr,sid,client_key);
        if(ret != 0)
        {
            printf("prisrv.Issue_Verify client Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("prisrv.Issue_Verify client ret : %d time =%f sec\n",ret,sum);
    ACME_X X_c;
    ACME_ABE_DK_X_REC Dk_C_xrec;
    for(int i=0;i<CP_ABE_PARA_N;i++)
    {
        X_c.X.x[i]=0;
    }
    X_c.X.x[0]=X_c.X.x[2]=1;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret =prisrv.DKeyGen(msk, X_c, Dk_C_xrec);
        if(ret != 0)
        {
            printf("prisrv.DKeyGen client Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("prisrv.DKeyGen client ret : %d time =%f sec\n",ret,sum);
    ACME_ABE_DK_f_REC DK_C_frec;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret =prisrv.PolGen(msk,DK_C_frec);
        if(ret != 0)
        {
            printf("prisrv.PolGen client Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("prisrv.PolGen client ret : %d time =%f sec\n",ret,sum);
    //////////////////////////broadcast
    ACME_CIPHER cipher;
    PriSrv_MSG_B msg_b;
    Big z;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret =prisrv.Broadcast(mpk, cred_key, cred_s, service_key, service_attr,bid, X_s, cipher, msg_b,z);
        if(ret != 0)
        {
            printf("prisrv.Broadcast  Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("prisrv.Broadcast ret : %d time =%f sec\n",ret,sum);
    ////////////////////////////Clint init
    Big x;
    PriSrv_C1 C1_msg;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret =prisrv.AMA_Cinit(mpk, cred_key, cred_c, client_key, Dk_C_xrec, DK_C_frec, X_s, X_c, client_attr, sid, cipher, msg_b, x, C1_msg);
        if(ret != 0)
        {
            printf("prisrv.AMA_Cinit  Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("prisrv.AMA_Cinit ret : %d time =%f sec\n",ret,sum);
    //////////////////////Service
    PriSrv_S S_msg;
    PriSrv_SSK ssk_s;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret =prisrv.AMA_S(mpk, cred_key, cred_s, service_key,z, service_attr, bid, Dk_S_xrec, DK_S_frec, X_s, X_c, C1_msg, S_msg, ssk_s);
        if(ret != 0)
        {
            printf("prisrv.AMA_S  Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("prisrv.AMA_S ret : %d time =%f sec\n",ret,sum);
    ///////////////////client rcv
    PriSrv_SSK ssk_c;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret =prisrv.AMA_Cverify(mpk, cred_key, cred_c, client_key, Dk_C_xrec, DK_C_frec, X_s, X_c, client_attr, sid,x, C1_msg, S_msg,ssk_c);
        if(ret != 0)
        {
            printf("prisrv.AMA_Cverify  Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("prisrv.AMA_Cverify ret : %d time =%f sec\n",ret,sum);
    if(ssk_c.ssk!=ssk_s.ssk)
    {
        printf("prisrv.AMA_C key  Erro ret =%d\n",ret);
        return 1;
    }
    /////////////////////trace
#if 0
    Big bid_1,sid_1;
    ret =prisrv.Trace(cred_key, C1_msg.CT.cipher_tok, bid);

    ret =prisrv.Trace(cred_key, C1_msg.CT.cipher_tok, bid);
#endif
    printf("#################test PriSrv speed end#######################\n");

    return 0;
}

#define P_LEN 4
struct Big_C
{
    unsigned int len;
    long w[P_LEN];

};
struct G1_C
{
    Big_C X,Y,Z;
};
int main()
{
#if 0
    PFC pfc(AES_SECURITY);
    Big b,a;
    pfc.random(b);
    Big_C bc;
    bc.len=b.fn->len;
    memcpy(bc.w,b.fn->w,sizeof(long)*bc.len);

    a.fn->len=bc.len;
    memcpy(a.fn->w,bc.w,sizeof(long)*bc.len);

    if(a!=b) printf("Big erro\n");
    printf("len=%d\n",bc.len);
    for(int i=0;i<bc.len;i++)
    {
        printf("0x%lx,\n",bc.w[i]);

    }
    ///////////////////////////////////////////
    G1 A1,A2;
    pfc.random(A1);
    G1_C AC;
    Big X,Y,Z;
    Big X_,Y_,Z_;
    A1.g.getxyz(X,Y,Z);
    AC.X.len=X.fn->len;
    memcpy(AC.X.w,X.fn->w,sizeof(long)*AC.X.len);
    AC.Y.len=Y.fn->len;
    memcpy(AC.Y.w,Y.fn->w,sizeof(long)*AC.Y.len);
    AC.Z.len=Z.fn->len;
    memcpy(AC.Z.w,Z.fn->w,sizeof(long)*AC.Z.len);

    X_.fn->len=AC.X.len;
    memcpy(X_.fn->w,AC.X.w,sizeof(long)*X_.fn->len);
    Y_.fn->len=AC.Y.len;
    memcpy(Y_.fn->w,AC.Y.w,sizeof(long)*Y_.fn->len);
    Z_.fn->len=AC.Z.len;
    memcpy(Z_.fn->w,AC.Z.w,sizeof(long)*Z_.fn->len);

    A2.g.set(X_,Y_);
    A2.g.setz(Z_);
    if(A1 !=A2) printf("G1 erro\n");
    printf("X len=%d\n",AC.X.len);
    for(int i=0;i<AC.X.len;i++)
    {
        printf("0x%lx,\n",AC.X.w[i]);

    }
    printf("Y len=%d\n",AC.Y.len);
    for(int i=0;i<AC.Y.len;i++)
    {
        printf("0x%lx,\n",AC.Y.w[i]);

    }
    printf("Z len=%d\n",AC.Z.len);
    for(int i=0;i<AC.Z.len;i++)
    {
        printf("0x%lx,\n",AC.Z.w[i]);

    }
    ////////////////G2








    return 0;
#endif
    return speed();

}
