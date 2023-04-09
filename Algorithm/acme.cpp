#include "acme.h"
#include "aes_ctr.h"
ACME::ACME(PFC *p):lss(p),fac(p),cp_abe(p)
{
    pfc=p;

}
ACME::~ACME()
{

}
int ACME::SetUp(ACME_MSK &msk,ACME_MPK &mpk)
{
    int ret = cp_abe.SetUp(msk.msk,mpk.mpk);
    if(ret) return -1;
    return 0;
}
int ACME::CredKeyGen(ACME_CRED_KEY &cred_key)
{
    int ret = fac.CredKeyGen(cred_key.cred_key);
    if(ret) return -1;
    return 0;
}
int ACME::UserKeyGen(ACME_USER_KEY &user_key)
{
    int ret = fac.UserKeyGen(user_key.user_key);

    if(ret) return -1;
    return 0;
}
int ACME::IssueUser_Send(ACME_USER_KEY &user_key,USER_ATTR &attr,Big &uid,ACME_SPK1 &spk1)
{
    int ret = fac.IssueUser_Send(user_key.user_key,attr,uid,spk1.spk1);
    if(ret) return -1;
    return 0;

}
int ACME::IssueIssuer(ACME_CRED_KEY &cred_key, USER_ATTR &attr, Big &uid, ACME_SPK1 &spk1, ACME_USER_PK &upk, ACME_CRED_U &cred_u)
{
    int ret = fac.IssueIssuer(cred_key.cred_key,attr,uid,spk1.spk1,upk.upk,cred_u.cred_u);
    if(ret) return -1;
    return 0;

}
int ACME::IssueUser_Verify(ACME_CRED_KEY_PK &pk,ACME_CRED_U &cred_u,USER_ATTR &attr,Big &uid,ACME_USER_KEY &user_key)
{
    int ret = fac.IssueUser_Verify(pk.pk,cred_u.cred_u,attr,uid,user_key.user_key);
    if(ret) return -1;
    return 0;

}
int ACME::DKeyGen(ACME_MSK &msk,  ACME_X &X_rcv, ACME_ABE_DK_X_REC &Dk_xrec)
{
    int ret = cp_abe.KeyGen(msk.msk,X_rcv.X,Dk_xrec.sk);
    if(ret) return -1;
    return 0;
}
int ACME::PolGen(ACME_MSK &msk,ACME_ABE_DK_f_REC &DK_f_rec)
{
    Big r[LSS_NC_SHARE_NUM][CP_ABE_PARA_K];
    LSS_NC_SHARE_INFO share_info[2*CP_ABE_PARA_K];
    //dkj
    for(int i=0;i<LSS_NC_SHARE_NUM;i++)
    {
        for(int j=0;j<CP_ABE_PARA_K;j++)
        {
            pfc->random(r[i][j]);
            DK_f_rec.dk[i][j]=pfc->mult(*pfc->hh,r[i][j]);
        }
    }
    //
    for(int i=0;i<2*CP_ABE_PARA_K;i++)
    {
        lss.share(msk.msk.V[i],share_info[i]);
#if 0 //test
        Big V;
        lss.reconstruct(share_info[i],V);
        if(V!=msk.msk.V[i])
        {
            printf("\n lss.reconstruct msk V erro i=%d\n",i);
            return -10;
        }

#endif
    }
    memcpy(DK_f_rec.share.rou,share_info[0].rou,sizeof(int)*(LSS_NC_SHARE_NUM+1));
    memcpy(DK_f_rec.share.w,share_info[0].w,sizeof(int)*(LSS_NC_SHARE_NUM+1));
    memcpy(DK_f_rec.share.fMatrix,share_info[0].fMatrix,sizeof(int)*((LSS_NC_PARA_N+1)*(LSS_NC_SHARE_NUM)));
    //dkij
    Big dk_rou[CP_ABE_PARA_N+1][LSS_NC_SHARE_NUM][2*CP_ABE_PARA_K];
    for(int i=0;i<CP_ABE_PARA_N+1;i++)
    {
        for(int j=0;j<LSS_NC_SHARE_NUM;j++)
        {
            if(DK_f_rec.share.fMatrix[i][j]==0)
            {
                for(int t=0;t<2*CP_ABE_PARA_K;t++)
                {
                    dk_rou[i][j][t]=0;
                }
            }
            else if(DK_f_rec.share.fMatrix[i][j]==1)
            {
                if(i==0)//share.rou[j]==0
                {
                    for(int t=0;t<2*CP_ABE_PARA_K;t++)
                    {
                        dk_rou[i][j][t]=share_info[t].bu[j];
                    }
                }
                else
                {
                    for(int l=0;l<2*CP_ABE_PARA_K;l++)
                    {
                        dk_rou[i][j][l]=pfc->Zpmulti(msk.msk.W[i-1][l][0],r[j][0]);
                        for(int m=1;m<CP_ABE_PARA_K;m++)
                        {
                            Big T=pfc->Zpmulti(msk.msk.W[i-1][l][m],r[j][m]);
                            dk_rou[i][j][l]=pfc->Zpadd(dk_rou[i][j][l],T);
                        }
                    }
                    for(int t=0;t<2*CP_ABE_PARA_K;t++)
                    {
                        dk_rou[i][j][t]=pfc->Zpadd(dk_rou[i][j][t],share_info[t].bu[j]);
                    }
                }
            }
            else//2
            {
                for(int l=0;l<2*CP_ABE_PARA_K;l++)
                {
                    dk_rou[i][j][l]=pfc->Zpmulti(msk.msk.W[i-1][l][0],r[j][0]);
                    for(int m=1;m<CP_ABE_PARA_K;m++)
                    {
                        Big T=pfc->Zpmulti(msk.msk.W[i-1][l][m],r[j][m]);
                        dk_rou[i][j][l]=pfc->Zpadd(dk_rou[i][j][l],T);
                    }
                }
            }
        }
    }
    for(int k=0;k<CP_ABE_PARA_N+1;k++)
    {
        for(int i=0;i<LSS_NC_SHARE_NUM;i++)
        {
            for(int j=0;j<2*CP_ABE_PARA_K;j++)
            {
                DK_f_rec.dk_rou[k][i][j]=pfc->mult(*pfc->hh,dk_rou[k][i][j]);
            }
        }
    }
#if 0//test
    for(int k=0;k<2*CP_ABE_PARA_K;k++)
    {
        for(int i=0;i<LSS_NC_SHARE_NUM;i++)
        {
            DK_f_rec.share.share_info[k].bu[i]=share_info[k].bu[i];
            DK_f_rec.share.share_info[k].u[i]=share_info[k].u[i];
            DK_f_rec.share.share_info[k].rou[i]=share_info[k].rou[i];
            DK_f_rec.share.share_info[k].w[i]=share_info[k].w[i];
        }
        for(int i=0;i<LSS_NC_PARA_N+1;i++)
        {
            for(int j=0;j<LSS_NC_SHARE_NUM;j++)
            {
                DK_f_rec.share.share_info[k].fMatrix[i][j]=share_info[k].fMatrix[i][j];
            }
        }
        DK_f_rec.V[k]=msk.msk.V[k];

    }

#endif
    return 0;
}
int ACME::Enc(ACME_MPK &mpk, ACME_CRED_KEY cred_key_pk, ACME_CRED_U &cred_snd, ACME_USER_KEY &user_key, USER_ATTR &attr, Big &uid, ACME_X &X_snd, Big &M, ACME_CIPHER &cipher)
{
    FAC_TOK t_tok;
    int ret = fac.Show(cred_key_pk.cred_key.pk,cred_snd.cred_u,attr,cipher.disclose,uid,user_key.user_key,t_tok,M);
    if(ret !=0) return -1;

    Big s[CP_ABE_PARA_K],s_[CP_ABE_PARA_K],sj[LSS_NC_SHARE_NUM][CP_ABE_PARA_K];
    for(int k=0;k<CP_ABE_PARA_K;k++)
    {
        pfc->random(s[k]);
        pfc->random(s_[k]);
        for(int i=0;i<LSS_NC_SHARE_NUM;i++)
        {
            pfc->random(sj[i][k]);
        }

    }
    //sAU0 -f-share
    LSS_NC_SHARE_INFO share_info[CP_ABE_PARA_K];
    G1 U[CP_ABE_PARA_K];
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        U[i]=pfc->mult(mpk.mpk.AU01[0][i],s[0]);
        for(int j=1;j<CP_ABE_PARA_K;j++)
        {
            G1 B1=pfc->mult(mpk.mpk.AU01[j][i],s[j]);
            U[i]=U[i]+B1;
        }
        lss.share(U[i],share_info[i]);
    }

    memcpy(cipher.share.rou,share_info[0].rou,sizeof(int)*(LSS_NC_SHARE_NUM+1));
    memcpy(cipher.share.w,share_info[0].w,sizeof(int)*(LSS_NC_SHARE_NUM+1));
    memcpy(cipher.share.fMatrix,share_info[0].fMatrix,sizeof(int)*((LSS_NC_PARA_N+1)*(LSS_NC_SHARE_NUM)));

    //ctm
    G1 K1;
    G2 K2;
    GT K;
    pfc->random(K1);
    pfc->random(K2);
    K=pfc->pairing(K2,K1);
#if 0//test
    cipher.K=K;
#endif
    //encrypt
#if 0//test  AES is not implemented here
    cipher.cipher_M=M;
    cipher.cipher_tok.T1=t_tok.T1;
    cipher.cipher_tok.T2=t_tok.T2;
    cipher.cipher_tok.sigma1=t_tok.sigma1;
    cipher.cipher_tok.sigma2=t_tok.sigma2;
    cipher.cipher_tok.spk2.c=t_tok.spk2.c;
    cipher.cipher_tok.spk2.gama=t_tok.spk2.gama;
    cipher.cipher_tok.spk2.sd=t_tok.spk2.sd;
    cipher.cipher_tok.spk2.sk=t_tok.spk2.sk;
#endif


    //ct0
    Big u[CP_ABE_PARA_K];
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        u[i]=pfc->Zpadd(s[i],s_[i]);

    }
    cipher.ct0=pfc->power(*pfc->gt,0);
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        GT T1=pfc->power(mpk.mpk.eAV[i],u[i]);
        cipher.ct0=cipher.ct0*T1;
    }

    cipher.ct0=cipher.ct0*K;
    //ct1 1*2k
    for(int j=0;j<2*CP_ABE_PARA_K;j++)
    {
        cipher.ct1[j]=pfc->mult(mpk.mpk.A1[0][j],s[0]);
        for(int i=1;i<CP_ABE_PARA_K;i++)
        {
            cipher.ct1[j]=cipher.ct1[j]+pfc->mult(mpk.mpk.A1[i][j],s[i]);
        }
    }
    //ct1_ 1*2k
    for(int j=0;j<2*CP_ABE_PARA_K;j++)
    {
        cipher.ct1_[j]=pfc->mult(mpk.mpk.A1[0][j],s_[0]);
        for(int i=1;i<CP_ABE_PARA_K;i++)
        {
            cipher.ct1_[j]=cipher.ct1_[j]+pfc->mult(mpk.mpk.A1[i][j],s_[i]);
        }
    }
    //ct2_
    G1 AW[CP_ABE_PARA_K][CP_ABE_PARA_K];
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        for(int j=0;j<CP_ABE_PARA_K;j++)
        {
            AW[i][j]=pfc->mult(*pfc->gg,0);

        }
    }
    for(int k=0;k<CP_ABE_PARA_N;k++)
    {
        if(X_snd.X.x[k]==1)
            for(int i=0;i<CP_ABE_PARA_K;i++)
            {
                for(int j=0;j<CP_ABE_PARA_K;j++)
                {
                    AW[i][j]=AW[i][j]+mpk.mpk.AW1[k][i][j];

                }
            }
    }
    for(int j=0;j<CP_ABE_PARA_K;j++)
    {
        cipher.ct2_[j]=pfc->mult(AW[0][j],s_[0]);
        for(int i=1;i<CP_ABE_PARA_K;i++)
        {
            cipher.ct2_[j]=cipher.ct2_[j]+pfc->mult(AW[i][j],s_[i]);
        }
    }

    //ct2j
    for(int k=0;k<LSS_NC_SHARE_NUM;k++)
    {
        for(int j=0;j<2*CP_ABE_PARA_K;j++)
        {
            cipher.ct2[k][j]=pfc->mult(mpk.mpk.A1[0][j],sj[k][0]);
            for(int i=1;i<CP_ABE_PARA_K;i++)
            {
                cipher.ct2[k][j]=cipher.ct2[k][j]+pfc->mult(mpk.mpk.A1[i][j],sj[k][i]);
            }
        }
    }

    //ct_rou,j

    for(int i=0;i<CP_ABE_PARA_N+1;i++)
    {
        for(int j=0;j<LSS_NC_SHARE_NUM;j++)
        {
            if(cipher.share.fMatrix[i][j]==0)
                continue;
            else if(cipher.share.fMatrix[i][j]==1)
            {
                if(i==0)//share.rou[j]==0
                {
                    for(int t=0;t<CP_ABE_PARA_K;t++)
                    {
                        cipher.ct_rou[i][j][t]=share_info[t].u[j];
                    }
                }
                else
                {
                    for(int l=0;l<CP_ABE_PARA_K;l++)
                    {
                        cipher.ct_rou[i][j][l]=pfc->mult(mpk.mpk.AW1[i-1][0][l],sj[j][0]);
                        for(int m=1;m<CP_ABE_PARA_K;m++)
                        {
                            G1 T=pfc->mult(mpk.mpk.AW1[i-1][m][l],sj[j][m]);
                            cipher.ct_rou[i][j][l]=cipher.ct_rou[i][j][l]+T;
                        }
                    }
                    for(int t=0;t<CP_ABE_PARA_K;t++)
                    {
                        cipher.ct_rou[i][j][t]=cipher.ct_rou[i][j][t]+share_info[t].u[j];
                    }
                }
            }
            else//2
            {
                for(int l=0;l<CP_ABE_PARA_K;l++)
                {
                    cipher.ct_rou[i][j][l]=pfc->mult(mpk.mpk.AW1[i-1][0][l],sj[j][0]);
                    for(int m=1;m<CP_ABE_PARA_K;m++)
                    {
                        G1 T=pfc->mult(mpk.mpk.AW1[i-1][m][l],sj[j][m]);
                        cipher.ct_rou[i][j][l]=cipher.ct_rou[i][j][l]+T;
                    }
                }
            }
        }
    }

#if 1 //aes_ctr
    AES_CTR aes_ctr;
    pfc->start_hash();
    Big key=pfc->hash_to_aes_key(K);
    char aes_key[16]={0},aes_iv[8]={0};
    memcpy(aes_key,key.fn->w,16);
    memcpy(aes_iv,key.fn->w+2,8);

    aes_ctr.init(aes_key,aes_iv);
    ret = aes_ctr.encrypt_add(M);
    if(ret !=0) return -10;
    ret = aes_ctr.encrypt_add(t_tok.T1);
    if(ret !=0) return -11;
    ret = aes_ctr.encrypt_add(t_tok.T2);
    if(ret !=0) return -12;
    ret = aes_ctr.encrypt_add(t_tok.sigma1);
    if(ret !=0) return -13;
    ret = aes_ctr.encrypt_add(t_tok.sigma2);
    if(ret !=0) return -14;
    ret = aes_ctr.encrypt_add(t_tok.spk2.c);
    if(ret !=0) return -15;
    ret = aes_ctr.encrypt_add(t_tok.spk2.gama);
    if(ret !=0) return -16;
    ret = aes_ctr.encrypt_add(t_tok.spk2.sd);
    if(ret !=0) return -17;
    ret = aes_ctr.encrypt_add(t_tok.spk2.sk);
    if(ret !=0) return -18;
    ret =aes_ctr.encrypt_data(cipher.cipher,&cipher.cipher_len);
    if(ret !=0) return -19;
 //   printf("cipher.cipher_len %d\n",cipher.cipher_len);

#endif
#if 0//test

    for(int k=0;k<LSS_NC_SHARE_NUM;k++)
    {
        cipher.share.uBr[k]=pfc->power(*pfc->gt,0);
        for(int i=0;i<CP_ABE_PARA_K;i++)
        {
            GT T=pfc->pairing(Dk_xrec.sk.sk2[i],share_info[i].u[k]);
            cipher.share.uBr[k]=cipher.share.uBr[k]*T;
        }
    }
    for(int k=0;k<LSS_NC_SHARE_NUM;k++)
    {

        cipher.share.s_Avj[k]=pfc->power(*pfc->gt,0);
        for(int i=0;i<2*CP_ABE_PARA_K;i++)
        {
#if 1
            Big V;
            lss.reconstruct(DK_f_rec.share.share_info[i],V);
            if(V!=DK_f_rec.V[i])
                printf("\n lss.reconstruct DK_f_rec V erro i=%d\n",i);
#endif
            G2 T2=pfc->mult(*pfc->hh,DK_f_rec.share.share_info[i].bu[k]);
            GT T=pfc->pairing(T2,cipher.ct1_[i]);
            cipher.share.s_Avj[k]=cipher.share.s_Avj[k]*T;
        }
        cipher.share.s_Avj[k]=1/cipher.share.s_Avj[k];
    }

    cipher.share.s_Av=pfc->power(*pfc->gt,0);
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        GT T=pfc->power(mpk.mpk.eAV[i],s_[i]);
        cipher.share.s_Av=cipher.share.s_Av*T;
    }
    cipher.share.s_Av=1/cipher.share.s_Av;

    cipher.share.sAv=pfc->power(*pfc->gt,0);
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        GT T=pfc->power(mpk.mpk.eAV[i],s[i]);
        cipher.share.sAv=cipher.share.sAv*T;
    }
    //cipher.share.sAv=1/cipher.share.sAv;
    for(int i=0;i<CP_ABE_PARA_N+1;i++)
    {
        printf("\n");
        for(int j=0;j<LSS_NC_SHARE_NUM;j++)
            printf("%d\t",cipher.share.fMatrix[i][j]);
    }

#endif

    return 0;
}
int ACME::Den(ACME_CRED_KEY cred_key_pk, ACME_ABE_DK_X_REC &Dk_xrec, ACME_ABE_DK_f_REC &DK_f_rec, ACME_X &X_snd, ACME_X &X_rcv, ACME_CIPHER &cipher, ACME_PLAIN &plain)
{    
    //e(ct1,dk1)
    GT T,SUM;
    SUM=pfc->pairing(Dk_xrec.sk.sk1[0],cipher.ct1[0]);
    for(int i=1;i<2*CP_ABE_PARA_K;i++)
    {
        T=pfc->pairing(Dk_xrec.sk.sk1[i],cipher.ct1[i]);
        SUM=SUM*T;
    }
    //ct0/e(ct1,dk1)
    GT K=cipher.ct0/SUM;

    //1/s_Avj---s_Av
    //II_(xi=1)dki,j
    G2 DK_rou[LSS_NC_SHARE_NUM][2*CP_ABE_PARA_K];
    for(int j=0;j<LSS_NC_SHARE_NUM;j++)
    {
        for(int k=0;k<2*CP_ABE_PARA_K;k++)
            DK_rou[j][k]=DK_f_rec.dk_rou[0][j][k];
        //dk0j
        if(DK_f_rec.share.w[j]!=0)
        {
            for(int i=0;i<CP_ABE_PARA_N;i++)
            {
                if(X_snd.X.x[i]==1)
                {
                    for(int k=0;k<2*CP_ABE_PARA_K;k++)
                    {
                        DK_rou[j][k]=DK_rou[j][k]+DK_f_rec.dk_rou[i+1][j][k];
                    }
                }
            }
        }
    }
#if 0//opt
    GT MT1=pfc->power(*pfc->gt,0);
    for(int j=0;j<LSS_NC_SHARE_NUM;j++)
    {
        GT ET;
        if(DK_f_rec.share.w[j]!=0)
        {
            GT E1,E1S=pfc->power(*pfc->gt,0);
            for(int k=0;k<2*CP_ABE_PARA_K;k++)
            {
                E1=pfc->pairing(DK_rou[j][k],cipher.ct1_[k]);
                E1S=E1S*E1;
            }
            GT E2,E2S=pfc->power(*pfc->gt,0);
            for(int k=0;k<CP_ABE_PARA_K;k++)
            {
                E2=pfc->pairing(DK_f_rec.dk[j][k],cipher.ct2_[k]);
                E2S=E2S*E2;
            }
            ET=E2S/E1S;
#if 0 //test
            if(ET!=cipher.share.s_Avj[j])
            {
                printf("s_avj erro j=%d w=%d!\n",j,DK_f_rec.share.w[j]);
            }
#endif
            ET=pfc->power(ET,DK_f_rec.share.w[j]);
      //      ET=pfc->power(cipher.share.s_Avj[j],DK_f_rec.share.w[j]);
            MT1=MT1*ET;
        }
    }
#else
    GT MT1=pfc->power(*pfc->gt,0);
    GT ES1=pfc->power(*pfc->gt,0);
    GT ES2=pfc->power(*pfc->gt,0);
    for(int k=0;k<CP_ABE_PARA_K;k++)
    {
        G2 S1=pfc->mult(*pfc->hh,0);
        for(int j=0;j<LSS_NC_SHARE_NUM;j++)
        {
            if(DK_f_rec.share.w[j]!=0)
            {
                                
                G2 ST=pfc->mult(DK_f_rec.dk[j][k],DK_f_rec.share.w[j]);
                S1=S1+ST;   

            }
        }
        ES1=ES1*pfc->pairing(S1,cipher.ct2_[k]);
        
    }
    for(int k=0;k<2*CP_ABE_PARA_K;k++)
    {
        G2 S1=pfc->mult(*pfc->hh,0);
        for(int j=0;j<LSS_NC_SHARE_NUM;j++)
        {
            if(DK_f_rec.share.w[j]!=0)
            {
                                
                G2 ST=pfc->mult(DK_rou[j][k],DK_f_rec.share.w[j]);
                S1=S1+ST;   

            }

        }
        ES2=ES2*pfc->pairing(S1,cipher.ct1_[k]);        
    }
    MT1= ES1/ES2;

#endif

#if 0//test

    if(MT1 != cipher.share.s_Av)
        printf("s_Av erro !\n");

#endif
    //uj*Br--sAU0Br
    //II_(xi=1)cti,j
    G1 CT_rou[LSS_NC_SHARE_NUM][CP_ABE_PARA_K];
    for(int j=0;j<LSS_NC_SHARE_NUM;j++)
    {
        for(int k=0;k<CP_ABE_PARA_K;k++)
            CT_rou[j][k]=cipher.ct_rou[0][j][k];
        //ct0j
        if(DK_f_rec.share.w[j]!=0)
        {
            for(int i=0;i<CP_ABE_PARA_N;i++)
            {
                if(X_rcv.X.x[i]==1)
                {
                    for(int k=0;k<CP_ABE_PARA_K;k++)
                    {
                        CT_rou[j][k]=CT_rou[j][k]+cipher.ct_rou[i+1][j][k];
                    }
                }
            }
        }
    }
#if 0//opt
    GT MT2=pfc->power(*pfc->gt,0);
    for(int j=0;j<LSS_NC_SHARE_NUM;j++)
    {
        GT ET;
        if(cipher.share.w[j]!=0)
        {
            GT E1,E1S=pfc->power(*pfc->gt,0);
            for(int k=0;k<CP_ABE_PARA_K;k++)
            {
                E1=pfc->pairing(Dk_xrec.sk.sk2[k],CT_rou[j][k]);
                E1S=E1S*E1;
            }
            GT E2,E2S=pfc->power(*pfc->gt,0);
            for(int k=0;k<2*CP_ABE_PARA_K;k++)
            {
                E2=pfc->pairing(Dk_xrec.sk.sk3[k],cipher.ct2[j][k]);
                E2S=E2S*E2;
            }
            ET=E1S/E2S;
#if 0 //test
            if(ET!=cipher.share.uBr[j])
            {
                printf("uBr erro j=%d w=%d!\n",j,cipher.share.w[j]);
            }
#endif
            ET=pfc->power(ET,cipher.share.w[j]);
            // ET=pfc->power(share.uBr[j],share.w[j]);
            MT2=MT2*ET;
        }
    }
#else
    GT MT2=pfc->power(*pfc->gt,0);
    GT ES3=pfc->power(*pfc->gt,0);
    GT ES4=pfc->power(*pfc->gt,0);
    for(int k=0;k<CP_ABE_PARA_K;k++)
    {
        
        G1 S1=pfc->mult(*pfc->gg,0);
        for(int j=0;j<LSS_NC_SHARE_NUM;j++)
        {
            if(cipher.share.w[j]!=0)
            {
                G1 ST=pfc->mult(CT_rou[j][k],cipher.share.w[j]);
                S1=S1+ST; 
            }

        }
        ES3=ES3*pfc->pairing(Dk_xrec.sk.sk2[k],S1);        
    }
    
    for(int k=0;k<2*CP_ABE_PARA_K;k++)
    {
        
        G1 S1=pfc->mult(*pfc->gg,0);
        for(int j=0;j<LSS_NC_SHARE_NUM;j++)
        {
            if(cipher.share.w[j]!=0)
            {
                G1 ST=pfc->mult(cipher.ct2[j][k],cipher.share.w[j]);
                S1=S1+ST; 
            }

        }
        ES4=ES4*pfc->pairing(Dk_xrec.sk.sk3[k],S1);        
    }
    MT2=ES3/ES4;
#endif
    K=K*MT1*MT2;
#if 0//test
    if(K!=cipher.K)
    {
        return -2;
    }
#endif
   // return 0;
#if 0//test
    plain.M=cipher.cipher_M;
    plain.tok.tok.T1=cipher.cipher_tok.T1;
    plain.tok.tok.T2=cipher.cipher_tok.T2;
    plain.tok.tok.sigma1=cipher.cipher_tok.sigma1;
    plain.tok.tok.sigma2=cipher.cipher_tok.sigma2;
    plain.tok.tok.spk2.c=cipher.cipher_tok.spk2.c;
    plain.tok.tok.spk2.gama=cipher.cipher_tok.spk2.gama;
    plain.tok.tok.spk2.sd=cipher.cipher_tok.spk2.sd;
    plain.tok.tok.spk2.sk=cipher.cipher_tok.spk2.sk;
#else //aes-ctr
    AES_CTR aes_ctr;
    pfc->start_hash();
    Big key=pfc->hash_to_aes_key(K);
    char aes_key[16]={0},aes_iv[8]={0};
    memcpy(aes_key,key.fn->w,16);
    memcpy(aes_iv,key.fn->w+2,8);

    aes_ctr.init(aes_key,aes_iv);
    int ret =aes_ctr.decrypt_data(cipher.cipher,cipher.cipher_len);
    if(ret !=0) return -19;
    ret = aes_ctr.decrypt_red(plain.tok.tok.spk2.sk);
    if(ret !=0) return -18;
    ret = aes_ctr.decrypt_red(plain.tok.tok.spk2.sd);
    if(ret !=0) return -17;
    ret = aes_ctr.decrypt_red(plain.tok.tok.spk2.gama);
    if(ret !=0) return -16;
    ret = aes_ctr.decrypt_red(plain.tok.tok.spk2.c);
    if(ret !=0) return -15;
    ret = aes_ctr.decrypt_red(plain.tok.tok.sigma2);
    if(ret !=0) return -14;
    ret = aes_ctr.decrypt_red(plain.tok.tok.sigma1);
    if(ret !=0) return -13;
    ret = aes_ctr.decrypt_red(plain.tok.tok.T2);
    if(ret !=0) return -12;
    ret = aes_ctr.decrypt_red(plain.tok.tok.T1);
    if(ret !=0) return -11;    
    ret = aes_ctr.decrypt_red(plain.M);
    if(ret !=0) return -10;  
   
#endif

    return fac.Verify(cred_key_pk.cred_key.pk,plain.tok.tok,plain.M,cipher.disclose);
}
int ACME::Trace(ACME_CRED_KEY &cred_key,ACME_TOK &tok,Big &uid)
{
    return fac.Trace(cred_key.cred_key,tok.tok,uid);
}
