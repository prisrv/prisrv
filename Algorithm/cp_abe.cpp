#include "cp_abe.h"

CP_ABE::CP_ABE(PFC *p)
{
    lss=new LSS_NC(p);
    pfc=p;
#if 0 //
    pfc->random(g);
    pfc->random(h);
    gt=pfc->pairing(h,g);
#endif

}
CP_ABE::~CP_ABE()
{
    delete lss;
}
int CP_ABE::SetUp(CP_ABE_MSK &msk,CP_ABE_MPK &mpk)
{    
    //return 0;
    //A,[A]1,k*2k
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        for(int j=0;j<2*CP_ABE_PARA_K;j++)
        {
            pfc->random(msk.A[i][j]);
            mpk.A1[i][j]=pfc->mult(*pfc->gg,msk.A[i][j]);

        }
    }
    //B,k*k
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        for(int j=0;j<CP_ABE_PARA_K;j++)
        {
            pfc->random(msk.B[i][j]);

        }
    }
    //U0,2k*k
    for(int i=0;i<2*CP_ABE_PARA_K;i++)
    {
        for(int j=0;j<CP_ABE_PARA_K;j++)
        {
            pfc->random(msk.U0[i][j]);

        }
    }
    //[AU0]1,k*k
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        for(int j=0;j<CP_ABE_PARA_K;j++)
        {
            Big T,SUM=0;
            for(int k=0;k<2*CP_ABE_PARA_K;k++)
            {
                T=pfc->Zpmulti(msk.A[i][k],msk.U0[k][j]);
                SUM=SUM+T;
            }
            mpk.AU01[i][j]=pfc->mult(*pfc->gg,SUM);
        }
    }
    //Wi N*2k*k
    for(int i=0;i<CP_ABE_PARA_N;i++)
    {
        for(int j=0;j<2*CP_ABE_PARA_K;j++)
        {
            for(int k=0;k<CP_ABE_PARA_K;k++)
            {
                pfc->random(msk.W[i][j][k]);

            }
        }
    }
    //[AWi]1,N*k*k

    for(int t=0;t<CP_ABE_PARA_N;t++)
    {
        for(int i=0;i<CP_ABE_PARA_K;i++)
        {
            for(int j=0;j<CP_ABE_PARA_K;j++)
            {
                Big T,SUM=0;
                for(int k=0;k<2*CP_ABE_PARA_K;k++)
                {
                    T=pfc->Zpmulti(msk.A[i][k],msk.W[t][k][j]);
                    SUM=SUM+T;
                }
                mpk.AW1[t][i][j]=pfc->mult(*pfc->gg,SUM);
            }
        }
    }
    //V,2k

    for(int i=0;i<2*CP_ABE_PARA_K;i++)
    {
        pfc->random(msk.V[i]);
      //  pfc->random_ord(msk.V[i]);
    }


    for(int i=0;i<2*CP_ABE_PARA_K;i++)
    {
        pfc->random(msk.V[i]);
        //pfc->random_ord(msk.V[i]);
#if 0//test
        Big V;
        LSS_NC_SHARE_INFO share_info;
        lss->share(msk.V[i],share_info);
        lss->reconstruct(share_info,V);
        if(V!=msk.V[i])
        {
            printf("\n lss.reconstruct msk V erro i=%d\n",i);
            return -10;
        }


#endif
    }
    //e(A,v),k
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        Big T,SUM=0;
        for(int j=0;j<2*CP_ABE_PARA_K;j++)
        {
            T=pfc->Zpmulti(msk.A[i][j],msk.V[j]);
            SUM=SUM+T;
        }
        mpk.eAV[i]=pfc->power(*pfc->gt,SUM);
    }

    return 0;
}
int CP_ABE::KeyGen(CP_ABE_MSK &msk, CP_APE_X &X, CP_ABE_SK &sk)
{

    Big r[CP_ABE_PARA_K],T;
    //r
    for(int i=0;i<CP_ABE_PARA_K;i++)
        pfc->random(r[i]);

    //[Br]2,k*1
    Big Br[CP_ABE_PARA_K]={0};
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        Br[i]=0;
        for(int j=0;j<CP_ABE_PARA_K;j++)
        {

            T=pfc->Zpmulti(msk.B[i][j],r[j]);
            Br[i]=Br[i]+T;
        }
        sk.sk2[i]=pfc->mult(*pfc->hh,Br[i]);
    }
    //U0*B*r,2k*1
    Big Te[2*CP_ABE_PARA_K];
    for(int i=0;i<2*CP_ABE_PARA_K;i++)
    {
        Te[i]=0;
        for(int j=0;j<CP_ABE_PARA_K;j++)
        {

            T=pfc->Zpmulti(msk.U0[i][j],Br[j]);
            Te[i]=Te[i]+T;
        }
    }
    //[V+U0*B*r]2
    for(int i=0;i<2*CP_ABE_PARA_K;i++)
    {
        Te[i]=pfc->Zpadd(Te[i],msk.V[i]);
        sk.sk1[i]=pfc->mult(*pfc->hh,Te[i]);
    }

    //  sk.sk3[0];
    Big WBr=0,SWBr[2*CP_ABE_PARA_K]={0};
    for(int i=0;i<2*CP_ABE_PARA_K;i++)
        SWBr[i]=0;
    for(int k=0;k<CP_ABE_PARA_N;k++)
    {
        if(X.x[k]==1)
        {
#if 0 //test
            printf("\n sk3.sk3  i=%d",k);
#endif
            for(int i=0;i<2*CP_ABE_PARA_K;i++)
            {
                WBr=0;
                for(int j=0;j<CP_ABE_PARA_K;j++)
                {
                    T=pfc->Zpmulti(msk.W[k][i][j],Br[j]);
                    WBr=WBr+T;
                }
                SWBr[i]=SWBr[i]+WBr;
            }
        }
    }
    for(int k=0;k<2*CP_ABE_PARA_K;k++)
    {
        sk.sk3[k]=pfc->mult(*pfc->hh,SWBr[k]);
    }
#if 0 //test
    G2 sk3[2*CP_ABE_PARA_K],SK3[2*CP_ABE_PARA_K];
    for(int i=0;i<2*CP_ABE_PARA_K;i++)
        SK3[i]=pfc->mult(*pfc->hh,0);
    for(int k=0;k<CP_ABE_PARA_N;k++)
    {
        if(X.x[k]==1)
        {
            for(int i=0;i<2*CP_ABE_PARA_K;i++)
            {
                sk3[i]=pfc->mult(*pfc->hh,0);
                for(int j=0;j<CP_ABE_PARA_K;j++)
                {
                    G2 T=pfc->mult(sk.sk2[j],msk.W[k][i][j]);
                    sk3[i]=sk3[i]+T;
                }
                SK3[i]=SK3[i]+sk3[i];
            }

        }

    }
    for(int k=0;k<2*CP_ABE_PARA_K;k++)
    {
        if(sk.sk3[k]!= SK3[k])
            printf("\n sk3 erro i=%d",k);
    }

#endif

    return 0;
}
int CP_ABE::Enc(CP_ABE_MPK &mpk,GT &M, CP_ABE_CIPHER &cipher, CP_ABE_SHARE_INFO &share)
{
    Big s[CP_ABE_PARA_K],sj[LSS_NC_SHARE_NUM][CP_ABE_PARA_K];
    LSS_NC_SHARE_INFO share_info[CP_ABE_PARA_K];
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        pfc->random(s[i]);
        for(int j=0;j<LSS_NC_SHARE_NUM;j++)
            pfc->random(sj[j][i]);
    }
#if 0//test
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        sj[0][i]=s[i];
    }
#endif
    //share s'[AU0]1
    G1 U[CP_ABE_PARA_K];
    for(int i=0;i<CP_ABE_PARA_K;i++)
    {
        U[i]=pfc->mult(mpk.AU01[0][i],s[0]);
        for(int j=1;j<CP_ABE_PARA_K;j++)
        {
            G1 B1=pfc->mult(mpk.AU01[j][i],s[j]);
            U[i]=U[i]+B1;
        }
        lss->share(U[i],share_info[i]);
    }

    //output (f) share rou and w for de
    memcpy(share.rou,share_info[0].rou,sizeof(int)*(LSS_NC_SHARE_NUM));
    memcpy(share.w,share_info[0].w,sizeof(int)*(LSS_NC_SHARE_NUM));
    memcpy(share.fMatrix,share_info[0].fMatrix,sizeof(int)*((LSS_NC_PARA_N+1)*(LSS_NC_SHARE_NUM)));
#if 0//test

    for(int k=0;k<LSS_NC_SHARE_NUM;k++)
    {
        share.uBr[k]=pfc->power(*pfc->gt,0);
        for(int i=0;i<CP_ABE_PARA_K;i++)
        {
            GT T=pfc->pairing(sk.sk2[i],share_info[i].u[k]);
            share.uBr[k]=share.uBr[k]*T;
        }
    }
    for(int i=0;i<CP_ABE_PARA_N+1;i++)
    {
        printf("\n");
        for(int j=0;j<LSS_NC_SHARE_NUM;j++)
            printf("%d\t",share.fMatrix[i][j]);
    }


#endif

    //ct1 1*1
    cipher.ct1=pfc->power(mpk.eAV[0],s[0]);
    for(int i=1;i<CP_ABE_PARA_K;i++)
    {
        GT TT= pfc->power(mpk.eAV[i],s[i]);
        cipher.ct1=cipher.ct1*TT;
    }
    cipher.ct1=cipher.ct1*M;
    //ct2 1*2k
    for(int j=0;j<2*CP_ABE_PARA_K;j++)
    {
        cipher.ct2[j]=pfc->mult(mpk.A1[0][j],s[0]);
        for(int i=1;i<CP_ABE_PARA_K;i++)
        {
            cipher.ct2[j]=cipher.ct2[j]+pfc->mult(mpk.A1[i][j],s[i]);
        }
    }

    //ct3
    for(int k=0;k<LSS_NC_SHARE_NUM;k++)
    {
        for(int j=0;j<2*CP_ABE_PARA_K;j++)
        {
            cipher.ct3[k][j]=pfc->mult(mpk.A1[0][j],sj[k][0]);
            for(int i=1;i<CP_ABE_PARA_K;i++)
            {
                cipher.ct3[k][j]=cipher.ct3[k][j]+pfc->mult(mpk.A1[i][j],sj[k][i]);
            }
        }
    }
#if 0//test
    for(int i=0;i<2*CP_ABE_PARA_K;i++)
    {
        if(cipher.ct3[0][i]!=cipher.ct2[i])
            printf("\n cipher.ct3 erro i=%d",i);
    }
#endif
    //ct-rou
    for(int i=0;i<CP_ABE_PARA_N+1;i++)
    {
        for(int j=0;j<LSS_NC_SHARE_NUM;j++)
        {
            if(share.fMatrix[i][j]==0)
                continue;
            else if(share.fMatrix[i][j]==1)
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
                        cipher.ct_rou[i][j][l]=pfc->mult(mpk.AW1[i-1][0][l],sj[j][0]);
                        for(int m=1;m<CP_ABE_PARA_K;m++)
                        {
                            G1 T=pfc->mult(mpk.AW1[i-1][m][l],sj[j][m]);
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
                    cipher.ct_rou[i][j][l]=pfc->mult(mpk.AW1[i-1][0][l],sj[j][0]);
                    for(int m=1;m<CP_ABE_PARA_K;m++)
                    {
                        G1 T=pfc->mult(mpk.AW1[i-1][m][l],sj[j][m]);
                        cipher.ct_rou[i][j][l]=cipher.ct_rou[i][j][l]+T;
                    }
                }
            }
        }
    }
    return 0;
}
int CP_ABE::Dec(CP_ABE_MPK &mpk, CP_APE_X &X, CP_ABE_SK &sk, CP_ABE_CIPHER &cipher, CP_ABE_SHARE_INFO &share, GT &M)
{
    //e(ct2,sk1)
    GT T,SUM=pfc->power(*pfc->gt,0);
    SUM=pfc->pairing(sk.sk1[0],cipher.ct2[0]);
    for(int i=1;i<2*CP_ABE_PARA_K;i++)
    {
        T=pfc->pairing(sk.sk1[i],cipher.ct2[i]);
        SUM=SUM*T;
    }
    //ct1/e(ct2,sk1)
    M=cipher.ct1/SUM;

    //II_(xi=1)cti,j
    G1 CT_rou[LSS_NC_SHARE_NUM][CP_ABE_PARA_K];
    for(int j=0;j<LSS_NC_SHARE_NUM;j++)
    {
        for(int k=0;k<CP_ABE_PARA_K;k++)
            CT_rou[j][k]=cipher.ct_rou[0][j][k];
        //ct0j
        if(share.w[j]!=0)
        {
            for(int i=0;i<CP_ABE_PARA_N;i++)
            {
                if(X.x[i]==1)
                {
                    for(int k=0;k<CP_ABE_PARA_K;k++)
                    {
                        CT_rou[j][k]=CT_rou[j][k]+cipher.ct_rou[i+1][j][k];
                    }
                }
            }
#if 0//speed
            for(int k=0;k<CP_ABE_PARA_K;k++)
                CT_rou[j][k]=pfc->mult(CT_rou[j][k],share.w[j]);
#endif
        }
    }
    GT MT=pfc->power(*pfc->gt,0);
    for(int j=0;j<LSS_NC_SHARE_NUM;j++)
    {
        GT ET;
        if(share.w[j]!=0)
        {
            GT E1,E1S=pfc->power(*pfc->gt,0);
            for(int k=0;k<CP_ABE_PARA_K;k++)
            {
                E1=pfc->pairing(sk.sk2[k],CT_rou[j][k]);
                E1S=E1S*E1;
            }
            GT E2,E2S=pfc->power(*pfc->gt,0);
            for(int k=0;k<2*CP_ABE_PARA_K;k++)
            {
                E2=pfc->pairing(sk.sk3[k],cipher.ct3[j][k]);
                E2S=E2S*E2;
            }
            ET=E1S/E2S;
#if 0 //test
            if(ET!=share.uBr[j])
            {
                printf("uBr erro j=%d w=%d!\n",j,share.w[j]);
            }
#endif
            ET=pfc->power(ET,share.w[j]);
           // ET=pfc->power(share.uBr[j],share.w[j]);
            MT=MT*ET;
        }
    }
    M=M*MT;
    return 0;

}
