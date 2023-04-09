#include "macddh.h"

MACddh::MACddh(PFC *p)
{
    pfc=p;

#if 0
    pfc->random(g);
    pfc->random(h);
#endif
}
MACddh::~MACddh()
{

}
int MACddh::KeyGen(MACddh_SK &sk,MACddh_PK &pk)
{
    pfc->random(sk.z);
    for(int i=0;i<MACddh_PARA_N+1;i++)
    {
        pfc->random(sk.x[i]);
        pfc->random(sk.y[i]);
        pk.X[i]=pfc->mult(*pfc->gg1,sk.x[i]);
        pk.Y[i]=pfc->mult(*pfc->gg1,sk.y[i]);
    }
    G1 T;
    Big x,y,z;
    pk.Cx0=pfc->mult(*pfc->gg1,x);
    T=pfc->mult(*pfc->gg,sk.x[0]);
    pk.Cx0=pk.Cx0+T;
    pk.Cy0=pfc->mult(*pfc->gg1,y);
    T=pfc->mult(*pfc->gg,sk.y[0]);
    pk.Cy0=pk.Cy0+T;
    pk.Cz=pfc->mult(*pfc->gg1,z);
    T=pfc->mult(*pfc->gg,sk.z);
    pk.Cz=pk.Cz+T;

    return 0;
}
int MACddh::MAC(MACddh_SK &sk, MACddh_M &M, MACddh_MAC &mac)
{
    if(M.N >MACddh_PARA_N) return -1;
    Big r;
    pfc->random(r);
    mac.sig_w=pfc->mult(*pfc->gg,r);
    Big sum=sk.x[0],A=0;
    for(int i=1;i<M.N+1;i++)
    {
        A=pfc->Zpmulti(sk.x[i],M.m[i-1]);
        sum=pfc->Zpadd(sum,A);
    }
    sum=pfc->Zpmulti(r,sum);
    mac.sig_x=pfc->mult(*pfc->gg,sum);
    sum=sk.y[0];
    for(int i=1;i<M.N+1;i++)
    {
        A=pfc->Zpmulti(sk.y[i],M.m[i-1]);
        sum=pfc->Zpadd(sum,A);
    }
    sum=pfc->Zpmulti(r,sum);
    mac.sig_y=pfc->mult(*pfc->gg,sum);
    sum=pfc->Zpmulti(sk.z,r);
    mac.sig_z=pfc->mult(*pfc->gg,sum);
    return 0;
}
int MACddh::Verify(MACddh_SK &sk, MACddh_M &M, MACddh_MAC &mac)
{
    if(M.N >MACddh_PARA_N) return -4;
    if(mac.sig_w==*pfc->gg) return -1;
    Big sum=sk.x[0],A=0;
    for(int i=1;i<M.N+1;i++)
    {
        A=pfc->Zpmulti(sk.x[i],M.m[i-1]);
        sum=pfc->Zpadd(sum,A);
    }
    G1 sig_x=pfc->mult(mac.sig_w,sum);
    if(sig_x != mac.sig_x) return -2;

    sum=sk.y[0],A=0;
    for(int i=1;i<M.N+1;i++)
    {
        A=pfc->Zpmulti(sk.y[i],M.m[i-1]);
        sum=pfc->Zpadd(sum,A);
    }
    G1 sig_y=pfc->mult(mac.sig_w,sum);
    if(sig_y != mac.sig_y) return -3;

    return 0;
}
