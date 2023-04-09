#include "lss_nc.h"

LSS_NC::LSS_NC(PFC *p)
{
    pfc=p;
}
LSS_NC::~LSS_NC()
{

}
int LSS_NC::share(G1 &u, LSS_NC_SHARE_INFO &share_info)
{
    //u
    G1 u5,u6;
    pfc->random(share_info.u[0]);//u1
    pfc->random(share_info.u[1]);//u2
    pfc->random(share_info.u[2]);//u3
    pfc->random(share_info.u[3]);//u4
    pfc->random(u5);//u5
    pfc->random(u6);//u6
    share_info.u[4]=share_info.u[0]+u5;//u5a
    share_info.u[5]=share_info.u[1]+u5;//u5b
    share_info.u[6]=share_info.u[4]+u5;//u6
    share_info.u[6]=u6+share_info.u[6];//u6
    share_info.u[7]=u+u5;//u7a
    share_info.u[8]=u+u6;//u7b

    //rou
    share_info.rou[0]=1;//rou1
    share_info.rou[1]=2;//rou2
    share_info.rou[2]=1;//rou3
    share_info.rou[3]=3;//rou4
    share_info.rou[4]=0;
    share_info.rou[5]=0;
    share_info.rou[6]=0;
    share_info.rou[7]=0;
    share_info.rou[8]=0;

    //omg
    share_info.w[0]=1;
    share_info.w[1]=0;
    share_info.w[2]=0;
    share_info.w[3]=0;
    share_info.w[4]=-1;
    share_info.w[5]=0;
    share_info.w[6]=0;
    share_info.w[7]=1;
    share_info.w[8]=0;
    //fMatrix 0-inexistence;1-rou(j),j;2-i=[n]/rou[j]/j;
    share_info.fMatrix[0][0]=0;share_info.fMatrix[0][1]=0;share_info.fMatrix[0][2]=0;share_info.fMatrix[0][3]=0;share_info.fMatrix[0][4]=1;share_info.fMatrix[0][5]=1;share_info.fMatrix[0][6]=1;share_info.fMatrix[0][7]=1;share_info.fMatrix[0][8]=1;
    share_info.fMatrix[1][0]=1;share_info.fMatrix[1][1]=2;share_info.fMatrix[1][2]=1;share_info.fMatrix[1][3]=2;share_info.fMatrix[1][4]=2;share_info.fMatrix[1][5]=2;share_info.fMatrix[1][6]=2;share_info.fMatrix[1][7]=2;share_info.fMatrix[1][8]=2;
    share_info.fMatrix[2][0]=2;share_info.fMatrix[2][1]=1;share_info.fMatrix[2][2]=2;share_info.fMatrix[2][3]=2;share_info.fMatrix[2][4]=2;share_info.fMatrix[2][5]=2;share_info.fMatrix[2][6]=2;share_info.fMatrix[2][7]=2;share_info.fMatrix[2][8]=2;
    share_info.fMatrix[3][0]=2;share_info.fMatrix[3][1]=2;share_info.fMatrix[3][2]=2;share_info.fMatrix[3][3]=1;share_info.fMatrix[3][4]=2;share_info.fMatrix[3][5]=2;share_info.fMatrix[3][6]=2;share_info.fMatrix[3][7]=2;share_info.fMatrix[3][8]=2;
    return 0;
}
int LSS_NC::reconstruct(LSS_NC_SHARE_INFO &share_info, G1 &u)
{
    u=pfc->mult(share_info.u[0],share_info.w[0]);
    for(int i=1;i<LSS_NC_SHARE_NUM;i++)
    {
        G1 T=pfc->mult(share_info.u[i],share_info.w[i]);
        u=u+T;
    }

#if 0
    G1 u5=share_info.u[4]+(-share_info.u[0]);
    u=share_info.u[7]+(-u5);
#endif
    return 0;
}
int LSS_NC::share(Big &u,LSS_NC_SHARE_INFO &share_info)
{
    //u
    Big u5,u6;
    pfc->random_ord(share_info.bu[0]);//u1
    pfc->random_ord(share_info.bu[1]);//u2
    pfc->random_ord(share_info.bu[2]);//u3
    pfc->random_ord(share_info.bu[3]);//u4
    pfc->random_ord(u5);//u5
    pfc->random_ord(u6);//u6
    share_info.bu[4]=pfc->Zpadd( share_info.bu[0],u5);//u5a
    share_info.bu[5]=pfc->Zpadd(share_info.bu[1],u5);//u5b
    share_info.bu[6]=pfc->Zpadd(share_info.bu[4],u5);//u6
    share_info.bu[6]=pfc->Zpadd(u6,share_info.bu[6]);//u6
    share_info.bu[7]=pfc->Zpadd(u,u5);//u7a
    share_info.bu[8]=pfc->Zpadd(u,u6);//u7b

    //rou
    share_info.rou[0]=1;//rou1
    share_info.rou[1]=2;//rou2
    share_info.rou[2]=1;//rou3
    share_info.rou[3]=3;//rou4
    share_info.rou[4]=0;
    share_info.rou[5]=0;
    share_info.rou[6]=0;
    share_info.rou[7]=0;
    share_info.rou[8]=0;

    //omg
    share_info.w[0]=1;
    share_info.w[1]=0;
    share_info.w[2]=0;
    share_info.w[3]=0;
    share_info.w[4]=-1;
    share_info.w[5]=0;
    share_info.w[6]=0;
    share_info.w[7]=1;
    share_info.w[8]=0;
    //fMatrix 0-inexistence;1-rou(j),j;2-i=[n]/rou[j]/j;
    share_info.fMatrix[0][0]=0;share_info.fMatrix[0][1]=0;share_info.fMatrix[0][2]=0;share_info.fMatrix[0][3]=0;share_info.fMatrix[0][4]=1;share_info.fMatrix[0][5]=1;share_info.fMatrix[0][6]=1;share_info.fMatrix[0][7]=1;share_info.fMatrix[0][8]=1;
    share_info.fMatrix[1][0]=1;share_info.fMatrix[1][1]=2;share_info.fMatrix[1][2]=1;share_info.fMatrix[1][3]=2;share_info.fMatrix[1][4]=2;share_info.fMatrix[1][5]=2;share_info.fMatrix[1][6]=2;share_info.fMatrix[1][7]=2;share_info.fMatrix[1][8]=2;
    share_info.fMatrix[2][0]=2;share_info.fMatrix[2][1]=1;share_info.fMatrix[2][2]=2;share_info.fMatrix[2][3]=2;share_info.fMatrix[2][4]=2;share_info.fMatrix[2][5]=2;share_info.fMatrix[2][6]=2;share_info.fMatrix[2][7]=2;share_info.fMatrix[2][8]=2;
    share_info.fMatrix[3][0]=2;share_info.fMatrix[3][1]=2;share_info.fMatrix[3][2]=2;share_info.fMatrix[3][3]=1;share_info.fMatrix[3][4]=2;share_info.fMatrix[3][5]=2;share_info.fMatrix[3][6]=2;share_info.fMatrix[3][7]=2;share_info.fMatrix[3][8]=2;
    return 0;
}
int LSS_NC::reconstruct(LSS_NC_SHARE_INFO &share_info,Big &u)
{
#if 0
    Big B=share_info.w[0];
    u=pfc->Zpmulti(share_info.bu[0],B);
    for(int i=1;i<LSS_NC_SHARE_NUM;i++)
    {
        B=share_info.w[i];
        Big T=pfc->Zpmulti(share_info.bu[i],B);
        u=u+T;
    }
    return 0;
#else //test
    Big u5=pfc->Zpsub(share_info.bu[4],share_info.bu[0]);
    u=pfc->Zpsub(share_info.bu[7],u5);
    return 0;
#endif
}
