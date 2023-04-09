#ifndef LSS_NC_H
#define LSS_NC_H
#include "pairing_3.h"
#define LSS_NC_PARA_N 3//= CP_ABE_PARA_N
#define LSS_NC_SHARE_NUM 9
struct LSS_NC_SHARE_INFO
{
    Big bu[LSS_NC_SHARE_NUM];
    G1 u[LSS_NC_SHARE_NUM];
    int rou[LSS_NC_SHARE_NUM];
    int w[LSS_NC_SHARE_NUM];
    int fMatrix[LSS_NC_PARA_N+1][LSS_NC_SHARE_NUM];//
};
class LSS_NC
{
private:
    PFC *pfc;
public:
    LSS_NC(PFC *p);//(x1Vx2)V(x1^x3)=x5Vx6=x7
    ~LSS_NC();
    int share(G1 &u,LSS_NC_SHARE_INFO &share_info);
    int reconstruct(LSS_NC_SHARE_INFO &share_info,G1 &u);
    int share(Big &u,LSS_NC_SHARE_INFO &share_info);
    int reconstruct(LSS_NC_SHARE_INFO &share_info,Big &u);
};

#endif // LSS_NC_H
