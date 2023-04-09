#ifndef MACDDH_H
#define MACDDH_H
#include "pairing_3.h"

#define MACddh_PARA_N 7

struct MACddh_SK
{
    Big x[MACddh_PARA_N+1];
    Big y[MACddh_PARA_N+1];
    Big z;
};
struct MACddh_PK
{
    G1 Cx0,Cy0,Cz;
    G1 X[MACddh_PARA_N+1],Y[MACddh_PARA_N+1];

};
struct MACddh_M
{
    int N;
    Big m[MACddh_PARA_N];
};
struct MACddh_MAC
{
    G1 sig_x,sig_y,sig_z,sig_w;
};
class MACddh
{
private:
    PFC *pfc;
#if 0
    G1 g,h;
#endif

public:
    MACddh(PFC *p);
    ~MACddh();
    int KeyGen(MACddh_SK &sk,MACddh_PK &pk);
    int MAC(MACddh_SK &sk,MACddh_M &M,MACddh_MAC &mac);
    int Verify(MACddh_SK &sk,MACddh_M &M,MACddh_MAC &mac);
};

#endif // MACDDH_H
