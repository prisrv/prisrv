#ifndef BN_SET_H
#define BN_SET_H
#include "pairing_3.h"
#include "bn_transfer.h"

class bn_set
{
public:
    bn_set();
    void bn_printfBig(Big_C *b);
    void bn_printfG1(G1_C *g1);
    void bn_printfG2(G2_C *g2);
    void bn_printfGT(GT_C *gt);
};

#endif // BN_SET_H
