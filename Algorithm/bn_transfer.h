#ifndef BN_TRANSFER_H
#define BN_TRANSFER_H
#include "bn_struct.h"
#include "pairing_3.h"



class BN_transfer
{
public:
    BN_transfer();
    ~BN_transfer();
    int Trf_Big_to_Char(Big &b, Big_C &bc);
    int Trf_Char_to_Big(Big_C &bc, Big &b);
    int Trf_G1_to_Char(G1 &g1, G1_C &g1c);
    int Trf_Char_to_G1(G1_C &g1c,G1 &g1);
    int Trf_G2_to_Char(G2 &g2, G2_C &g2c);
    int Trf_Char_to_G2(G2_C &g2c,G2 &g2);
    int Trf_GT_to_Char(GT &gt, GT_C &gtc);
    int Trf_Char_to_GT(GT_C &gtc,GT &gt);
    void bn_printfBig(char *name,Big_C &b);
    void bn_printfG1(char *name,G1_C &g1);
    void bn_printfG2(char *name,G2_C &g2);
    void bn_printfGT(char *name,GT_C &gt);
};

#endif // BN_TRANSFER_H
