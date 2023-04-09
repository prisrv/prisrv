#include "bn_transfer.h"
#include <stdlib.h>
BN_transfer::BN_transfer()
{

}
BN_transfer::~BN_transfer()
{

}
int BN_transfer::Trf_Big_to_Char(Big &b, Big_C &bc)
{

    int ret=0;
    bc.len=b.fn->len;
    //big_to_bytes(64,b.fn,(char *)bc.w,FALSE);
    memcpy(bc.w,b.fn->w,sizeof(unsigned long)*bc.len);
    return ret;
}
int BN_transfer::Trf_Char_to_Big(Big_C &bc, Big &b)
{

    int ret=0;
    b.fn->len=bc.len;
    //bytes_to_big(64,(char *)bc.w,b.fn);
    memcpy(b.fn->w,bc.w,sizeof(unsigned long)*bc.len);
    return ret;
}
int BN_transfer::Trf_G1_to_Char(G1 &g1, G1_C &g1c)
{
    int ret=0;
    Big x,y,z;
    g1.g.getxyz(x,y,z);
    Trf_Big_to_Char(x, g1c.X);
    Trf_Big_to_Char(y, g1c.Y);
    Trf_Big_to_Char(z, g1c.Z);
#if 0
    g1c.X.len=x.fn->len;
    memcpy(g1c.X.w,x.fn->w,sizeof(unsigned long)*g1c.X.len);
    g1c.Y.len=y.fn->len;
    memcpy(g1c.Y.w,y.fn->w,sizeof(unsigned long)*g1c.Y.len);
    g1c.Z.len=z.fn->len;
    memcpy(g1c.Z.w,z.fn->w,sizeof(unsigned long)*g1c.Z.len);
#endif
    return ret;
}
int BN_transfer::Trf_Char_to_G1(G1_C &g1c,G1 &g1)
{
    if(g1c.Z.len==0) return 0;//test
    int ret=0;    
    Big x,y,z;
    Trf_Char_to_Big(g1c.X,x);
    Trf_Char_to_Big(g1c.Y,y);
    Trf_Char_to_Big(g1c.Z,z);
#if 0
    x.fn->len=g1c.X.len;
    memcpy(x.fn->w,g1c.X.w,sizeof(unsigned long)*x.fn->len);
    y.fn->len=g1c.Y.len;
    memcpy(y.fn->w,g1c.Y.w,sizeof(unsigned long)*y.fn->len);
    z.fn->len=g1c.Z.len;
    memcpy(z.fn->w,g1c.Z.w,sizeof(unsigned long)*z.fn->len);
#endif
    g1.g.set(x,y);
    g1.g.setz(z);
    return ret;
}
int BN_transfer::Trf_G2_to_Char(G2 &g2, G2_C &g2c)
{
    int ret=0;
    ZZn2 x,y,z;
    g2.g.get(x,y,z);
    Big a,b;
    x.get(a,b);
    Trf_Big_to_Char(a, g2c.Xa);
    Trf_Big_to_Char(b, g2c.Xb);

    y.get(a,b);
    Trf_Big_to_Char(a, g2c.Ya);
    Trf_Big_to_Char(b, g2c.Yb);

    z.get(a,b);
    Trf_Big_to_Char(a, g2c.Za);
    Trf_Big_to_Char(b, g2c.Zb);

    return ret;
}
int BN_transfer::Trf_Char_to_G2(G2_C &g2c,G2 &g2)
{
    int ret=0;
    ZZn2 x,y,z;
    Big a,b;

    Trf_Char_to_Big(g2c.Xa, a);
    Trf_Char_to_Big(g2c.Xb, b);

    x.set(a,b);

    Trf_Char_to_Big(g2c.Ya, a);
    Trf_Char_to_Big(g2c.Yb, b);
    y.set(a,b);

    Trf_Char_to_Big(g2c.Za, a);
    Trf_Char_to_Big(g2c.Zb, b);
    z.set(a,b);

    g2.g.set(x,y,z);

    return ret;
}
int BN_transfer::Trf_GT_to_Char(GT &gt, GT_C &gtc)
{
    int ret=0;
    ZZn4 A,B,C;
    gt.g.get(A,B,C);
    ZZn2 a,b;
    Big s,t;

    A.get(a,b);
    a.get(s,t);
    Trf_Big_to_Char(s, gtc.Aaa);
    Trf_Big_to_Char(t, gtc.Aab);
    b.get(s,t);
    Trf_Big_to_Char(s, gtc.Aba);
    Trf_Big_to_Char(t, gtc.Abb);
   // gtc.Aunitary=A.is_unitary();


    B.get(a,b);
    a.get(s,t);
    Trf_Big_to_Char(s, gtc.Baa);
    Trf_Big_to_Char(t, gtc.Bab);
    b.get(s,t);
    Trf_Big_to_Char(s, gtc.Bba);
    Trf_Big_to_Char(t, gtc.Bbb);
   // gtc.Bunitary=B.is_unitary();


    C.get(a,b);
    a.get(s,t);
    Trf_Big_to_Char(s, gtc.Caa);
    Trf_Big_to_Char(t, gtc.Cab);
    b.get(s,t);
    Trf_Big_to_Char(s, gtc.Cba);
    Trf_Big_to_Char(t, gtc.Cbb);
    //gtc.Cunitary=C.is_unitary();


    return ret;
}
int BN_transfer::Trf_Char_to_GT(GT_C &gtc,GT &gt)
{
    int ret=0;

    ZZn4 A,B,C;

    ZZn2 a,b;
    Big s,t;

    Trf_Char_to_Big(gtc.Aaa, s);
    Trf_Char_to_Big(gtc.Aab, t);
    a.set(s,t);
    Trf_Char_to_Big(gtc.Aba, s);
    Trf_Char_to_Big(gtc.Abb, t);
    b.set(s,t);
    A.set(a,b);

    Trf_Char_to_Big(gtc.Baa, s);
    Trf_Char_to_Big(gtc.Bab, t);
    a.set(s,t);
    Trf_Char_to_Big(gtc.Bba, s);
    Trf_Char_to_Big(gtc.Bbb, t);
    b.set(s,t);
    B.set(a,b);

    Trf_Char_to_Big(gtc.Caa, s);
    Trf_Char_to_Big(gtc.Cab, t);
    a.set(s,t);
    Trf_Char_to_Big(gtc.Cba, s);
    Trf_Char_to_Big(gtc.Cbb, t);
    b.set(s,t);
    C.set(a,b);

    gt.g.set(A,B,C);
    return ret;
}

void BN_transfer::bn_printfBig(char *name, Big_C &b)
{
    cout<<name<<endl;
    //printf("%s\n",name);
    cout<<hex<<"0x"<<b.len<<";"<<endl;
    //printf("0x%08x,\n",b.len);
    for(unsigned int i=0;i<b.len;i++)
    {
        cout<<hex<<"0x"<<b.w[i]<<";"<<endl;
        //printf("0x%x,\n",b.w[i]);
    }

}
void BN_transfer::bn_printfG1(char *name, G1_C &g1)
{
    cout<<name<<endl;
    bn_printfBig("X",g1.X);
    bn_printfBig("Y",g1.Y);
    bn_printfBig("Z",g1.Z);


}
void BN_transfer::bn_printfG2(char *name, G2_C &g2)
{
    cout<<name<<endl;
    bn_printfBig("Xa",g2.Xa);
    bn_printfBig("Xb",g2.Xb);
    bn_printfBig("Ya",g2.Ya);
    bn_printfBig("Yb",g2.Yb);
    bn_printfBig("Za",g2.Za);
    bn_printfBig("Zb",g2.Zb);

}
void BN_transfer::bn_printfGT(char *name, GT_C &gt)
{
    cout<<name<<endl;
    bn_printfBig("Aaa",gt.Aaa);
    bn_printfBig("Aab",gt.Aab);
    bn_printfBig("Aba",gt.Aba);
    bn_printfBig("Abb",gt.Abb);

    bn_printfBig("Baa",gt.Baa);
    bn_printfBig("Bab",gt.Bab);
    bn_printfBig("Bba",gt.Bba);
    bn_printfBig("Bbb",gt.Bbb);

    bn_printfBig("Caa",gt.Caa);
    bn_printfBig("Cab",gt.Cab);
    bn_printfBig("Cba",gt.Cba);
    bn_printfBig("Cbb",gt.Cbb);


}
