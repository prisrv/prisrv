#include "fac.h"

FAC::FAC(PFC *p)
{
    pfc=p;
#if 0
    pfc->random(g);
    pfc->random(h);
#endif

}
FAC::~FAC()
{

}
#if 0
int FAC::SetUp(FAC_PP &pp)
{
    pfc->random(pp.g);
    pfc->random(pp.h);
    return 0;
}
#endif
int FAC::CredKeyGen(FAC_CRED_KEY &cred_key)
{
    pfc->random(cred_key.sk.x);
    cred_key.pk.W=pfc->mult(*pfc->gg,cred_key.sk.x);
    for(int i=0;i<FAC_PARA_N+2;i++)
    {
        pfc->random(cred_key.sk.y[i]);
        cred_key.pk.X[i]=pfc->mult(*pfc->hh,cred_key.sk.y[i]);
        cred_key.pk.Y[i]=pfc->mult(*pfc->gg,cred_key.sk.y[i]);
    }
    for(int i=0;i<FAC_PARA_N+2;i++)
    {
        G1 T=pfc->mult(*pfc->gg,cred_key.sk.y[i]);
        for(int j=0;j<FAC_PARA_N+2;j++)
        {
            if(i==j)
                cred_key.pk.Z[i][j]=*pfc->gg;
            else
            {
                cred_key.pk.Z[i][j]=pfc->mult(T,cred_key.sk.y[j]);
            }
        }
    }
    return 0;
}
int FAC::UserKeyGen(FAC_USER_KEY &user_key)
{
    //generate key
    pfc->random(user_key.usk.usk);
    user_key.upk.upk1=pfc->mult(*pfc->hh,user_key.usk.usk);
    user_key.upk.upk2=pfc->mult(*pfc->gg,user_key.usk.usk);
#if 0
    cout<<"fac usk"<<endl;
    cout<<user_key.usk.usk<<endl;
    cout<<"fac user_key.upk.upk1"<<endl;
    cout<<user_key.upk.upk1.g<<endl;
    cout<<"fac user_key.upk.upk2"<<endl;
    cout<<user_key.upk.upk2.g<<endl;

#endif
    return 0;
}
int FAC::IssueUser_Send(FAC_USER_KEY &user_key,USER_ATTR &attr,Big &uid,FAC_SPK1 &spk1)
{
    //generate uid and attri
    pfc->random(uid);
    for(int i=1;i<FAC_PARA_N+1;i++)
        pfc->random(attr.x[i]);

    attr.x[0]=user_key.usk.usk;
    attr.x[FAC_PARA_N+1]=uid;//uid;
    //compute pok1
    Big usk_;
    pfc->random(usk_);
    spk1.gam1=pfc->mult(*pfc->hh,usk_);
    spk1.gam2=pfc->mult(*pfc->gg,usk_);
    pfc->start_hash();
    pfc->add_to_hash(user_key.upk.upk1);
    pfc->add_to_hash(user_key.upk.upk2);
    pfc->add_to_hash(spk1.gam1);
    pfc->add_to_hash(spk1.gam2);
    spk1.c=pfc->finish_hash_to_group();
    Big t=pfc->Zpmulti(spk1.c,user_key.usk.usk);
    spk1.s=pfc->Zpsub(usk_,t);
    return 0;
}
int FAC::IssueIssuer(FAC_CRED_KEY &cred_key, USER_ATTR &attr, Big &uid, FAC_SPK1 &spk1, FAC_USER_PK &upk, FAC_CRED_U &cred_u)
{
    //verify pok1
    pfc->start_hash();
    pfc->add_to_hash(upk.upk1);
    pfc->add_to_hash(upk.upk2);
    pfc->add_to_hash(spk1.gam1);
    pfc->add_to_hash(spk1.gam2);
    Big c=pfc->finish_hash_to_group();
    if(c != spk1.c) return -1;

    //ps sign
    Big r;
    pfc->random(r);
    cred_u.sigma1=pfc->mult(*pfc->hh,r);
    Big a=pfc->Zpmulti(r,cred_key.sk.y[0]);
    G2 A=pfc->mult(upk.upk1,a);
    Big sum=cred_key.sk.x;
    for(int i=1;i<FAC_PARA_N+1;i++)
    {
        a=pfc->Zpmulti(attr.x[i],cred_key.sk.y[i]);
        sum=pfc->Zpadd(a,sum);
    }
    a=pfc->Zpmulti(uid,cred_key.sk.y[FAC_PARA_N+1]);
    sum=pfc->Zpadd(a,sum);
    sum=pfc->Zpmulti(r,sum);
    cred_u.sigma2=pfc->mult(*pfc->hh,sum);
    cred_u.sigma2=cred_u.sigma2+A;

    //add st
    FAC_ST_UNIT stu;
    stu.uid=uid;
    for(int i=1;i<FAC_PARA_N+1;i++)
        stu.attr.x[i]=attr.x[i];
    stu.upk.upk1=upk.upk1;
    stu.upk.upk2=upk.upk2;
    stu.cred_u.sigma1=cred_u.sigma1;
    stu.cred_u.sigma2=cred_u.sigma2;
    cred_key.st.push_front(stu);
    //printf("st.size=%ld\n",cred_key.st.size());
    return 0;
}
int FAC::IssueUser_Verify(FAC_CRED_KEY_PK &pk,FAC_CRED_U &cred_u,USER_ATTR &attr,Big &uid,FAC_USER_KEY &user_key)
{
    GT E1,E2;
    G1 A1,SUM=pk.W;
    E1=pfc->pairing(cred_u.sigma2,*pfc->gg);
    A1=pfc->mult(pk.Y[0],user_key.usk.usk);
    SUM=SUM+A1;
    A1=pfc->mult(pk.Y[FAC_PARA_N+1],uid);
    SUM=SUM+A1;
    for(int i=1;i<FAC_PARA_N+1;i++)
    {
        A1=pfc->mult(pk.Y[i],attr.x[i]);
        SUM=SUM+A1;
    }
    E2=pfc->pairing(cred_u.sigma1,SUM);
    if(E1 != E2) return -1;
    return 0;
}
int FAC::Show(FAC_CRED_KEY_PK &pk,FAC_CRED_U &cred_u,USER_ATTR &attr,FAC_USER_DISCLOSE_ATTR &disclose,Big &uid,FAC_USER_KEY &user_key,FAC_TOK &tok,Big &m)
{
    Big t1,t2;
    G1 A1,A2,SUM;

    attr.x[0]=user_key.usk.usk;
    attr.x[FAC_PARA_N+1]=uid;
    for(int i=0;i<FAC_PARA_D;i++)
        disclose.x[i]=attr.x[i+1];

    //compute T1
    pfc->random(t1);
    SUM=pfc->mult(*pfc->gg,t1);
    for(int i=FAC_PARA_D+1;i<FAC_PARA_N+1;i++)
    {
        A1=pfc->mult(pk.Y[i],attr.x[i]);
        SUM=SUM+A1;
    }
    tok.T1=SUM;

    //compute T2
    SUM=pk.Y[FAC_PARA_N+1];
    for(int i=0;i<FAC_PARA_D+1;i++)
        SUM=SUM+pk.Y[i];
    SUM=pfc->mult(SUM,t1);
#if 0
    for(int j=FAC_PARA_N-FAC_PARA_D+2;j<FAC_PARA_N+1;j++)
    {
        A1=pfc->mult(pk.Z[FAC_PARA_D+1][j],attr.x[j]);
        SUM=SUM+A1;
    }
#endif

    for(int j=FAC_PARA_D+1;j<FAC_PARA_N+1;j++)
    {
        A1=pk.Z[0][j]+pk.Z[FAC_PARA_N+1][j];
        for(int i=0;i<FAC_PARA_D;i++)
        {
            A1=A1+pk.Z[i+1][j];

        }
        A1=pfc->mult(A1,attr.x[j]);
        SUM=SUM+A1;
    }
    tok.T2=SUM;

    //compute sigma
    pfc->random(t2);
    tok.sigma1=pfc->mult(cred_u.sigma1,t2);
    G2 B1=pfc->mult(cred_u.sigma2,t2);
    G2 B2=pfc->mult(tok.sigma1,t1);
    tok.sigma2=B1+B2;

    //compute spk2
    Big rk,rd;

    pfc->random(rk);
    pfc->random(rd);
#if 0//test
    cout<<"rk"<<endl;
    cout<<rk<<endl;
    cout<<"rd"<<endl;
    cout<<rd<<endl;
#endif

    A1=pfc->mult(pk.Y[0],rk);
    A2=pfc->mult(pk.Y[FAC_PARA_N+1],rd);
    SUM=A1+A2;
    tok.spk2.gama=pfc->pairing(tok.sigma1,SUM);
    pfc->start_hash();
    pfc->add_to_hash(m);
    for(int i=0;i<FAC_PARA_D;i++)
        pfc->add_to_hash(disclose.x[i]);
    pfc->add_to_hash(tok.spk2.gama);
    pfc->add_to_hash(tok.T1);
    pfc->add_to_hash(tok.T2);
    pfc->add_to_hash(tok.sigma1);
    pfc->add_to_hash(tok.sigma2);
    tok.spk2.c=pfc->finish_hash_to_group();
    Big t=pfc->Zpmulti(tok.spk2.c,uid);
    tok.spk2.sd=pfc->Zpsub(rd,t);
    t=pfc->Zpmulti(tok.spk2.c,user_key.usk.usk);
    tok.spk2.sk=pfc->Zpsub(rk,t);
#if 0//test
    cout<<"usk"<<endl;
    cout<<user_key.usk.usk<<endl;
    cout<<"rk"<<endl;
    cout<<rk<<endl;
    cout<<"t"<<endl;
    cout<<t<<endl;
    cout<<"tok.spk2.sk"<<endl;
    cout<<tok.spk2.sk<<endl;
#endif
    return 0;
}
int FAC::Verify(FAC_CRED_KEY_PK &pk,FAC_TOK &tok,Big &m,FAC_USER_DISCLOSE_ATTR &disclose)
{
#if 0 //test
    cout<<"~~~~~~~~~~~~~~~~~`m~~~~~~~~~~~~~~~~~~"<<endl;
    cout<<m<<endl;

    cout<<"\\---------- tok_c -------------\\"<<endl;
    cout<<"T1"<<endl;
    cout<<tok.T1.g<<endl;
    cout<<"T2"<<endl;
    cout<<tok.T2.g<<endl;
    cout<<"sigma1"<<endl;
    cout<<tok.sigma1.g<<endl;
    cout<<"sigma2"<<endl;
    cout<<tok.sigma2.g<<endl;

    cout<<"\\--------- disclose attributes ---------\\"<<endl;
    for(int i=0;i<FAC_PARA_D;i++)
    {
        cout<<disclose.x[i]<<endl;
    }

#endif
    //compute and compare c
    pfc->start_hash();
    pfc->add_to_hash(m);
    for(int i=0;i<FAC_PARA_D;i++)
        pfc->add_to_hash(disclose.x[i]);
    pfc->add_to_hash(tok.spk2.gama);
    pfc->add_to_hash(tok.T1);
    pfc->add_to_hash(tok.T2);
    pfc->add_to_hash(tok.sigma1);
    pfc->add_to_hash(tok.sigma2);
    Big c=pfc->finish_hash_to_group();
    if(c!=tok.spk2.c) return -1;


    GT E1,E2;
    //
    G2 X=pk.X[0]+pk.X[FAC_PARA_N+1];
    for(int i=0;i<FAC_PARA_D;i++)
        X=X+pk.X[i+1];
    E1=pfc->pairing(X,tok.T1);
    E2=pfc->pairing(*pfc->hh,tok.T2);
    if(E1 !=E2) return -2;
    //

    G1 A1,A2,SUM;
    A1=pfc->mult(pk.Y[0],tok.spk2.sk);
    A2=pfc->mult(pk.Y[FAC_PARA_N+1],tok.spk2.sd);
    SUM=A1+A2;
    E1=pfc->pairing(tok.sigma1,SUM);

    E2=pfc->pairing(tok.sigma2,*pfc->gg);
    E2=pfc->power(E2,c);

    E1=E1*E2;

#if 0//test
    cout<<"Y0"<<endl;
    cout<<pk.Y[0].g<<endl;
    cout<<"tok.spk2.sk"<<endl;
    cout<<tok.spk2.sk<<endl;
    cout<<"A1"<<endl;
    cout<<A1.g<<endl;

    cout<<"E1"<<endl;
    cout<<E1.g<<endl;


#endif


    //
    SUM=pk.W+tok.T1;
    for(int i=0;i<FAC_PARA_D;i++)
    {
        A1=pfc->mult(pk.Y[i+1],disclose.x[i]);
        SUM=SUM+A1;
    }
    E2=pfc->pairing(tok.sigma1,SUM);
    E2=pfc->power(E2,c);
    E2=E2*tok.spk2.gama;


    if(E1 != E2) return -3;

    return 0;
}
//Trace
int FAC::Trace(FAC_CRED_KEY &cred_key, FAC_TOK &tok, Big &uid)
{
    G1 A1=pfc->mult(cred_key.pk.Y[0],tok.spk2.sk);
    Big x=pfc->Zpmulti(tok.spk2.c,cred_key.sk.y[0]);
    G1 A2=pfc->mult(cred_key.pk.Y[FAC_PARA_N+1],tok.spk2.sd);
    A1=A1+A2;
    list <FAC_ST_UNIT>::iterator it;

    for(it = cred_key.st.begin();it!=cred_key.st.end();it++)
    {
        A2=pfc->mult(it->upk.upk2,x);
        G1 SUM=A1+A2;
        Big y=pfc->Zpmulti(tok.spk2.c,it->uid);
        A2=pfc->mult(cred_key.pk.Y[FAC_PARA_N+1],y);
        SUM=SUM+A2;
        GT E=pfc->pairing(tok.sigma1,SUM);
        if(E!=tok.spk2.gama)
            continue;
        else
        {
            uid=it->uid;
            return 0;
        }
    }
    return 1;
}
