all:
	cp mirdef.hpp mirdef.h
	g++ -c -m64 -fPIC mrcore.c
	g++ -c -m64 -fPIC mrarth0.c
	g++ -c -m64 -fPIC mrarth1.c
	g++ -c -m64 -fPIC mrarth2.c
	g++ -c -m64 -fPIC mralloc.c
	g++ -c -m64 -fPIC mrsmall.c
	g++ -c -m64 -fPIC mrio1.c
	g++ -c -m64 -fPIC mrio2.c
	g++ -c -m64 -fPIC mrgcd.c
	g++ -c -m64 -fPIC mrjack.c
	g++ -c -m64 -fPIC mrxgcd.c
	g++ -c -m64 -fPIC mrarth3.c
	g++ -c -m64 -fPIC mrbits.c
	g++ -c -m64 -fPIC mrrand.c
	g++ -c -m64 -fPIC mrprime.c
	g++ -c -m64 -fPIC mrcrt.c
	g++ -c -m64 -fPIC mrscrt.c
	g++ -c -m64 -fPIC mrmonty.c
	g++ -c -m64 -fPIC mrpower.c
	g++ -c -m64 -fPIC mrsroot.c
	g++ -c -m64 -fPIC mrcurve.c
	g++ -c -m64 -fPIC mrfast.c
	g++ -c -m64 -fPIC mrshs.c
	g++ -c -m64 -fPIC mrshs256.c
	g++ -c -m64 -fPIC mrshs512.c
	g++ -c -m64 -fPIC mrsha3.c
	g++ -c -m64 -fPIC mrfpe.c
	g++ -c -m64 -fPIC mraes.c
	g++ -c -m64 -fPIC mrgcm.c
	g++ -c -m64 -fPIC mrlucas.c
	g++ -c -m64 -fPIC mrzzn2.c
	g++ -c -m64 -fPIC mrzzn2b.c
	g++ -c -m64 -fPIC mrzzn3.c
	g++ -c -m64 -fPIC mrzzn4.c
	g++ -c -m64 -fPIC mrecn2.c
	g++ -c -m64 -fPIC mrstrong.c
	g++ -c -m64 -fPIC mrbrick.c
	g++ -c -m64 -fPIC mrebrick.c
	g++ -c -m64 -fPIC mrec2m.c
	g++ -c -m64 -fPIC mrgf2m.c
	g++ -c -m64 -fPIC mrflash.c
	g++ -c -m64 -fPIC mrfrnd.c
	g++ -c -m64 -fPIC mrdouble.c
	g++ -c -m64 -fPIC mrround.c
	g++ -c -m64 -fPIC mrbuild.c
	g++ -c -m64 -fPIC mrflsh1.c
	g++ -c -m64 -fPIC mrpi.c
	g++ -c -m64 -fPIC mrflsh2.c
	g++ -c -m64 -fPIC mrflsh3.c
	g++ -c -m64 -fPIC mrflsh4.c
	cp mrmuldv.g64 mrmuldv.c
	g++ -c -m64 -fPIC mrmuldv.c
	g++ -c -m64 -fPIC big.cpp
	g++ -c -m64 -fPIC zzn.cpp
	g++ -c -m64 -fPIC ecn.cpp
	g++ -c -m64 -fPIC ec2.cpp
	g++ -c -m64 -fPIC flash.cpp
	g++ -c -m64 -fPIC crt.cpp
	g++ -c -m64 -fPIC zzn2.cpp
	g++ -c -m64 -fPIC zzn4.cpp
	g++ -c -m64 -fPIC zzn12a.cpp
	g++ -c -m64 -fPIC ecn2.cpp
	#g++ -o libmiracl.so -fPIC -shared *.o -O2
	ar rc miracl.a mrcore.o mrarth0.o mrarth1.o mrarth2.o mralloc.o mrsmall.o mrzzn2.o mrzzn3.o
	ar r miracl.a mrio1.o mrio2.o mrjack.o mrgcd.o mrxgcd.o mrarth3.o mrbits.o mrecn2.o mrzzn4.o
	ar r miracl.a mrrand.o mrprime.o mrcrt.o mrscrt.o mrmonty.o mrcurve.o mrsroot.o mrzzn2b.o
	ar r miracl.a mrpower.o mrfast.o mrshs.o mrshs256.o mraes.o mrlucas.o mrstrong.o mrgcm.o    
	ar r miracl.a mrflash.o mrfrnd.o mrdouble.o mrround.o mrbuild.o
	ar r miracl.a mrflsh1.o mrpi.o mrflsh2.o mrflsh3.o mrflsh4.o 
	ar r miracl.a mrbrick.o mrebrick.o mrec2m.o mrgf2m.o mrmuldv.o mrshs512.o  mrsha3.o mrfpe.o
	ar r miracl.a big.o zzn.o ecn.o ec2.o flash.o crt.o zzn2.o zzn4.o zzn12a.o ecn2.o
	rm -f *.o	
	cp miracl.a ../
	rm -f *.a	

 
