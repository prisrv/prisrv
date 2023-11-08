export LD_LIBRARY_PATH=./
CXX = g++
CC= gcc
all:
	make -C MIRACL
	${CXX} -o test_aes_ctr test_aes_ctr.cpp aes_ctr.cpp bn_transfer.cpp bn_pair.cpp WjCryptLib_Aes.c WjCryptLib_AesCtr.c miracl.a -fpermissive -w -O2
	${CXX} -o test_fac test_fac.cpp fac.cpp bn_pair.cpp   miracl.a -O2 
	${CXX} -o test_lss_nc test_lss_nc.cpp lss_nc.cpp bn_pair.cpp   miracl.a -O2 
	${CXX} -o test_cp_abe test_cp_abe.cpp cp_abe.cpp lss_nc.cpp bn_pair.cpp   miracl.a -O2 
	${CXX} -o test_mac_ddh test_mac_ddh.cpp macddh.cpp bn_pair.cpp   miracl.a -O2 
	${CXX} -o test_acme test_acme.cpp acme.cpp fac.cpp lss_nc.cpp cp_abe.cpp bn_pair.cpp   aes_ctr.cpp bn_transfer.cpp WjCryptLib_Aes.c WjCryptLib_AesCtr.c miracl.a -fpermissive -O2 -w
	${CXX} -o test_prisrv test_prisrv.cpp prisrv.cpp macddh.cpp acme.cpp fac.cpp lss_nc.cpp cp_abe.cpp bn_pair.cpp   bn_transfer.cpp  aes_ctr.cpp WjCryptLib_Aes.c WjCryptLib_AesCtr.c miracl.a -fpermissive -O2 -w
clean:
	rm -f *.a *.so 
	rm -f test_aes_ctr
	rm -f test_fac
	rm -f test_lss_nc
	rm -f test_cp_abe
	rm -f test_mac_ddh
	rm -f test_acme
	rm -f test_acme
	rm -f test_prisrv
test:
	./test_aes_ctr
	./test_fac
	./test_lss_nc
	./test_cp_abe
	./test_mac_ddh
	./test_acme
	./test_prisrv


