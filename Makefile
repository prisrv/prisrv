export LD_LIBRARY_PATH=./
CXX = g++
CC= gcc

.PHONY: algorithm 

algorithm:	
	make -C Algorithm
clean:	
	cd Algorithm/ && make clean && cd ../ 	
test:
	cd Algorithm/ && make test && cd ../
