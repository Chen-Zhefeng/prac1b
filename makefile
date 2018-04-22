CC:=g++ -std=c++11 -g
exe:=main
obj:=main.o Cipher.o
link:= -lssl -lcrypto

all:$(obj)
	$(CC) -o $(exe) $^ $(link) 

%.o:%.cpp
	$(CC) -c $^ -o $@

.PHONY:clean 
clean:
	rm -f *.o *.out

rebuild:clean all
