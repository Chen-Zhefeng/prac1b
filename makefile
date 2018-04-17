CC:=g++ -std=c++0x -g
exe:=main
obj:=main.o Cipher.o transcode.o
link:= -lssl -lcrypto

all:$(obj)
	$(CC) -o $(exe) $^ $(link) 

%.o:%.cpp
	$(CC) -c $^ -o $@

.PHONY:clean 
clean:
	rm -f *.o *.out

rebuild:clean all
