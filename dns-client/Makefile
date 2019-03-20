CC = gcc
CCFLAGS = -Wall -g
CLT = dnsclient

build: $(CLT)

$(CLT):	$(CLT).c
	$(CC) $(CCFLAGS) $(CLT).c -o $(CLT)
run :
	./$(CLT) www.google.com A
clean:
	rm -f *.o *~
	rm -f $(CLT)