all:
	x86_64-w64-mingw32-gcc -c EnableWebDAVClient.c -masm=intel -Wall -DBOF -o EnableWebDAVClient.o
	x86_64-w64-mingw32-strip --strip-unneeded EnableWebDAVClient.o
clean:
	rm EnableWebDAVClient.o