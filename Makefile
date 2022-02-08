CC=gcc

all: trace

trace: trace.o
	$(CC) -std=c99 -pedantic -o trace trace.c
