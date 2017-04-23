CC=g++

traceroute: trace.cpp
	$(CC) -std=c++11 -o trace trace.cpp
