#include <iostream>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <linux/errqueue.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <unistd.h>
#include <string.h>
#include <string>
#include <getopt.h>
#include <iomanip>
#include <stdio.h>

using namespace std;

typedef struct{
   string address;
   string port;
   struct addrinfo* info;
} host_t;

void trace(host_t host) {
   int host_socket = socket(host.info->ai_family, host.info->ai_socktype, 0);
   if (host_socket == -1) {
      perror("Unable to connect!");
      exit(1);
   }
   
   int optval = 1;
   if (host.info->ai_family == AF_INET)
      setsockopt(host_socket, SOL_IP, IP_RECVERR, &optval, sizeof(optval));
   else if (host.info->ai_family == AF_INET6)
      setsockopt(host_socket, SOL_IPV6, IPV6_RECVERR, &optval, sizeof(optval));
	
	unsigned ttl = 0;
	unsigned port = 33434;

   sockaddr_in address = {0};
   memcpy(&address, host.info->ai_addr, host.info->ai_addrlen);
	
   do {
		ttl++;
		if (host.info->ai_family == AF_INET)
      	setsockopt(host_socket, IPPROTO_IP, IP_TTL, &ttl, sizeof(unsigned));
   	else if (host.info->ai_family == AF_INET6)
      	setsockopt(host_socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(unsigned));
		
		if (port == 33534) 
			port = 33434;

		address.sin_port = htons(port++);

		if (sendto(host_socket, NULL, 0, 0, (sockaddr*)&address, sizeof(address)) < 0) {
			perror("Unable to send!");
      	exit(1);
		}
		
	} while (true);
   
}

int main () {
   host_t host;
   struct addrinfo input = {0};
   input.ai_family = AF_UNSPEC;
   input.ai_socktype = SOCK_DGRAM;
   
   if (!getaddrinfo(host.address.c_str(), host.port.c_str(), &input, &host.info)) {
      perror("Invalid host!");
      exit(-1);
   }

   trace(host);
}
