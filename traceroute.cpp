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
   struct addrinfo* info;
} host_t;

void trace(host_t host) {
   int host_socket = socket(host.info->ai_family, SOCK_DGRAM, 0);
   if (host_socket == -1) {
      perror("Unable to connect!");
      exit(1);
   }
   
   sockaddr_in6 address = {0};
   memcpy(&address, host.info->ai_addr, host.info->ai_addrlen);
   
   int optval = 1;
   if (host.info->ai_family == AF_INET)
      if (setsockopt(host_socket, SOL_IP, IP_RECVERR, &optval, sizeof(optval)) != 0) {
        perror("set err1");
        exit(1);    
      }
   else if (host.info->ai_family == AF_INET6) {
      if (setsockopt(host_socket, IPPROTO_IPV6, IPV6_RECVERR, &optval, sizeof(optval)) != 0) {
        perror("set err1");
        exit(1);    
      }
   }
   unsigned ttl = 0, port = 33434;
   
   do {
      ttl++;
      if (port == 33534) port = 33434;
      if (host.info->ai_family == AF_INET) {
         setsockopt(host_socket, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
         ((sockaddr_in*)&address)->sin_port = htons(port++);
      }
      else if (host.info->ai_family == AF_INET6) {
         setsockopt(host_socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl));
         ((sockaddr_in6*)&address)->sin6_port = htons(port++);
      }

      if (sendto(host_socket, NULL, 0, 0, (sockaddr*)&address, sizeof(address)) < 0) {
         perror("Unable to send!");
         exit(1);
      }

      struct timespec time_sended;
      timespec_get(&time_sended, TIME_UTC);

      fd_set rfds;
      FD_ZERO(&rfds);
      FD_SET(host_socket, &rfds);

      struct timeval timeout = {0};
      timeout.tv_sec = 2;
      while (true) {
         int ready = select(sizeof(rfds), &rfds, NULL, NULL, &timeout);
         if (ready == -1) {
            perror("Select error!");
            exit(1);
         } else if (ready > 0) {
            struct msghdr message;
            if (recvmsg(host_socket, &message, MSG_ERRQUEUE) < 0) {
               perror("Recieve error!");
               exit(1);
            }
            
            struct timespec time_received;
            timespec_get(&time_received, TIME_UTC);
            unsigned ping_ms = (time_received.tv_sec - time_sended.tv_sec) * 1000 + 
                             (time_received.tv_nsec - time_sended.tv_nsec) / 1000000;
         } else {
            break;
         }

         //TODO
      }
      break;
   } while (true);
   
}

int main () {
   struct addrinfo input = {0};
   input.ai_family = AF_UNSPEC;
   input.ai_socktype = SOCK_DGRAM;    
   
   host_t host;
   host.address = "8.8.8.8";

   if (getaddrinfo(host.address.c_str(), "0", &input, &host.info) != 0) {
      perror("Invalid host!");
      exit(-1);
   }

   trace(host);
}
