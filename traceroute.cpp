#include <netinet/ip_icmp.h>
#include <linux/errqueue.h>
#include <iostream>
#include <string.h>
#include <getopt.h>
#include <netdb.h>
#include <poll.h>
//#include <sys/socket.h>
//#include <sys/types.h>
//#include <sys/time.h>
//#include <arpa/inet.h>
//#include <stdlib.h>
//#include <netinet/in.h>
//#include <netinet/ip.h>
//#include <netinet/ip6.h>
//#include <netinet/icmp6.h>
//#include <unistd.h>
//#include <string>
//#include <iomanip>
//#include <stdio.h>

#define TIMEOUT 2000
using namespace std;

void decodeICMP(struct msghdr* message) {
   struct sock_extended_err* sock_err;

   for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(message); cmsg; cmsg = CMSG_NXTHDR(message, cmsg)) 
      if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_RECVERR && (struct sock_extended_err*)CMSG_DATA(cmsg)) {
         if (sock_err->ee_origin == SO_EE_ORIGIN_ICMP) 
            switch (sock_err->ee_type) {
               case ICMP_NET_UNREACH: break;
               case ICMP_HOST_UNREACH: break;
            }
      } else if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_RECVERR && (struct sock_extended_err*)CMSG_DATA(cmsg)) {
         if (sock_err->ee_origin == SO_EE_ORIGIN_ICMP) 
            switch (sock_err->ee_type) {
               case ICMP_NET_UNREACH: break;
               case ICMP_HOST_UNREACH: break;
            }
      }
}

void exitError(string message, int code = 1) {
   cerr << message << endl;
   exit(code);
}

void trace(struct addrinfo* info) {
   int host_socket = socket(info->ai_family, SOCK_DGRAM, 0);
   if (host_socket == -1)
      exitError("Unable to connect!");

   sockaddr_in6 address = {0};
   memcpy(&address, info->ai_addr, info->ai_addrlen);
   
   int optval = 1;
   bool error = false;
   switch (info->ai_family) {
      case AF_INET:
         error |= setsockopt(host_socket, SOL_IP, IP_RECVERR, &optval, sizeof(optval));
         break;

      case AF_INET6:
         error |= setsockopt(host_socket, IPPROTO_IPV6, IPV6_RECVERR, &optval, sizeof(optval));
         break;
   }

   unsigned ttl = 0, port = 33434;
   for (; true; ttl++) {

      if (port == 33534) port = 33434;
      switch (info->ai_family) {
         case AF_INET:
            error |= setsockopt(host_socket, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
            ((sockaddr_in*)&address)->sin_port = htons(port++);
            break;

         case AF_INET6:
            error |= setsockopt(host_socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl));
            ((sockaddr_in6*)&address)->sin6_port = htons(port++);
            break;
      }

      if (error)
         exitError("Setting socket paramaters failed!");
      
      if (sendto(host_socket, NULL, 0, 0, (sockaddr*)&address, sizeof(address)) < 0)
         exitError("Unable to send!");

      struct timespec time_sended;
      timespec_get(&time_sended, TIME_UTC);

      struct msghdr message;

      struct pollfd fd;
      fd.fd = host_socket;
      fd.events = POLLIN;
      switch (poll(&fd, 1, TIMEOUT)) {
         case -1: 
            exitError("Receive error!");
         case 0: 
            exitError("TIMEOUT");
         default:
            recvmsg(host_socket, &message, MSG_ERRQUEUE);
            struct timespec time_received;
            timespec_get(&time_received, TIME_UTC);

            decodeICMP(&message);
            unsigned ping_ms = (time_received.tv_sec - time_sended.tv_sec) * 1000 + (time_received.tv_nsec - time_sended.tv_nsec) / 1000000;
      }
      break;
   }
}

int main () {
   struct addrinfo input = {0};
   input.ai_family = AF_UNSPEC;
   input.ai_socktype = SOCK_DGRAM;    
   
   struct addrinfo* info;
   string address = "8.8.8.8";

   if (getaddrinfo(address.c_str(), "0", &input, &info) != 0)
      exitError("Invalid host!");

   trace(info);
}
