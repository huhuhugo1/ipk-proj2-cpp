#include <netinet/ip_icmp.h>
#include <linux/errqueue.h>
#include <iostream>
#include <string.h>
#include <getopt.h>
#include <netdb.h>
#include <poll.h>
#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <sys/time.h>

#define TIMEOUT 2000
enum {
   ICMP_continue,
   ICMP_break,
   ICMP_exit
};

using namespace std;

class Timer {
   struct timeval start_time;
   public:
      void reset() {
         gettimeofday(&start_time, NULL);
      }

      timeval delay() {
         struct timeval now_time;
         gettimeofday(&now_time, NULL);
         unsigned long long delay = (now_time.tv_sec - start_time.tv_sec) * 1000000 + (now_time.tv_usec - start_time.tv_usec);

         now_time.tv_sec = delay / 1000;
         now_time.tv_usec = delay -  now_time.tv_sec * 1000;
         return now_time;
      }  
} timer;

string decodeAddress(int type, struct sock_extended_err* sock_err) {
   char address[200] = {};
   
   if (type == AF_INET)
      inet_ntop(type, &((struct sockaddr_in*)(sock_err + 1))->sin_addr, address, sizeof(address));

   else if (type == AF_INET6)
      inet_ntop(type, &((struct sockaddr_in6*)(sock_err + 1))->sin6_addr, address, sizeof(address));
   
   return string(address);
}

string decodeHostName(int type, struct sock_extended_err* sock_err) {
   char host_name[512];
   
   if (type == AF_INET) {
      struct sockaddr_in address;
      address.sin_family = AF_INET;
      address.sin_addr = ((struct sockaddr_in*)(sock_err + 1))->sin_addr;
      if (getnameinfo((struct sockaddr*)&address, sizeof(address), host_name, sizeof(host_name), NULL, 0, NI_NAMEREQD) == 0)
        return string(host_name);
   }
   else if (type == AF_INET6) {
      struct sockaddr_in6 address;
      address.sin6_family = AF_INET6;
	   memcpy(address.sin6_addr.s6_addr, ((struct sockaddr_in6*)(sock_err + 1))->sin6_addr.s6_addr, sizeof(((struct sockaddr_in6*)(sock_err + 1))->sin6_addr.s6_addr));
      if (getnameinfo((struct sockaddr*)&address, sizeof(address), host_name, sizeof(host_name), NULL, 0, NI_NAMEREQD) == 0)
        return string(host_name);
   }

   return "";//decodeAddress(type, sock_err);
}

int decodeICMP(unsigned ttl, struct msghdr* message, struct timeval delay) {
   for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(message); cmsg; cmsg = CMSG_NXTHDR(message, cmsg)) 
      if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_RECVERR) {
         if (struct sock_extended_err* sock_err = (struct sock_extended_err*) CMSG_DATA(cmsg)) { 
            switch (sock_err->ee_type) {
               case ICMP_UNREACH:
                  switch (sock_err->ee_code) {
                     case ICMP_UNREACH_NET:
                        printf("%2u   %-40s   %-15s   N!\n", ttl, decodeHostName(AF_INET, sock_err).c_str(), decodeAddress(AF_INET, sock_err).c_str());
                        return ICMP_exit;
                     case ICMP_UNREACH_HOST:
                        printf("%2u   %-40s   %-15s   H!\n", ttl, decodeHostName(AF_INET, sock_err).c_str(), decodeAddress(AF_INET, sock_err).c_str());
                        return ICMP_exit;
                     case ICMP_UNREACH_PROTOCOL:
                        printf("%2u   %-40s   %-15s   P!\n", ttl, decodeHostName(AF_INET, sock_err).c_str(), decodeAddress(AF_INET, sock_err).c_str());
                        return ICMP_exit;
                     case ICMP_UNREACH_PORT:
                        printf("%2u   %-40s   %-15s   %lu.%03lu ms\n", ttl, decodeHostName(AF_INET, sock_err).c_str(), decodeAddress(AF_INET, sock_err).c_str(), delay.tv_sec, delay.tv_usec);
                        return ICMP_exit;
                     case ICMP_UNREACH_FILTER_PROHIB:
                        printf("%2u   %-40s   %-15s   X!\n", ttl, decodeHostName(AF_INET, sock_err).c_str(), decodeAddress(AF_INET, sock_err).c_str());
                        return ICMP_exit;
                     default:
                        return ICMP_exit;
                  }
               case ICMP_TIMXCEED:
                  if(sock_err->ee_code == ICMP_TIMXCEED_INTRANS) {
                     printf("%2u   %-40s   %-15s   %lu.%03lu ms\n", ttl, decodeHostName(AF_INET, sock_err).c_str(), decodeAddress(AF_INET, sock_err).c_str(), delay.tv_sec, delay.tv_usec);
                     return ICMP_break;
                  }
                  break;
               default:
                  return ICMP_exit;
            }
         }
      } else if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_RECVERR) {
         if (struct sock_extended_err* sock_err = (struct sock_extended_err*) CMSG_DATA(cmsg)) { 
            switch (sock_err->ee_type) {
               case ICMP6_DST_UNREACH:
                  switch (sock_err->ee_code) {
                     case ICMP6_DST_UNREACH_NOROUTE:
                        printf("%2u   %-40s   %-35s   N!\n", ttl, decodeHostName(AF_INET6, sock_err).c_str(), decodeAddress(AF_INET6, sock_err).c_str());
                        return ICMP_exit;
                     case ICMP6_DST_UNREACH_ADMIN:
                        printf("%2u   %-40s   %-35s   X!\n", ttl, decodeHostName(AF_INET6, sock_err).c_str(), decodeAddress(AF_INET6, sock_err).c_str());
                        return ICMP_exit;
                     case ICMP6_DST_UNREACH_ADDR:
                        printf("%2u   %-40s   %-35s   H!\n", ttl, decodeHostName(AF_INET6, sock_err).c_str(), decodeAddress(AF_INET6, sock_err).c_str());
                        return ICMP_exit;
                     case ICMP6_DST_UNREACH_NOPORT:
                        printf("%2u   %-40s   %-35s   %lu.%03lu ms\n", ttl, decodeHostName(AF_INET6, sock_err).c_str(), decodeAddress(AF_INET6, sock_err).c_str(), delay.tv_sec, delay.tv_usec);
                        return ICMP_exit;
                     default:
                        return ICMP_exit;
                  }
               case ICMP6_TIME_EXCEEDED:
                  if(sock_err->ee_code == ICMP6_TIME_EXCEED_TRANSIT) {
                     printf("%2u   %-40s   %-35s   %lu.%03lu ms\n", ttl, decodeHostName(AF_INET6, sock_err).c_str(), decodeAddress(AF_INET6, sock_err).c_str(), delay.tv_sec, delay.tv_usec);
                     return ICMP_break;
                  }
                  break;
               case ICMP6_PARAM_PROB:
                  if (sock_err->ee_code == ICMP6_PARAMPROB_NEXTHEADER) {
                     printf("%2u   %-40s   %-35s   P!\n", ttl, decodeHostName(AF_INET6, sock_err).c_str(), decodeAddress(AF_INET6, sock_err).c_str());
                     return ICMP_exit;
                  }
                  break;
               default:
                  return ICMP_exit;
            }
         }
      }

   printf("Unknown error!\n");
   return ICMP_continue;
}

void exitError(string message, int code = 1) {
   cerr << message << endl;
   exit(code);
}

void trace(struct addrinfo* info, unsigned ttl, unsigned max_ttl) {
   int host_socket = socket(info->ai_family, SOCK_DGRAM, 0);
   if (host_socket == -1)
      exitError("Unable to connect!");

   sockaddr_in6 address = {0};
   memcpy(&address, info->ai_addr, info->ai_addrlen);
   
   int optval = 1;
   bool error = false;
   if (info->ai_family == AF_INET)
      error |= setsockopt(host_socket, SOL_IP, IP_RECVERR, &optval, sizeof(optval));
   else
      error |= setsockopt(host_socket, IPPROTO_IPV6, IPV6_RECVERR, &optval, sizeof(optval));
   
   for (unsigned repeat = ICMP_continue, port = 33434; ttl <= max_ttl && repeat != ICMP_exit; ttl++, port++) {
      if (port == 33534) port = 33434;
      
      if (info->ai_family == AF_INET) {
         error |= setsockopt(host_socket, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
         ((sockaddr_in*)&address)->sin_port = htons(port);
      } else {
         error |= setsockopt(host_socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl));
         ((sockaddr_in6*)&address)->sin6_port = htons(port);
      }

      if (error)
         exitError("Setting socket paramaters failed!");

      if (sendto(host_socket, NULL, 0, 0, (sockaddr*)&address, sizeof(address)) < 0)
         if (sendto(host_socket, NULL, 0, 0, (sockaddr*)&address, sizeof(address)) < 0)
            exitError("Unable to send!");
      
      timer.reset();
      
      char buffer[2048] = {};
      struct iovec io;
      io.iov_base = buffer;
      io.iov_len = sizeof(buffer);
      
      char control[1024];
      struct msghdr message;
      message = {0};
      message.msg_iov = &io;
      message.msg_iovlen = 1;
      message.msg_control = &control;
      message.msg_controllen = sizeof(control);

      struct pollfd fd;
      fd.fd = host_socket;
      fd.events = POLLIN;
      int ready;
      do {
         switch (ready = poll(&fd, 1, TIMEOUT)) {
            case -1: 
               exitError("Receive error!");
            case 0: 
               printf("%2u   *\n", ttl); 
               break;
            default:
               if (recvmsg(host_socket, &message, MSG_ERRQUEUE) == -1)
                  exitError("Unable to receive!");
         }
      } while (ready && (repeat = decodeICMP(ttl, &message, timer.delay())) == ICMP_continue);
   }
}

int main(int argc, char** argv) {
   string address = "";
   unsigned max_ttl = 30;
   unsigned ttl = 1;
   switch (argc) {
      default: 
         exitError("Invalid arguments!");

      case  6: 
         if (string(argv[3]) == "-f")
            ttl = stoul(argv[4]);
         else if (string(argv[3]) == "-m")
            max_ttl = stoul(argv[4]);

      case  4: 
         if (string(argv[1]) == "-f")
            ttl = stoul(argv[2]);
         else if (string(argv[1]) == "-m")
            max_ttl = stoul(argv[2]);

      case  2: 
         address = string(argv[argc-1]); 
   }

   struct addrinfo* info;
   struct addrinfo input = {0};
   input.ai_family = AF_UNSPEC;
   input.ai_socktype = SOCK_DGRAM;    

   if (getaddrinfo(address.c_str(), "0", &input, &info) != 0)
      exitError("Invalid host!");

   if (info->ai_family == AF_INET || info->ai_family == AF_INET6)
      trace(info, ttl, max_ttl);
   else
      exitError("Invalid network protocol!");
}
