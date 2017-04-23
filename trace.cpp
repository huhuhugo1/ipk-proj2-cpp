// trace.cpp Traceroute
// Brno University of Technology         
// Computer Communications and Networks  
// Author: Juraj Kubiš  Login: xkubis15 

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
#include <unistd.h>

#define TIMEOUT 2000

using namespace std;

class Timer {
   struct timeval start_time;
   public:
      void reset() {
         gettimeofday(&start_time, NULL);
      }

      /*Returns time in millis and micros from last reset calling*/
      timeval delay() {
         struct timeval now_time;
         gettimeofday(&now_time, NULL);
         unsigned long long delay = (now_time.tv_sec - start_time.tv_sec) * 1000000 + (now_time.tv_usec - start_time.tv_usec);

         now_time.tv_sec = delay / 1000;
         now_time.tv_usec = delay - now_time.tv_sec * 1000;
         return now_time;
      }  
} timer;

/*Closes socket and free dynamically allocated memory on exit (when destructor is called)*/
struct Cleaner {
   int sock;
   struct addrinfo* info;
   
   ~Cleaner() {
      free(info);
      close(sock);
   }
} cleaner;

/*Decodes ip iddress of ICMP response sender*/
string decodeAddress(int type, struct sock_extended_err* sock_err) {
   char address[200] = {};
   
   if (type == AF_INET)
      inet_ntop(type, &((struct sockaddr_in*)(sock_err + 1))->sin_addr, address, sizeof(address));

   else if (type == AF_INET6)
      inet_ntop(type, &((struct sockaddr_in6*)(sock_err + 1))->sin6_addr, address, sizeof(address));
   
   return string(address);
}

/*Decodes host name of ICMP response sender*/
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

   return "";
}

/*Decodes ICMP code from message, prints content and retrun, if program should try next proble*/
bool decodeICMP(unsigned ttl, struct msghdr* message, struct timeval delay) {
   for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(message); cmsg; cmsg = CMSG_NXTHDR(message, cmsg)) 
      if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_RECVERR) {
         if (struct sock_extended_err* sock_err = (struct sock_extended_err*) CMSG_DATA(cmsg)) { 
            switch (sock_err->ee_type) {
               case ICMP_UNREACH:
                  switch (sock_err->ee_code) {
                     case ICMP_UNREACH_NET:
                        printf("%2u   %-15s   %-40s           N!\n", ttl, decodeAddress(AF_INET, sock_err).c_str(), decodeHostName(AF_INET, sock_err).c_str());
                        return false;
                     case ICMP_UNREACH_HOST:
                        printf("%2u   %-15s   %-40s           H!\n", ttl, decodeAddress(AF_INET, sock_err).c_str(), decodeHostName(AF_INET, sock_err).c_str());
                        return false;
                     case ICMP_UNREACH_PROTOCOL:
                        printf("%2u   %-15s   %-40s           P!\n", ttl, decodeAddress(AF_INET, sock_err).c_str(), decodeHostName(AF_INET, sock_err).c_str());
                        return false;
                     case ICMP_UNREACH_PORT:
                        printf("%2u   %-15s   %-40s   %3lu.%03lu ms\n", ttl, decodeAddress(AF_INET, sock_err).c_str(), decodeHostName(AF_INET, sock_err).c_str(), delay.tv_sec, delay.tv_usec);
                        return false;
                     case ICMP_UNREACH_FILTER_PROHIB:
                        printf("%2u   %-15s   %-40s           X!\n", ttl, decodeAddress(AF_INET, sock_err).c_str(), decodeHostName(AF_INET, sock_err).c_str());
                        return false;
                     default:
                        return false;
                  }
               case ICMP_TIMXCEED:
                  if(sock_err->ee_code == ICMP_TIMXCEED_INTRANS) {
                     printf("%2u   %-15s   %-40s   %3lu.%03lu ms\n", ttl, decodeAddress(AF_INET, sock_err).c_str(), decodeHostName(AF_INET, sock_err).c_str(), delay.tv_sec, delay.tv_usec);
                     return true;
                  }
                  break;
               default:
                  return false;
            }
         }
      } else if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_RECVERR) {
         if (struct sock_extended_err* sock_err = (struct sock_extended_err*) CMSG_DATA(cmsg)) { 
            switch (sock_err->ee_type) {
               case ICMP6_DST_UNREACH:
                  switch (sock_err->ee_code) {
                     case ICMP6_DST_UNREACH_NOROUTE:
                        printf("%2u   %-40s   %-40s           N!\n", ttl, decodeAddress(AF_INET6, sock_err).c_str(), decodeHostName(AF_INET6, sock_err).c_str());
                        return false;
                     case ICMP6_DST_UNREACH_ADMIN:
                        printf("%2u   %-40s   %-40s           X!\n", ttl, decodeAddress(AF_INET6, sock_err).c_str(), decodeHostName(AF_INET6, sock_err).c_str());
                        return false;
                     case ICMP6_DST_UNREACH_ADDR:
                        printf("%2u   %-40s   %-40s           H!\n", ttl, decodeAddress(AF_INET6, sock_err).c_str(), decodeHostName(AF_INET6, sock_err).c_str());
                        return false;
                     case ICMP6_DST_UNREACH_NOPORT:
                        printf("%2u   %-40s   %-40s   %3lu.%03lu ms\n", ttl, decodeAddress(AF_INET6, sock_err).c_str(), decodeHostName(AF_INET6, sock_err).c_str(), delay.tv_sec, delay.tv_usec);
                        return false;
                     default:
                        return false;
                  }
               case ICMP6_TIME_EXCEEDED:
                  if(sock_err->ee_code == ICMP6_TIME_EXCEED_TRANSIT) {
                     printf("%2u   %-40s   %-40s   %3lu.%03lu ms\n", ttl, decodeAddress(AF_INET6, sock_err).c_str(), decodeHostName(AF_INET6, sock_err).c_str(), delay.tv_sec, delay.tv_usec);
                     return true;
                  }
                  break;
               case ICMP6_PARAM_PROB:
                  if (sock_err->ee_code == ICMP6_PARAMPROB_NEXTHEADER) {
                     printf("%2u   %-40s   %-40s           P!\n", ttl, decodeAddress(AF_INET6, sock_err).c_str(), decodeHostName(AF_INET6, sock_err).c_str());
                     return false;
                  }
                  break;
               default:
                  return false;
            }
         }
      }

   return false;
}

/*Prints error message to stderr and exit program*/
void exitError(string message, int code = 1) {
   cerr << message << endl;
   exit(code);
}

/*Starts tracing route to host*/
void trace(struct addrinfo* info, unsigned ttl, unsigned max_ttl) {
   /*Creates an UDP socket*/
   int host_socket = cleaner.sock = socket(info->ai_family, SOCK_DGRAM, 0);

   if (host_socket == -1)
      exitError("Unable to connect!");

   sockaddr_in6 address = {0};
   memcpy(&address, info->ai_addr, info->ai_addrlen);
   
   int optval = 1;
   bool error = false;

   /*Sets socket to receive error ICMP messages*/
   if (info->ai_family == AF_INET)
      error |= setsockopt(host_socket, SOL_IP, IP_RECVERR, &optval, sizeof(optval));
   else
      error |= setsockopt(host_socket, IPPROTO_IPV6, IPV6_RECVERR, &optval, sizeof(optval));
   
   bool next_ttl = true;
   for (unsigned port = 33434; ttl <= max_ttl && next_ttl; ttl++, port++) {
      if (port == 33534) port = 33434;
      
      /*Sets TTL and port*/
      if (info->ai_family == AF_INET) {
         error |= setsockopt(host_socket, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
         ((sockaddr_in*)&address)->sin_port = htons(port);
      } else {
         error |= setsockopt(host_socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl));
         ((sockaddr_in6*)&address)->sin6_port = htons(port);
      }

      if (error)
         exitError("Setting socket paramaters failed!");
      
      /*When sending of UDP packet failed, tries it one more time*/
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

      /*Waits on socket activity (ICMP repsonse received) or TIMEOUT expiration*/
      switch (poll(&fd, 1, TIMEOUT)) {
         case -1: /*Error*/
            exitError("Receive error!");
         
         case 0: /*TIMEOUT expired*/
            printf("%2u   *\n", ttl);
            break;
         
         default: /*Receives ICMP response*/
            if (recvmsg(host_socket, &message, MSG_ERRQUEUE) == -1)
               exitError("Unable to receive!");
            next_ttl = decodeICMP(ttl, &message, timer.delay());
      }
   }
}

int main(int argc, char** argv) {
   string address = "";
   unsigned max_ttl = 30;
   unsigned ttl = 1;

   /*Process arguments*/
   switch (argc) {
      default: 
         exitError("Invalid arguments!");

      case 6: 
         if (string(argv[3]) == "-f" && isdigit(argv[4][0]))
            ttl = stoul(argv[4]);
         else if (string(argv[3]) == "-m" && isdigit(argv[4][0]))
            max_ttl = stoul(argv[4]);
         else
            exitError("Invalid arguments!");

      case 4: 
         if (string(argv[1]) == "-f" && isdigit(argv[2][0]))
            ttl = stoul(argv[2]);
         else if (string(argv[1]) == "-m" && isdigit(argv[2][0]))
            max_ttl = stoul(argv[2]);
         else
            exitError("Invalid arguments!");

      case 2: 
         address = string(argv[argc-1]); 
   }

   struct addrinfo input = {0};
   input.ai_family = AF_UNSPEC;
   input.ai_socktype = SOCK_DGRAM;

   /*Validates IP address / host name, gets version of IP protocol*/
   if (getaddrinfo(address.c_str(), "0", &input, &cleaner.info) != 0)
      exitError("Invalid host!");

   if (cleaner.info->ai_family == AF_INET || cleaner.info->ai_family == AF_INET6)
      trace(cleaner.info, ttl, max_ttl);
   else
      exitError("Invalid network protocol!");

   return 0;
}
