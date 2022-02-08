/*
 *	Projekt: Traceroute
 *	Autor: Martin Studeny
 *	Login: xstude23
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <linux/errqueue.h>
#include <linux/icmpv6.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <netdb.h>
#include <time.h>
#include <regex.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <poll.h>


int variable = 0;
int timeout = 0;
struct timeval tv1, tv2;
int is_ipv6 = 0; // 0 -> ipv4 , 1 -> ipv6

// funkce, ktera zkontroluje, jestli je IP adresa ve spravnem formatu
int check_ip_address(char *s) {
	int value;
	char buf[sizeof(struct in6_addr)];

	if(strchr(s, ':') == NULL) {
		value = inet_pton(AF_INET, s, buf); // konvertuje adresu z textove formy do binarni
		is_ipv6 = 0;
	}
	else {
		value = inet_pton(AF_INET6, s, buf); // konvertuje adresu z textove formy do binarni
		is_ipv6 = 1;
	}

	if(value == 1)
		return 0; // SUCCESS
	else
		return 1; // FAIL
}


// vytvoreni socketu
int create_socket() {
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if(s < 0){
		fprintf(stderr, "Chyba: Socket se nepodarilo vytvorit\n");
		return 1;
	}
	else {
	}
	return s;	
}

int create_socket_6() {
	int s = socket(AF_INET6, SOCK_DGRAM, 0);
	if(s < 0){
		fprintf(stderr, "Chyba: Socket se nepodarilo vytvorit\n");
		return 1;
	}
	else {
	}
	return s;	
}

int recv_err(int socket, int j, char* ip) {
	int res;
	char cbuf[512];
	struct iovec iov;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct sock_extended_err *e;
	struct icmphdr icmph;
	struct sockaddr_in target;
	int count = 1;
	struct pollfd fd;
	char buffer[INET_ADDRSTRLEN];
	while(1) {
		iov.iov_base = &icmph;
		iov.iov_len = sizeof(icmph);
		msg.msg_name = (void*)&target;
		msg.msg_namelen = sizeof(target);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_flags = 0;
		msg.msg_control = cbuf;
		msg.msg_controllen = sizeof(cbuf);
		fd.fd = socket;
		fd.events = POLLIN;
		res = poll(&fd, 1, 2000); // 2000 ms timeout
		if(res == 0) {
			timeout = 1;
		    return 1;
		}
		else if(res == -1) {
		    fprintf(stderr,"Chyba\n");
			exit(errno);
		}
		else {
			res = recvmsg(socket, &msg, MSG_ERRQUEUE | MSG_WAITALL);
			gettimeofday(&tv2,NULL);
		}
		if(res < 0) {
			if(variable == 1) {
				return 0;
			}
			continue;
		}
		for(cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			if(cmsg->cmsg_level == SOL_IP)
				if(cmsg->cmsg_type == IP_RECVERR) {
					e = (struct sock_extended_err*)CMSG_DATA(cmsg);
					if(e)
						if(e->ee_origin == SO_EE_ORIGIN_ICMP) {
							struct sockaddr_in *sin = (struct sockaddr_in *)(e+1);
							if(variable == 0) {
								inet_ntop(AF_INET, &(sin->sin_addr), buffer, sizeof(buffer));
								printf("%d\t%s\t", j, buffer);
								count++;
							}
							if(strcmp(buffer, ip) == 0) {
								variable = 1;
							}
							if((e->ee_type == ICMP_DEST_UNREACH) && (e->ee_code == ICMP_PORT_UNREACH)) {
								return 0;								
							}
							if((e->ee_type == ICMP_DEST_UNREACH) && (e->ee_code == ICMP_NET_UNREACH)) {
								return 2;								
							}
							if((e->ee_type == ICMP_DEST_UNREACH) && (e->ee_code == ICMP_HOST_UNREACH)) {
								return 3;								
							}
							if((e->ee_type == ICMP_DEST_UNREACH) && (e->ee_code == ICMP_PROT_UNREACH)) {
								return 4;								
							}	
							if((e->ee_type == ICMP_TIME_EXCEEDED) && (e->ee_code == ICMP_EXC_TTL)) {
								return 0;								
							}
							if((e->ee_type == ICMP_DEST_UNREACH) && (e->ee_code == ICMP_PKT_FILTERED)) {
								return 5;								
							}
							return 0;					
						}
				}
		}
	}
}

int recv_err_6(int socket, int j, char* ip) {
	int res;
	char cbuf[512];
	struct iovec iov;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct sock_extended_err *e;
	struct icmphdr icmph;
	struct sockaddr_in6 target;
	int count = 1;
	struct pollfd fd;
	char buffer[10000];
	while(1) {
		iov.iov_base = &icmph;
		iov.iov_len = sizeof(icmph);
		msg.msg_name = (void*)&target;
		msg.msg_namelen = sizeof(target);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_flags = 0;
		msg.msg_control = cbuf;
		msg.msg_controllen = sizeof(cbuf);
		fd.fd = socket;
		fd.events = POLLIN;
		res = poll(&fd, 1, 2000); // 2000 ms timeout
		if(res == 0)
		{
			timeout = 1;
		    return 1;
		}
		else if(res == -1)
		{
		    fprintf(stderr, "Chyba: Timeout\n");
			exit(errno);
		}
		else{
			res = recvmsg(socket, &msg, MSG_ERRQUEUE | MSG_WAITALL);
			gettimeofday(&tv2,NULL);
		}
		if(res < 0) {
			if(variable == 1) {
				return 0;
			}
			continue;
		}
		for(cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			if(cmsg->cmsg_level == SOL_IPV6)
				if(cmsg->cmsg_type == IPV6_RECVERR) {
					e = (struct sock_extended_err*)CMSG_DATA(cmsg);
					if(e)
						if(e->ee_origin != SO_EE_ORIGIN_LOCAL) {
							struct sockaddr_in6 *sin = (struct sockaddr_in6 *)(e+1);
							if(variable == 0) {
								inet_ntop(AF_INET6, &(sin->sin6_addr), buffer, sizeof(buffer));
								printf("%d\t%s\t", j, buffer);
								count++;
							}
							if(strcmp(buffer, ip) == 0) {
								variable = 1;
							}
							if((e->ee_type == ICMPV6_DEST_UNREACH) && (e->ee_code == ICMPV6_PORT_UNREACH)) {
								return 0;								
							}
							if((e->ee_type == ICMPV6_DEST_UNREACH) && (e->ee_code == ICMPV6_NOROUTE)) {
								return 2;								
							}
							if((e->ee_type == ICMPV6_DEST_UNREACH) && (e->ee_code == ICMPV6_ADDR_UNREACH )) {
								return 3;								
							}
							if((e->ee_type == ICMPV6_TIME_EXCEED) && (e->ee_code == ICMPV6_EXC_HOPLIMIT)) {
								return 0;								
							}
							if((e->ee_type == ICMPV6_DEST_UNREACH) && (e->ee_code == ICMPV6_ADM_PROHIBITED)) {
								return 5;								
							}
							if((e->ee_type == ICMPV6_PARAMPROB) && (e->ee_code == ICMPV6_UNK_NEXTHDR)) {
								return 4;								
							}
							return 0;
						}
				}
		}
	}
}

int main(int argc, char *argv[]) {
	char ip_address[100];
	int first_packet_TTL = 1; // implicitne je 1
	int max_TTL = 30; // implicitne je 30
	struct sockaddr_in server;
	struct sockaddr_in6 server_ipv6;
	int socket;

	/*
	 *	Osetreni argumentu
	 * 
	*/
	// program musi byt spusten alespon s jednim argumentem
	if(argc < 2) {
		fprintf(stderr, "Chyba: Spatne zadane argumenty\n");
		return 1;
	}
	else if(argc > 6) {
		fprintf(stderr, "Chyba: Spatne zadane argumenty\n");
		return 1;
	}
	// pokud je zadana pouze ip adresa
	if(argc == 2) {
		strcpy(ip_address, argv[1]);
	}
	// pokud je zadana jen ip adresa a dalsi argument
	if(argc == 4) {
		if(strcmp(argv[1],"-f") == 0) {
			first_packet_TTL = atoi(argv[2]);
		}
		else if(strcmp(argv[1], "-m") == 0) {
			max_TTL = atoi(argv[2]);
		}
		strcpy(ip_address, argv[3]);
	}
	if(argc == 6) {
		if(strcmp(argv[1],"-f") == 0) {
			first_packet_TTL = atoi(argv[2]);
		}
		else if(strcmp(argv[1], "-m") == 0) {
			max_TTL = atoi(argv[2]);
		}
		if(strcmp(argv[3], "-m") == 0) {
			max_TTL = atoi(argv[4]);
		}
		else if(strcmp(argv[3],"-f") == 0) {
			first_packet_TTL = atoi(argv[4]);
		}
		strcpy(ip_address, argv[5]);
	}
	if(check_ip_address(ip_address) == 1) {
		fprintf(stderr, "Chyba: argumenty jsou zadany spatne\n");
		return 1;
	}
	// nasteveni pri ipv4
	if(is_ipv6 == 0) {
		server.sin_family = AF_INET;
		server.sin_port = htons(33434);
		inet_pton(AF_INET, ip_address, &(server.sin_addr));		
	}
	// nastaveni pro ipv6
	else if(is_ipv6 == 1) {
		server_ipv6.sin6_family = AF_INET6;
		server_ipv6.sin6_port = htons(33434);
		inet_pton(AF_INET6, ip_address, &(server_ipv6.sin6_addr));			
	}
	// ivp4
	if(is_ipv6 == 0) {
		socket = create_socket(); // vytvoreni socketu
		if(setsockopt(socket, IPPROTO_IP, IP_TTL, &first_packet_TTL, sizeof(first_packet_TTL)) != 0) {
			fprintf(stderr, "Chyba: setsockopt\n");
			return 1;
		}
		int val = 1;
		if(setsockopt(socket, SOL_IP, IP_RECVERR, (char*)&val, sizeof(val))) {
			fprintf(stderr, "Chyba: Socket set\n");
			return 1;
		}	
	}
	// ipv6
	else {
		socket = create_socket_6(); // vytvoreni socketu
		if(setsockopt(socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &first_packet_TTL, sizeof(first_packet_TTL)) != 0) {
				fprintf(stderr, "Chyba: setsockopt\n");
				return 1;
		}
		int val = 1;
		if(setsockopt(socket, SOL_IPV6, IPV6_RECVERR, (char*)&val, sizeof(val))) {
			fprintf(stderr, "Chyba: Socket set\n");
			return 1;
		}		
	}
	


	//int a = ping(socket, 200, &server, sizeof(server));
	
	double elapsedTime;
 
	/*if(setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &tv1, sizeof(tv1)) < 0) {
		fprintf(stderr, "Chyba: Socket set\n");
		return 1;
	}*/

	int j;
	int v;
	int ajfaf;
	// pro ipv4
	if(is_ipv6 == 0) {
		for(j = first_packet_TTL; j < max_TTL; j++) {
			if(setsockopt(socket, IPPROTO_IP, IP_TTL, &j, sizeof(j)) != 0) {
				fprintf(stderr, "Chyba\n");
				return 1;
			}
			if(sendto(socket, NULL, 0,0, (struct sockaddr *) &server, sizeof(server))) {
				if(errno == 113 || errno == 0)
					continue;
				else
					exit(errno);
			}
			gettimeofday(&tv1,NULL);
			v = recv_err(socket, j, ip_address);
			if(v == 1) {
				printf("%d\t*\n",j);
			}
			else if(v == 2) {
				printf("  N!\n");
				return 0;
			}
			else if(v == 3) {
				printf("  H!\n");
				return 0;
			}
			else if(v == 4) {
				printf("  P!\n");
				return 0;
			}
			else if(v == 5) {
				printf("  X!\n");
				return 0;
			}
			elapsedTime = (tv2.tv_sec - tv1.tv_sec) * 1000.0;
			elapsedTime = elapsedTime + (tv2.tv_usec - tv1.tv_usec) / 1000.0;
			if(timeout == 1) {
				timeout = 0;
			}
			else
				printf("  %g ms\n", elapsedTime);
			if(variable == 1) {
				return 0;
			}
		}		
	}
	// pro ipv6
	else if(is_ipv6 == 1) {
		for(j = first_packet_TTL; j < max_TTL; j++) {
			if(setsockopt(socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &j, sizeof(j)) != 0) {
				return(errno);
				fprintf(stderr, "Chyba\n");
				return 1;
			}
			char buffer1[10000];
			inet_ntop(AF_INET6, &(server_ipv6.sin6_addr), buffer1, sizeof(buffer1));
			//printf("---%s\n", buffer1);
			if(sendto(socket, NULL, 0,0, (struct sockaddr *) &server_ipv6, sizeof(server_ipv6)) == -1) {
				if(errno == 113 || errno == 0)
					ajfaf = 56;
				else {
					exit(errno);
				}
			}
			gettimeofday(&tv1,NULL);
			v = recv_err_6(socket, j, ip_address);
			if(v == 1) {
				printf("%d\t*\n",j);
			}
			else if(v == 2) {
				printf("  N!\n");
				return 0;
			}
			else if(v == 3) {
				printf("  H!\n");
				return 0;
			}
			else if(v == 4) {
				printf("  P!\n");
				return 0;
			}
			else if(v == 5) {
				printf("  X!\n");
				return 0;
			}
			elapsedTime = (tv2.tv_sec - tv1.tv_sec) * 1000.0;
			elapsedTime = elapsedTime + (tv2.tv_usec - tv1.tv_usec) / 1000.0;
			if(timeout == 1) {
				timeout = 0;
			}
			else
				printf("  %g ms\n", elapsedTime);
			if(variable == 1) {
				return 0;
			}
		}	
	}
}