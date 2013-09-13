#ifndef MAC_AUTH_H
#define MAC_AUTH_H
#endif

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#define MAC_SIZE_DEFAULT 30
#define SERV_PORT 7880

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>

struct MAC_ADDR
{
	u8 mac_addr[ETH_ALEN];	
};

struct IFC_LIST
{
	char* ifc_name; 
	MAC_ADDR* accept_mac_array;
	int array_len;	
}ifc_list;

static pthread_mutex_t ifc_list_lock = PTHREAD_MUTEX_INITIALIZER; 

void mac_auth_init()
{
	return;
}

void* mac_auth_sock_thread(void* args)
{
	int listen_sock, recv_sock, if_sock;
	struct sockaddr_in serv_addr, cli_addr;

	bzero(&svr_addr, sizeof(serv_addr));
	serv_addr.sin_fimaly = AF_INET;
	serv_addr.sin_port = hosts(SERV_PORT);

	struct ifreq* if_start, * ifend;
	struct ifconf ifc;
	struct ifreq ifs[5];
	if_sock = socket(AF_INET, SOCK_DGRAM, 0);
	ifc.ifc_len = sizeof(ifs);
	ifc.ifc_req = ifs;
	if(ioctl(if_sock, SIOCGIFCONF, &ifc)){
		exit(0);
	}
	if_end = ifs + (ifc.ifc_len / sizeof(struct ifreq));
	for(if_start = ifs; if_start < if_end; ++if_start){
		if(strncmp("eth0", if_start->ifr_name, sizeof("eth0"))){
			serv_addr.sin_addr = ((struct sockaddr_in *)&if_start->ifr_addr)->sin_addr;
			break;
		}
	}

	listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO);
	bind(listen_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
	listen(listen_sock, 5);

	return (void*)0;
}

int mac_auth_found(char* ifc_name, u8* src_mac_addr)
{
	if(strcmp(ifc_name, ifc_list.ifc_name)){
		pthread_mutex_lock(&ifc_list_lock);
		int i, j, is_found;
		is_found = 0;
		for(i = 0; i < ifc_list.array_len; ++i){
			if(memcmp(src_mac_addr, ifc_list.accept_mac_array[i], ETH_ALEN) == 0){
				is_found = 1;
				break;
			}
		}
		pthread_mutex_unlock(&ifc_list_lock);
		if(is_found)
			return 1;
		else
			return 0;

	}else
		return 0;
}
