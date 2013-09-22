#ifndef MAC_AUTH_H
#define MAC_AUTH_H
#endif

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#define MAC_SIZE_DEFAULT 30
#define SERV_PORT 7880
#define BUF_SIZE 20
#define DEFAULT_MAC_LEN 30
#define INIT_MADADDR_PATH "mac.accept"

//#define HOSTAPD_DEBUG 1

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>


typedef unsigned char u8;

struct MAC_ADDR
{
    u8 mac_addr[ETH_ALEN];
};

struct IFC_LIST
{
    char* ifc_name;
    struct MAC_ADDR* accept_mac_array;
    int array_len;
    int mac_count;
} ifc_list;

static pthread_mutex_t ifc_list_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t sock_thread_id;

int mac_auth_init();
static void* mac_auth_sock_thread(void* args);
int mac_auth_found(char* ifc_name, u8* src_mac_addr);

