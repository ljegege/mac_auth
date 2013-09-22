#include "mac_auth.h"

static int hex2num(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}


/**
 * hwaddr_aton - Convert ASCII string to MAC address (colon-delimited format)
 * @txt: MAC address as a string (e.g., "00:11:22:33:44:55")
 * @addr: Buffer for the MAC address (ETH_ALEN = 6 bytes)
 * Returns: 0 on success, -1 on failure (e.g., string not a MAC address)
 */
static int hwaddr_aton(const char *txt, u8 *addr)
{
    int i;

    for (i = 0; i < 6; i++)
    {
        int a, b;

        a = hex2num(*txt++);
        if (a < 0)
            return -1;
        b = hex2num(*txt++);
        if (b < 0)
            return -1;
        *addr++ = (a << 4) | b;
        if (i < 5 && *txt++ != ':')
            return -1;
    }

    return 0;
}
/*
 * 将addr添加到ifc_list_p所指的链表中
 * 返回0标识添加成功，-1则标识添加失败
 */
static int add_mac_addr(struct IFC_LIST* ifc_list_p, u8* addr)
{
    // 判断ifc_list_p中是否有空间可以存放新的mac地址
    if(ifc_list_p->mac_count >= ifc_list_p->array_len)
    {
        // 如果没有则重新为ifc_list_p分配空间新空间大小是原来空戛纳大小的1.5倍
        if(!realloc(ifc_list_p->accept_mac_array, (int)ifc_list_p->array_len * 1.5))
        {
            return -1;
        }
        ifc_list_p->array_len = ifc_list_p->array_len * 1.5;
    }
    else
    {
        // 将addr地址添加进去ifc_list_p中
        if(!memcpy(ifc_list_p->accept_mac_array[ifc_list_p->mac_count++].mac_addr, addr, ETH_ALEN))
        {
            return -1;
        }
    }
    return 0;
}

/*
 * 初始化允许接入的网络的mac地址列表并创建线程，该线程用于监听连接端口和接收外部传进来的mac地址。
 * 返回0标识添加成功，-1则标识添加失败
 */
int mac_auth_init()
{
    char buf[128], *pos;
    u8 addr[ETH_ALEN];
    int line = 0;

    // 	初始化ifc_list
    ifc_list.ifc_name = "eth0";
    ifc_list.mac_count = 0;
    ifc_list.array_len = DEFAULT_MAC_LEN;
    ifc_list.accept_mac_array = (struct MAC_ADDR*)malloc(sizeof(struct MAC_ADDR) * DEFAULT_MAC_LEN);

    FILE* accept_file = fopen(INIT_MADADDR_PATH, "r");
    if(accept_file == NULL)
    {
        perror("初始化文件不存在");
        return -1;
    }

    //将地址行读入buf中
    while (fgets(buf, sizeof(buf), accept_file))
    {
        line++;

        if (buf[0] == '#')
            continue;
        pos = buf;
        while (*pos != '\0')
        {
            if (*pos == '\n')
            {
                *pos = '\0';
                break;
            }
            pos++;
        }
        if (buf[0] == '\0')
            continue;
        // 将读入的地址转换为以太网地址，并存储在addr中
        if (hwaddr_aton(buf, addr))
        {
            printf("Invalid MAC address '%s' at line %d in '%s'", buf, line, INIT_MADADDR_PATH);
            fclose(accept_file);
            free(ifc_list.accept_mac_array);
            return -1;
        }
#ifdef HOSTAPD_DEBUG
        printf("mac=%s\tmac=%d\n", buf, addr[5]);
#endif
        // 成功转换后将mac地址添加到ifc_list中
        if(add_mac_addr(&ifc_list, addr) == -1)
        {
            printf("fail to init the mac address!");
            fclose(accept_file);
            free(ifc_list.accept_mac_array);
            return -1;
        }
    }
    fclose(accept_file);
    // 创建mac_auth_sock_thread
    pthread_create(&sock_thread_id, NULL, mac_auth_sock_thread, NULL);

    return 0;
}

static void* mac_auth_sock_thread(void* args)
{
#ifdef HOSTAPD_DEBUG
    int mac_count;
    for(mac_count = 0; mac_count < ifc_list.mac_count; ++mac_count)
    {
        printf("%d\n", ifc_list.accept_mac_array->mac_addr[0]);
    }
#endif
    int listen_sock, recv_sock, if_sock;
    socklen_t cli_addr_len;
    struct sockaddr_in serv_addr;
    struct sockaddr_in cli_addr;
    char buf[BUF_SIZE];
    fd_set sock_set;

    bzero(&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERV_PORT);

    struct ifreq* if_start, * if_end;
    struct ifconf ifc;
    struct ifreq ifs[5];
    // 创建以太网接口sock
    if_sock = socket(AF_INET, SOCK_DGRAM, 0);
    ifc.ifc_len = sizeof(ifs);
    ifc.ifc_req = ifs;
    // 获取所有以太网设备的设备信息
    if(ioctl(if_sock, SIOCGIFCONF, &ifc))
    {
        exit(0);
    }
    if_end = ifs + (ifc.ifc_len / sizeof(struct ifreq));
    // 查找有线网，并获取其IP地址
    for(if_start = ifs; if_start < if_end; ++if_start)
    {
        if(strncmp("eth0", if_start->ifr_name, sizeof("eth0")) == 0)
        {
            serv_addr.sin_addr = ((struct sockaddr_in *)&if_start->ifr_addr)->sin_addr;
#ifdef HOSTAPD_DEBUG
            printf("eth0=%s\n", inet_ntoa(serv_addr.sin_addr));
#endif
            break;
        }
    }
    // 创建监听sock
    listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    // 绑定监听地址
    bind(listen_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    listen(listen_sock, 10);

    recv_sock = -1;
    while(1)
    {
        //#ifdef HOSTAPD_DEBUG
        printf("client\n");
//#endif

        // 将监听接口添加到I/O转接集合中
        FD_ZERO(&sock_set);
        FD_SET(listen_sock, &sock_set);
        // 如果接收sock已经初始化，则将接收sock添加到I/O转接集合中
        if(recv_sock != -1)
        {
            FD_SET(recv_sock, &sock_set);
        }
        // 等待客户端的连接或者客户端发送mac地址
        int max_sock = listen_sock > recv_sock? listen_sock : recv_sock;
        printf("%d,%d,%d\n", max_sock, listen_sock, recv_sock);
        int rt = select(max_sock + 1, &sock_set, NULL, NULL, NULL);

        if(rt <= 0)
        {
            // 未考虑网络出错处理
            perror("network interface error");
            return (void*)0;
        }
        else
        {
            // 如果客户端请求连接，则先关闭原有的接收sock，则接受新的请求连接
            if(FD_ISSET(listen_sock, &sock_set))
            {
                // close（-1）不知道会有什么后果？？？？
                close(recv_sock);
                cli_addr_len = sizeof(cli_addr);
                recv_sock = accept(listen_sock, (struct sockaddr*)&cli_addr, &cli_addr_len);
                perror("accept:");
//#ifdef HOSTAPD_DEBUG
                printf("client=%s\n", inet_ntoa(cli_addr.sin_addr));
//#endif
            }
            // 如果有新的mac地址添加进来，则将其添加到ifc_list中
            if(FD_ISSET(recv_sock, &sock_set))
            {
                bzero(buf, BUF_SIZE);
                // 接收客户端传送过来的mac地址
                int rt_count = recv(recv_sock, buf, BUF_SIZE, 0);
                if(rt_count >= 17)
                {
                    u8 mac_addr[ETH_ALEN];
                    // 将AA：DD：DD：EE：DD：EA形式的硬件地址转换成网络地址
                    if(hwaddr_aton(buf, mac_addr) != -1)
                    {
                        // 获取ifc_list_lock锁，并将转换后的地址添加到ifc_list中
                        pthread_mutex_lock(&ifc_list_lock);
                        if(add_mac_addr(&ifc_list, mac_addr) == -1)
                        {
                            perror("fail to add the mac address!");
                        }
                        // 释放ifc_list_lock锁
                        pthread_mutex_unlock(&ifc_list_lock);
                    }
                }
                else if(rt_count == 0)
                {
                    close(recv_sock);
                    recv_sock = -1;
                }
            }
        }

    }
    return (void*)0;
}
/*
 * 查找指定的mac地址是否在accept_mac_array中。
 * 查找成功则返回0，失败则返回-1。
 */
int mac_auth_found(char* ifc_name, u8* src_mac_addr)
{
    if(!strcmp(ifc_name, ifc_list.ifc_name))
    {
        // 获取ifc_list_lock锁。
        pthread_mutex_lock(&ifc_list_lock);
        int i, is_found;
        is_found = 0;
        for(i = 0; i < ifc_list.mac_count; ++i)
        {
            // 从ifc_list中的mac_accept_array中查找对应的src_mac_addr地址
            if(memcmp(src_mac_addr, ifc_list.accept_mac_array[i].mac_addr, ETH_ALEN) == 0)
            {
                is_found = 1;
                break;
            }
        }
        // 释放ifc_list_lock锁
        pthread_mutex_unlock(&ifc_list_lock);
        // 如果能找到对应的mac地址则返回0，否则返回-1.
        if(is_found)
            return 0;
        else
            return -1;

    }
    else
        return -1;
}

