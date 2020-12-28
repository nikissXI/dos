typedef unsigned char byte;   //һ���ֽ�
typedef unsigned short byte2; //�����ֽ�
typedef unsigned int byte4;   //�ĸ��ֽ�

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

//α��ͷ 12���ֽ�
struct FAKE_HEADER
{
    byte4 ip_src;     //Դ��ַ(Source address)
    byte4 ip_dst;     //Ŀ�ĵ�ַ(Destination address)
    byte padding;     //���
    byte proto;       //Э��(Protocol)
    byte2 header_len; //IP���ĳ���
};