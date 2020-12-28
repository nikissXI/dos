typedef unsigned char byte;   //一个字节
typedef unsigned short byte2; //两个字节
typedef unsigned int byte4;   //四个字节

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

//伪报头 12个字节
struct FAKE_HEADER
{
    byte4 ip_src;     //源地址(Source address)
    byte4 ip_dst;     //目的地址(Destination address)
    byte padding;     //填充
    byte proto;       //协议(Protocol)
    byte2 header_len; //IP报文长度
};