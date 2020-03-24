#pragma once
#define WIN32  
#define HAVE_REMOTE
#include"pcap.h"
#include<Packet32.h>
#include<ntddndis.h>
#include<iostream>
#include<time.h>
#pragma comment(lib,"Packet")
#pragma comment(lib,"wpcap")
#pragma comment(lib,"ws2_32")
using namespace std;

//用户数据报协议数据头
typedef struct udp_sport
{
	u_short sport;//源端口
	u_short dport;//目的端口
	u_short len;//数据包长度
	u_short crc;//校验和
}udp_header;

//IP地址（4个字节）
typedef struct ip_address 
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
};

//IP报头
typedef struct ip_header
{
	u_char	ver_ihl;		// 译文和因特网报头（各4bits）
	u_char	tos;			// 服务类型
	u_short tlen;			// 总长
	u_short identification; // 识别位，通过标识
	u_short flags_fo;		// 标志位（3bits）和 分段偏移（13bits）
	u_char	ttl;			// 存活周期
	u_char	proto;			// 拓扑类型
	u_short crc;			// 报头校验码
	ip_address	saddr;		// 源地址
	ip_address	daddr;		// 目的地址
	u_int	op_pad;			// 选择和填充
}ip_header;

class Dump
{
private:
	pcap_if_t* alldevs;
	pcap_if_t* d;
	int inum;
	int i = 0;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[255];
	struct bpf_program fcode;
public:
	Dump();
	void Run();
};
