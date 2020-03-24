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

//�û����ݱ�Э������ͷ
typedef struct udp_sport
{
	u_short sport;//Դ�˿�
	u_short dport;//Ŀ�Ķ˿�
	u_short len;//���ݰ�����
	u_short crc;//У���
}udp_header;

//IP��ַ��4���ֽڣ�
typedef struct ip_address 
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
};

//IP��ͷ
typedef struct ip_header
{
	u_char	ver_ihl;		// ���ĺ���������ͷ����4bits��
	u_char	tos;			// ��������
	u_short tlen;			// �ܳ�
	u_short identification; // ʶ��λ��ͨ����ʶ
	u_short flags_fo;		// ��־λ��3bits���� �ֶ�ƫ�ƣ�13bits��
	u_char	ttl;			// �������
	u_char	proto;			// ��������
	u_short crc;			// ��ͷУ����
	ip_address	saddr;		// Դ��ַ
	ip_address	daddr;		// Ŀ�ĵ�ַ
	u_int	op_pad;			// ѡ������
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
