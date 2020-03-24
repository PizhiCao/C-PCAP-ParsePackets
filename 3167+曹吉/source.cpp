#include"head.h"
#pragma warning(disable:4996)
Dump::Dump()
{
		
	alldevs = NULL;
	d = NULL;
	inum = 0;
	i = 0;
	adhandle = NULL;
	netmask = 0;
	char b[] = "ip and udp";
	strcpy(packet_filter, b);
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Pcap_findalldevs error!: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return ;
	}

	cout << "Enter the interface number (1-" <<i<<"):";
	cin >> inum;
	
}
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	struct tm* ltime;
	char timestr[16];
	ip_header* ih;
	udp_header* uh;
	u_int ip_len;
	u_short sport, dport;
	time_t local_tv_sec;
	(VOID)(param);
	//将时间戳转换为可读格式
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
	//打印数据包的时间戳和长度
	printf("%s.%.6d len:%d \n", timestr, header->ts.tv_usec, header->len);

	//重新设置ip报头的位置
	ih = (ip_header*)(pkt_data +14); //以太网报头长度

	//重新设置udp报头的位置
	ip_len = (ih->ver_ihl & 0xf) * 4;
	uh = (udp_header*)((u_char*)ih + ip_len);

	//将网络字节顺序转换为主机字节顺序
	sport = ntohs(uh->sport);
	dport = ntohs(uh->dport);

	//打印ip地址和udp端口
	printf("ip_header\n");
	printf("\t%-10s: %02X\n", "ver_ihl", ih->ver_ihl);
	printf("\t%-10s: %02X\n", "tos", ih->tos);
	printf("\t%-10s: %04X\n", "tlen", ntohs(ih->tlen));
	printf("\t%-10s: %04X\n", "identification", ntohs(ih -> identification));
	printf("\t%-10s: %04X\n", "flags_fo", ntohs(ih->flags_fo));
	printf("\t%-10s: %02X\n", "ttl", ih->ttl);
	printf("\t%-10s: %02X\n", "proto", ih->proto);
	printf("\t%-10s: %04X\n", "crc", ntohs(ih->crc));
	printf("\t%-10s: %08X\n", "op_pad", ntohs(ih->op_pad));
	printf("\t%-10s: ", "saddr:");
	printf("%d.%d.%d.%d.%d -> %d.%d.%d.%d.%d\n",
		ih->saddr.byte1,
		ih->saddr.byte2,
		ih->saddr.byte3,
		ih->saddr.byte4,
		sport,
		ih->daddr.byte1,
		ih->daddr.byte2,
		ih->daddr.byte3,
		ih->daddr.byte4,
		dport);
}
void Dump::Run()
{

	//检查是否指定了有效的适配器
	if (inum < 1 || inum > i)
	{
		printf("\nAdapter number out of range.\n");

		//释放设备列表
		pcap_freealldevs(alldevs);
		return ;
	}

	//跳转到所选的适配器
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	//打开适配器
	if ((adhandle = pcap_open_live(d->name,	65536,1,1000,errbuf)) == NULL)// 设备名称
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return ;
	}

	//检查链接层 
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		pcap_freealldevs(alldevs);
		return ;
	}

	if (d->addresses != NULL)
		//检索接口的第一个地址的掩码
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else netmask = 0xffffff;


	//编译过滤器
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		pcap_freealldevs(alldevs);
		return ;
	}

	//设置过滤器
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		pcap_freealldevs(alldevs);
		return ;
	}

	printf("\nlistening on %s...\n", d->description);

	//释放多余的设备列表
	pcap_freealldevs(alldevs);

	//开始捕获
	pcap_loop(adhandle, 0, packet_handler, NULL);
}

int main()
{
	Dump dump;
	dump.Run();
}