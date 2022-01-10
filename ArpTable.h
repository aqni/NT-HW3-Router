#ifndef ARP_TABLE_H
#define ARP_TABLE_H
#include "device.h"
#include "MyThread.h"
#include <stdint.h>
#include <map>

#pragma pack(1)
struct ARPFrame {
	FrameHeader frameHeader;
	uint16_t hardwareType;
	uint16_t protocolType;
	uint8_t hLen;
	uint8_t pLen;
	uint16_t operation;
	Mac sendHA;
	IPv4Addr sendIP;
	Mac recvHA;
	IPv4Addr recvIP;
	ARPFrame(uint32_t reqIP, uint32_t myIP, Mac myMAC);
};
#pragma pack()

using std::map;
using std::pair;
using std::string;
using std::multimap;

class Router;

struct CachePkg
{
	iphdr_s* pkg;
	size_t size;
	Router* router;
	time_t time;
};

class ArpTable
{
	public:
		ArpTable(uint32_t myip,const std::string& devName);
		~ArpTable();
		Mac get(uint32_t targetip);
		void fprintfArpTable(FILE* out);
		void reponseMac(Router* router,iphdr_s* data,size_t size,uint32_t dstip);
		void setArp(uint32_t ip,Mac mac);
	private:
		static Mac getMac(pcap_t *dev,uint32_t targetip,uint32_t myip, Mac mymac);
		static void setFilter(pcap_t *dev,uint32_t targetip);
        static void setFilter(pcap_t *dev);
		static unsigned __stdcall runArp(void* arps);
	private:
		multimap<uint32_t,CachePkg> cache;
		map<uint32_t,Mac> addr2mac;
		map<uint32_t,time_t> age;
		string devName;
		uint32_t myip;
		Mac mymac;
		pcap_t* dev;
		Mutex mutex;
		Mutex mutex2;
		MyThread thrd;
		bool stop;
};

#endif
