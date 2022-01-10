#ifndef ROUTER_H
#define ROUTER_H

#include <string>
#include <iostream>
#include "RouterTable.h"
#include "device.h"
#include "ArpTable.h"

using std::string;
using std::ostream;
using std::vector;



uint16_t checksum(uint16_t *words,size_t len);

class Router
{
	public:
		Router(const string& devName,const RouterTable& table,ArpTable& arps,
		       vector<uint32_t>& ips);
		~Router();
		void run(ostream &log,bool& stop);
  bool deliver(iphdr_s* data,size_t size,uint32_t dstip);
	private:
		void setFilter();
		std::pair<iphdr_s*,size_t> getIPPkg();
		void ICMPTimeout(icmp_s* icmp,const iphdr_s* pkg);
	private:
		const RouterTable& table;
		ArpTable& arps;
		std::ostream& log;
		pcap_t *dev;
		std::vector<uint32_t> ips;
		IPv4Addr myip;
		Mac mymac;
 		Mutex mutex;
};

#endif
