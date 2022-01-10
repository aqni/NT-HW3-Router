#include "ArpTable.h"
#include "device.h"
#include "utils.h"
#include "Router.h"
#include <sstream>
#include <string.h>
#include <time.h>

using namespace std;

ARPFrame::ARPFrame(uint32_t reqIP, uint32_t myIP, Mac myMAC)
{
	memset(frameHeader.desMAC.addr,0xFF,sizeof(frameHeader.desMAC));  /* 广播地址 */
	frameHeader.srcMAC=myMAC;
	frameHeader.frameType=0x0608;                                /* 帧类型为ARP */
	hardwareType=
	  0x0100;                                         /* 硬件类型为以太网 */
	protocolType=0x0008;                                         /* 协议类型为IP */
	hLen=6;                                                      /* 硬件地址长度为6 */
	pLen=4;                                                      /* 协议地址长度为4 */
	operation=0x0100;                                            /* 操作为ARP请求 */
	sendHA=myMAC;                                                /* 源MAC为本地MAC */
	sendIP.addr=myIP;                                            /* 源IP为本地IP */
	memset(recvHA.addr,0,sizeof(recvHA));                             /* 设为0 */
	recvIP.addr=
	  reqIP;                                           /* 目的IP为查询IP */
};

IPv4Addr va(0x7A7A7A7A);
Mac vm(0x66);


ArpTable::ArpTable(uint32_t myip,const std::string& devName)
	:myip(myip),stop(false)
{
	pcap_t* tempdev=open_dev(devName);
	mymac=getMac(tempdev,myip,va.addr,vm);
	if(!mymac.isValid()) {
		PANIC("failed to get local mac!");
	}
	addr2mac[myip]=mymac;
	pcap_close(tempdev);
	dev=open_dev(devName);
	MyThread temp(runArp,this);
	thrd.swap(temp);
}

ArpTable::~ArpTable()
{
	stop=true;
	thrd.join();

	/* delete pkg */
	multimap<uint32_t,CachePkg>::iterator m,beg,end;
	beg = cache.begin();
	end = cache.end();
	for(m = beg; m != end; m++) {
		const CachePkg &pkg=m->second;
		delete[](char*)(m->second.pkg);
	}

	pcap_close(dev);
}

#define AGED 6000
Mac ArpTable::get(uint32_t targetip)
{
	Guard g(mutex);
	if(addr2mac.count(targetip)!=0) {
		if(age.count(targetip)==0||age[targetip]+AGED>time(NULL)) {
			return addr2mac[targetip];
		}
	}

	ARPFrame reqMac(targetip, myip, mymac);
	if (0 != pcap_sendpacket(dev, (u_char *)&reqMac, sizeof(reqMac))) {
		PANIC("send arp err!");
	}
	return Mac();
}

unsigned __stdcall ArpTable::runArp(void* arps)
{
	printf("arp table opened.");
	ArpTable* me=(ArpTable*)arps;
	ArpTable::setFilter(me->dev);
	struct pcap_pkthdr *pkthdr = NULL;
	const u_char *rawdata = NULL;
	while (!me->stop) {
		if (1 != pcap_next_ex(me->dev, &pkthdr, &rawdata)) {
			continue;
		}

		ARPFrame *arp = (ARPFrame *)rawdata;
		if (arp->frameHeader.frameType == 0x0608 /*htons(0x0806)*/ &&
		    /* 必须是arp包 */
		    arp->operation == 0x0200/*htons(0x0002)*/ &&
		    /* 必须是arp应答 */
		    /* 必须是查询IP的应答 */
		    arp->sendIP.addr != me->myip) { /* 不是刚刚发出的包 */

			Guard g(me->mutex2);
			//updata arp table
			uint32_t ip=arp->sendIP.addr;
			me->setArp(ip,Mac(arp->sendHA));

			//flush cache
			multimap<uint32_t,CachePkg>::iterator m,beg,end;
			beg = me->cache.lower_bound(ip);
			end = me->cache.upper_bound(ip);
			for(m = beg; m != end; m++) {
				const CachePkg &pkg=m->second;
				pkg.router->deliver(pkg.pkg,pkg.size,ip);
				delete[]((char*)pkg.pkg);

			}
			me->cache.erase(ip);
		}
	}
	printf("arp table closed.\n");
}

void ArpTable::setArp(uint32_t ip,Mac mac)
{
	Guard g(mutex);
	addr2mac[ip]=mac;
	age[ip]=time(NULL);
}

Mac ArpTable::getMac(pcap_t *dev,uint32_t targetip,uint32_t myip, Mac mymac)
{
	setFilter(dev,targetip);
	ARPFrame reqMac(targetip, myip, mymac);
	if (0 != pcap_sendpacket(dev, (u_char *)&reqMac, sizeof(reqMac))) {
		PANIC("send arp err!");
	}
	struct pcap_pkthdr *pkthdr = NULL;
	const u_char *rawdata = NULL;
	int n = 1;
	while (n-- > 0) {
		if (1 != pcap_next_ex(dev, &pkthdr, &rawdata))
			continue;
		ARPFrame *arp = (ARPFrame *)rawdata;
		if (arp->frameHeader.frameType == 0x0608 /*htons(0x0806)*/ &&
		    /* 必须是arp包 */
		    arp->operation == 0x0200/*htons(0x0002)*/ &&
		    /* 必须是arp应答 */
		    arp->sendIP.addr == targetip &&
		    /* 必须是查询IP的应答 */
		    arp->sendIP.addr != myip) { /* 不是刚刚发出的包 */
			return arp->sendHA;
		}
	}
	return Mac();
}

void ArpTable::setFilter(pcap_t *dev,uint32_t targetip)
{
	IPv4Addr reqIP(targetip);
	ostringstream filterCondition;
	filterCondition
	    << "arp and (ether[21]=0x2) and (arp host "
	    << reqIP<<")";
	string str = filterCondition.str();
	struct bpf_program filter;

	if (pcap_compile(dev, &filter, str.c_str(), 1, 0) < 0) {
		PANIC("Unable to compile the packet filter. Check the syntax.");
	}
	if (pcap_setfilter(dev, &filter) < 0) {
		PANIC("\nError setting the filter.\n");
	}
}

void ArpTable::setFilter(pcap_t *dev)
{
	const char condition[]="arp and (ether[21]=0x2)";
	struct bpf_program filter;
	if (pcap_compile(dev, &filter, condition, 1, 0) < 0) {
		PANIC("Unable to compile the packet filter. Check the syntax.");
	}
	if (pcap_setfilter(dev, &filter) < 0) {
		PANIC("\nError setting the filter.\n");
	}
}

#define fprintAddr(out,dw) (fprintf(out,"%03d.%03d.%03d.%03d",(dw>>0)&0xFF,(dw>>8)&0xFF,(dw>>16)&0xFF,(dw>>24)&0xFF))
void ArpTable::fprintfArpTable(FILE* out)
{
	Guard g(mutex);
	fprintf(out,"|-------------- ARP TABLE -------------|\n");
	for(std::map<uint32_t,Mac>::const_iterator it=addr2mac.begin() ;
	    it!=addr2mac.end(); it++) {
		fprintf(out,"| ");
		fprintAddr(out,it->first);
		fprintf(out," -> ");
		const uint8_t *sm= it->second.addr;
		fprintf(out, "%02X:%02X:%02X:%02X:%02X:%02X", sm[0], sm[1], sm[2], sm[3], sm[4],
		        sm[5]);
		fprintf(out," |\n");
	}
}

#define OVER_TIME 10
void ArpTable::reponseMac(Router* router,iphdr_s* data,size_t size,
                          uint32_t dstip)
{
	Guard g(mutex2);
	if(get(dstip).isValid()) {
		//缓存时已经得到mac结果
		Guard g(mutex);
		age[dstip]=0;
		get(dstip);
	}
	char* mydata=new char[size];
	memcpy(mydata,data,size);
	CachePkg pkg= {(iphdr_s*)mydata,size,router,time(NULL)};
	cache.insert(make_pair(dstip,pkg));

	//delete timeout cache

	multimap<uint32_t,CachePkg>::iterator m,beg,end;
	beg = cache.begin();
	end = cache.end();
	time_t t=time(NULL);
	for(m = beg; m != end;) {
		const CachePkg &pkg=m->second;
		if(pkg.time+OVER_TIME<t) {
			delete[](char*)(pkg.pkg);
			cache.erase(m++);
		} else {
			m++;
		}
	}
}

