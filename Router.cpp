#include "Router.h"
#include <string>
#include <sstream>
#include <stdint.h>
#include <algorithm>
#include "device.h"
#include "utils.h"

using namespace std;

Router::Router(const string& devName,const RouterTable& table,ArpTable& arps,
               vector<uint32_t>& ips)
	:table(table),arps(arps),log(log),ips(ips)
{
	mymac=arps.get(ips[0]);
	dev=open_dev(devName);
	setFilter();
}

Router::~Router()
{
	pcap_close(dev);
}

void Router::setFilter()
{
	ostringstream filterCondition;
	filterCondition<< "ip and (ether dst "<<mymac<<")";
	string str = filterCondition.str();
	bpf_program filter;
	
	if (pcap_compile(dev, &filter, str.c_str(), 1, 0) < 0) {
		PANIC("Unable to compile the packet filter. Check the syntax.");
	}
	if (pcap_setfilter(dev, &filter) < 0) {
		PANIC("\nError setting the filter.\n");
	}
}

void Router::run(ostream &log, bool&stop)
{
	while(!stop) {
		pair<iphdr_s*,size_t> ipPkg=getIPPkg();
		if(ipPkg.first==NULL) continue;
		iphdr_s* iphdr=ipPkg.first;
		size_t pkgsize=ipPkg.second;
		
		log<<"[recv]:\t"
		   <<"{src-ip:"<<IPv4Addr(iphdr->src_ip)
		   <<" dst-ip:"<<IPv4Addr(iphdr->des_ip)
		   <<" src-mac:"<<Mac(iphdr->frmhdr.src_mac)
		   <<" dst-mac:"<<Mac(iphdr->frmhdr.des_mac)
		   <<"}"<<endl;

		/* check sum */
		uint16_t *words = (uint16_t *)&(iphdr->ver_hlen);
		size_t len = (sizeof(iphdr_s)-sizeof(frmhdr_s)) / sizeof(uint16_t);
		if(checksum(words,len)) {
			log<<"[warn]:\tdiscard (checksum ne 0)!"<<endl;
			continue;
		}

		/* judge ttl */
		if(iphdr->ttl-1>0) { //route pkg
			if(find(ips.begin(),ips.end(),iphdr->des_ip)!=ips.end()){
				// dst ip is me
				continue;
			}
			iphdr->ttl--;
			uint32_t nextHop=table.findNextHop(iphdr->des_ip);
			if(nextHop==0) { //no table item
				log<<"[warn]:\tdiscard (lack of tableItem of "<<IPv4Addr(
				     iphdr->des_ip)<<")"<<endl;
				continue;
			}
			if(!deliver(iphdr,pkgsize,nextHop)) {
				log<<"[warn]:\tcahced ip package (fail to get mac)!"<<endl;
				continue;
			}
			log<<"[rout]:\t{ip dst "<<IPv4Addr(iphdr->des_ip)<<"} -> {host "<<IPv4Addr(
			     nextHop)<<"}"<<endl;
		} else { //send icmp
			icmp_s icmp;
			ICMPTimeout(&icmp,iphdr);
			uint32_t nextHop=table.findNextHop(icmp.iphdr.des_ip);
			if(nextHop==0) { //no table item
				log<<"[warn]:\tdiscard (lack of tableItem of "<<IPv4Addr(
				     iphdr->des_ip)<<")"<<endl;
				continue;
			}
			if(!deliver((iphdr_s*)&icmp,sizeof(icmp),nextHop)) {
				log<<"[warn]:\tcahced icmp (fail to get mac)!"<<endl;
				continue;
			}
			log<<"[icmp]:\t{timeout dst "<<IPv4Addr(iphdr->des_ip)<<"} -> {host "<<IPv4Addr(
			     icmp.iphdr.des_ip)<<"}"<<endl;
		}
	}
}

pair<iphdr_s*,size_t> Router::getIPPkg()
{
	struct pcap_pkthdr *pkthdr = NULL;
	const u_char *rawdata = NULL;
	while (true) {
		int capret = pcap_next_ex(dev, &pkthdr, &rawdata);
		if (1 == capret) {
			if(pkthdr->caplen==pkthdr->len) {
				return make_pair((iphdr_s*)rawdata,(size_t)pkthdr->len);
			} else {
				return make_pair((iphdr_s*)NULL,0);
			}
		} else if (0 == capret) {
			return make_pair((iphdr_s*)NULL,0);
		} else if (-1 == capret) {
			PANIC("Error when capturing!");
		} else {
			PANIC("pcap_next_ex() return unexpected errcode when capturing!");
		}
	}
}

bool Router::deliver(iphdr_s* data,size_t size,uint32_t dstip)
{
	Guard g(mutex);
	Mac dstmac=arps.get(dstip);
	if(!dstmac.isValid()){
		arps.reponseMac(this,data,size,dstip); //cache pkg
        return false;
	}
	memcpy(data->frmhdr.des_mac,dstmac.addr,6);
	memcpy(data->frmhdr.src_mac,mymac.addr,6);

	/* recalculate checksum */
	data->check_sum=0;
	uint16_t *words = (uint16_t *)&(data->ver_hlen);
	size_t len = (sizeof(iphdr_s)-sizeof(frmhdr_s)) / sizeof(uint16_t);
	data->check_sum=checksum(words,len);

	/* send pkg */
	if (0 != pcap_sendpacket(dev, (u_char *)data, size)) {
		PANIC("Send pkg err!");
	}

	return true;
}

void Router::ICMPTimeout(icmp_s* icmp,const iphdr_s* pkg)
{
	/* set icmp data */
	memcpy(icmp->data,&(pkg->ver_hlen),sizeof(icmp->data));
	icmp->type=11;
	icmp->code=0;
	icmp->other=0;
	icmp->checksum=0;

	uint16_t *words1 = (uint16_t *)&(icmp->type);
	size_t len1 = (sizeof(icmp_s)-sizeof(iphdr_s)) / sizeof(uint16_t);
	icmp->checksum=checksum(words1,len1);

	/* set ip data */
	icmp->iphdr.frmhdr.frame_type=0x0008;
	icmp->iphdr.ver_hlen=0x45;
	icmp->iphdr.tos=0;
	icmp->iphdr.total_len=swapByteOrder(sizeof(icmp_s)-sizeof(frmhdr_s));
	icmp->iphdr.id=0xFFFF;
	icmp->iphdr.flags=0;
	icmp->iphdr.ttl=0xFF;
	icmp->iphdr.protocol=1;
	icmp->iphdr.check_sum=0;
	icmp->iphdr.des_ip=pkg->src_ip;
	icmp->iphdr.src_ip=ips[0];

	uint16_t *words = (uint16_t *)&(icmp->iphdr.ver_hlen);
	size_t len = (sizeof(iphdr_s)-sizeof(frmhdr_s)) / sizeof(uint16_t);
	icmp->iphdr.check_sum=checksum(words,len);
}

uint16_t checksum(uint16_t *words,size_t len)
{
	uint32_t checksum = 0;
	for (int i = 0; i < len; i++)
		checksum += swapByteOrder(words[i]);
	//未考虑可选长度
	checksum = (checksum >> 16) + (checksum & 0x0000FFFF);
	checksum = (checksum >> 16) + checksum;
	return swapByteOrder((uint16_t)~checksum);
}
