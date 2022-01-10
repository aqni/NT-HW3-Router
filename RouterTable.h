#ifndef ROUTER_TABLE_H
#define ROUTER_TABLE_H

#include <vector>
#include <stdio.h>
#include <stdint.h>
#include <iostream>
#include "MyThread.h"
#include "device.h"

struct RouterTableItem {
	uint32_t netid;
	uint32_t subnetMask;
	uint32_t nextHop;
};

class RouterTable
{
	public:
		void insertRouterTable(uint32_t netid,uint32_t subnetMask,uint32_t nextHop);
		void modifyRouterTable(size_t idx,uint32_t nextHop);
		void removeRouterTable(size_t idx);
		void fprintRouterTable(FILE* out)const;
		uint32_t findNextHop(uint32_t destip)const;
	private:
		std::vector<RouterTableItem> table;
		Mutex mutex;
};

inline bool operator<(const RouterTableItem& a,const RouterTableItem& b)
{
	return a.netid<b.netid || (a.netid==b.netid && a.subnetMask<b.subnetMask);
};

inline bool operator==(const RouterTableItem& a,const RouterTableItem& b)
{
	return (a.netid & a.subnetMask) ==(b.netid & b.subnetMask);
};

inline void RouterTable::insertRouterTable(uint32_t netid,uint32_t subnetMask,
    uint32_t nextHop)
{
	Guard g(mutex);
	RouterTableItem item;
	item.netid=netid&subnetMask;
	item.subnetMask=subnetMask;
	item.nextHop=nextHop;
	std::vector<RouterTableItem>::iterator curr=table.begin();
	std::vector<RouterTableItem>::iterator end=table.end();
	while(curr!=end && *curr<item) curr++;
	if(curr!=end && *curr==item) {
		*curr=item;
	} else {
		table.insert(curr,item);
	}
};

inline void RouterTable::modifyRouterTable(size_t idx,uint32_t nextHop)
{
	Guard g(mutex);
	if(idx<table.size()) {
		table[idx].nextHop=nextHop;
	}
}

inline void RouterTable::removeRouterTable(size_t idx)
{
	Guard g(mutex);
	if(idx<table.size()) {
		table.erase(table.begin() + idx);
	}
}

#define fprintAddr(out,dw) (fprintf(out,"%03d.%03d.%03d.%03d",(dw>>0)&0xFF,(dw>>8)&0xFF,(dw>>16)&0xFF,(dw>>24)&0xFF))
inline void RouterTable::fprintRouterTable(FILE* out) const
{
	Guard g(mutex);
	fprintf(out,"|----------------------- ROUTER TABLE ----------------------|\n");
	fprintf(out,"| No. | - NETWORK  ID - | - SUBNET MASK - | -- NEXT  HOP -- |\n");
	size_t size=table.size();
	for(size_t i=0; i<size; i++) {
		fprintf(out,"| %03d | ",i);
		fprintAddr(out,table[i].netid);
		fprintf(out," | ");
		fprintAddr(out,table[i].subnetMask);
		fprintf(out," | ");
		fprintAddr(out,table[i].nextHop);
		fprintf(out," |\n");
	}
}

inline uint32_t RouterTable::findNextHop(uint32_t destip) const
{
	Guard g(mutex);
	int size=table.size();
	for(int i=size-1; i>=0; i--) {
		if((destip&(table[i].subnetMask))==table[i].netid) {
			if(table[i].nextHop==0) {
				return destip;
			} else {
				return table[i].nextHop;
			}
		}
	}
	return 0;
}

#endif
