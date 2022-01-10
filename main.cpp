#include "RouterTable.h"
#include "Router.h"
#include "MyThread.h"
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include "device.h"
#include "utils.h"
#include "ArpTable.h"

using namespace std;

struct RouterControl {
	bool* stop;
	Router* router;
	ofstream *log;
};

unsigned __stdcall runRouter(void* vrc)
{
	RouterControl* rc=(RouterControl*)vrc;
	(rc->router)->run(*(rc->log),*(rc->stop));
	
};

void init(string&devName,RouterTable& table,vector<uint32_t>&ips);
void userUI(RouterTable& table,ArpTable& arps);

//implement a router on a stick
int main()
{
	printf("<<< ROUTER ON A STICK >>>\n\n");

	//init : get device name and router's table
	string devName;
	vector<uint32_t> ips;
	RouterTable table;
	init(devName,table,ips);
	
//	table.insertRouterTable(0x000301CE,0x00FFFFFF,0x020201CE);

	printf("\nAfter initialization, the router's table is as follows:\n");
	table.fprintRouterTable(stdout);
	printf("\n");

	//set arp table
	if(ips.empty()) {
		PANIC("This device is not configured with IP address!\n");
	}
	printf("initializing arp table...\n");
	ArpTable arps(ips[0],devName);
	printf("After initialization, the arp table is as follows:\n\n");
	arps.fprintfArpTable(stdout);

	//show local ip and mac
	printf("\nLocal information:\n");
	printf("- device name: %s\n",devName.c_str());
	cout<<"- local mac: "<<arps.get(ips[0])<<endl;
	printf("- all ip address:");
	for(size_t i=0; i<ips.size(); i++)
		cout<<" "<<IPv4Addr(ips[i]);
	printf("\n\n");

	//init router
	printf("initializing router...\n");
	Router router(devName,table,arps,ips);

	//open log file
	printf("initializing log file...\n");
	ofstream logFile("route.log");
	printf("log will be written in 'route.log'.\n");

	//create new thread to run router
	printf("initializing new thread...\n");
	bool stop=false;
	RouterControl rc;
	rc.log=&logFile;
	rc.router=&router;
	rc.stop=&stop;
	MyThread thrd(runRouter,&rc);
	printf("Router launched.\n");

	//user control
	userUI(table,arps);

	//stop and exit
	stop=true;
	thrd.join();
}

inline uint32_t conbine(uint32_t bytes[4])
{
	return  (bytes[0])&0x000000FF
	        |(bytes[1]<<8)&0x0000FF00
	        |(bytes[2]<<16)&0x00FF0000
	        |(bytes[3]<<24)&0xFF000000;
}

void userUI(RouterTable& table,ArpTable& arps)
{
	printf("Launch user's ui, enter '?' for help.\n");
	char line[0xFF];
	while(true) {
		/* enter a line */
		fgets(line,sizeof(line),stdin);
		char op='e';
		if(EOF!=sscanf(line,"%c",&op)) {
			uint32_t netids[4]= {0};
			uint32_t mask[4]= {0};
			uint32_t nexthop[4]= {0};
			size_t tableno;
			size_t linelen=strlen(line);
			switch(op) {
				case 'i': /* insert */
					sscanf(line,
					       "%c %d.%d.%d.%d %d.%d.%d.%d %d.%d.%d.%d",&op,
					       &(netids[0]),&(netids[1]),&(netids[2]),&(netids[3]),
					       &(mask[0]),&(mask[1]),&(mask[2]),&(mask[3]),
					       &(nexthop[0]),&(nexthop[1]),&(nexthop[2]),&(nexthop[3]));
					table.insertRouterTable(conbine(netids),conbine(mask),conbine(nexthop));
					break;
				case 'r': /* remove */
					sscanf(line,"%c %d",&op,&tableno);
					table.removeRouterTable(tableno);
					break;
				case 'm': /* modify */
					sscanf(line,"%c %d %d.%d.%d.%d",
					       &op,&tableno,&(nexthop[0]),&(nexthop[1]),&(nexthop[2]),&(nexthop[3]));
					table.modifyRouterTable(tableno,conbine(nexthop));
					break;
				case 't': /* show table */
					table.fprintRouterTable(stdout);
					break;
				case 'a': /* show arps */
					arps.fprintfArpTable(stdout);
					break;
				case 's': /* stop router */
					return;
				case '?':
					printf("[UI]: input format:\n");
					printf("  ? --- get help\n");
					printf("  s --- stop router and exit\n");
					printf("  t --- show router table\n");
					printf("  a --- show arp table\n");
					printf("  i <network id> <subnet mask> <next hop> --- add table item\n");
					printf("  r <table No.> --- remove table item\n");
					printf("  m <table No.> <next hop> --- modify table item\n");
					break;
				default:
					printf("[UI]:input syntax error!\n");
					break;
			}
		} else {
			printf("[UI]:input syntax error!\n");
		}
	}
}

void init(string&devName,RouterTable& table,vector<uint32_t>&ips)
{
	//print device name and ipv4 address
	pcap_if_t *alldevs= find_alldevs();
	printf("All device on local host:\n");
	int num = 0;
	for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
		printf( "[%d]:\t%s\n" ,num++ , d->description);
		printf("\tname: %s\n",d->name);
		for (pcap_addr_t *a = d->addresses; a != NULL; a = a->next) {
			if (a->addr->sa_family == AF_INET) { //是IPv4地址则，
				printf("\t-----------------\n");
				if (a->addr) //地址
					cout <<"\taddress:             "<< IPv4Addr(((struct sockaddr_in *)
					     a->addr)->sin_addr.s_addr) << endl;
				if (a->netmask) //网络掩码
					cout <<"\tnetmask:             "<< IPv4Addr(((struct sockaddr_in *)
					     a->netmask)->sin_addr.s_addr) << endl;
				if (a->broadaddr) //广播地址
					cout <<"\tbroadcast_address:   "<< IPv4Addr(((struct sockaddr_in *)
					     a->broadaddr)->sin_addr.s_addr) << endl;
				if (a->dstaddr) //目的地址
					cout <<"\tdestination_address: "<< IPv4Addr(((struct sockaddr_in *)
					     a->dstaddr)->sin_addr.s_addr) << endl;
			}
		}
	}
	printf("\n");
	//user select the device
	int select_no = -1;
	while (!(0 <= select_no && select_no < num)) {
		cout << "Which device do you choose to use for the router?[0,"<< num << ")";
		cin >> select_no;
		cin.get();
	}
	pcap_if_t* selectDev=alldevs;
	for (int i = 0; i < select_no; i++) {
		if (selectDev == NULL)
			break;
		selectDev = selectDev->next;
	}

	//init devName and RouterTable
	devName=selectDev->name;
	for (pcap_addr_t *a = selectDev->addresses; a != NULL; a = a->next) {
		if (a->addr->sa_family == AF_INET && a->addr &&a->netmask) {
			uint32_t addr=((struct sockaddr_in *)a->addr)->sin_addr.s_addr;
			uint32_t netmask=((struct sockaddr_in *)a->netmask)->sin_addr.s_addr;
			table.insertRouterTable(addr,netmask,0);
			ips.push_back(addr);
		}
	}
}
