#ifndef DEVICE_H
#define DEVICE_H

#include "pcap.h"
#include <stdio.h>
#include <string>
#include <iostream>


#pragma pack(1)
typedef struct frame_header {
	uint8_t des_mac[6];  //目的MAC地址
	uint8_t src_mac[6];  //源MAC地址
	uint16_t frame_type; //帧类型
} frmhdr_s;

typedef struct ip_header {
	frmhdr_s frmhdr;
	uint8_t ver_hlen;
	uint8_t tos;
	uint16_t total_len;
	uint16_t id;
	uint16_t flags;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t check_sum;
	uint32_t src_ip;
	uint32_t des_ip;
} iphdr_s;

typedef struct icmp_pkg {
	iphdr_s iphdr;
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	uint32_t other;
	uint8_t data[sizeof(iphdr_s)-sizeof(frmhdr_s)+8];
} icmp_s;

union IPv4Addr {
	uint32_t addr;
	uint8_t bytes[4];
	IPv4Addr() {
		addr=0;
	}
	IPv4Addr(uint32_t a) : addr(a) {}
};

struct Mac {
	uint8_t addr[6];
	Mac() {
		addr[0]=addr[1]=addr[2]=addr[3]=addr[4]=addr[5]=0;
	}
	Mac(uint8_t b) {
		addr[0]=addr[1]=addr[2]=addr[3]=addr[4]=addr[5]=b;
	}
	Mac(uint8_t a[]){
		memcpy(addr,a,6);
	}
	bool isValid() {
		return (addr[0] |addr[1] |addr[2] |addr[3] |addr[4] |addr[5]);
	}
};

struct FrameHeader {
	Mac desMAC;         //目的MAC地址
	Mac srcMAC;         //源MAC地址
	uint16_t frameType; //帧类型
};

#pragma pack()

pcap_if_t* find_alldevs();

pcap_t* open_dev(const std::string& name);

std::ostream &operator<<(std::ostream &out, const IPv4Addr &ip);
std::ostream &operator<<(std::ostream &out, const Mac &mac);

#endif
