#include "device.h"
#include "pcap.h"
#include "utils.h"
#include <iomanip>
using namespace std;

pcap_if_t* find_alldevs()
{
	pcap_if_t *alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];
	if (-1 == pcap_findalldevs_ex(PCAP_SRC_IF_STRING, //获取本机的设备接口
	                              NULL,               //无须认证
	                              &alldevs,           //指向设备列表首部
	                              errbuf)) {          //出错信息保存缓存区
		//输出错误原因，并退出
		PANIC("Error in pcap_findalldevs_ex: %s\n", errbuf);
	}
	return alldevs;
}

pcap_t* open_dev(const std::string& name)
{
	char errbuf[PCAP_ERRBUF_SIZE] = {0};
	pcap_t *captureDevice = pcap_open(name.c_str(),
	                                  0xFFFF, /*用于捕获ARP包*/
	                                  PCAP_OPENFLAG_PROMISCUOUS,
	                                  10, /*超时*/
	                                  NULL,
	                                  errbuf);
	if (NULL == captureDevice) {
		fprintf(stderr,"Can not open decive:%s", errbuf);
		exit(EXIT_FAILURE);
	}

}

ostream &operator<<(std::ostream &out, const IPv4Addr &ip)
{
	out << (int)ip.bytes[0] << "."
	    << (int)ip.bytes[1] << "."
	    << (int)ip.bytes[2] << "."
	    << (int)ip.bytes[3];
	return out;
}

std::ostream &operator<<(std::ostream &out, const Mac &mac)
{
	out << setfill('0') << setw(2) << setiosflags(ios::uppercase) << hex <<
	    (int)mac.addr[0] << ":"
	    << setfill('0') << setw(2) << setiosflags(ios::uppercase) << hex <<
	    (int)mac.addr[1] << ":"
	    << setfill('0') << setw(2) << setiosflags(ios::uppercase) << hex <<
	    (int)mac.addr[2] << ":"
	    << setfill('0') << setw(2) << setiosflags(ios::uppercase) << hex <<
	    (int)mac.addr[3] << ":"
	    << setfill('0') << setw(2) << setiosflags(ios::uppercase) << hex <<
	    (int)mac.addr[4] << ":"
	    << setfill('0') << setw(2) << setiosflags(ios::uppercase) << hex <<
	    (int)mac.addr[5] << dec;
	return out;
}

