#include "ProcessMonitor.h"
#include "netutils.h"
#include "model/ConnDataObj.h"
#include <stdio.h>
#include <QDebug>
#include <QLabel>
#include <iostream>
#include <QTimer>
#include <QThread>
#include <unordered_map>

ProcessMonitor::ProcessMonitor(QWidget *parent)
    : QWidget(parent)
{
    ui.setupUi(this);
	auto layout = new QVBoxLayout(this);
	auto tableViewTcp = new QTableView();

	model.setMapDelegate(&portBytes_map);
	udpModel.setMapDelegate(&portBytes_map);

	tableViewTcp->setModel(&model);

	auto tableViewUdp = new QTableView();
	tableViewUdp->setModel(&udpModel);
	auto tcpLabel = new QLabel();
	auto udpLabel = new QLabel();
	tcpLabel->setText("TCP endpoints");
	udpLabel->setText("UDP endpoints");

	layout->addWidget(tcpLabel);
	layout->addWidget(tableViewTcp);
	layout->addWidget(udpLabel);
	layout->addWidget(tableViewUdp);

	configureApis();

	std::thread tcpPollThread{ [this] {
			while (1) {
				updateTcpTable();
				std::this_thread::sleep_for(std::chrono::milliseconds(1000));
			} 
		}
	};

	std::thread udpPollThread{ [this] {
			while (1) {
				updateUdpTable();
				std::this_thread::sleep_for(std::chrono::milliseconds(1000));
			}
		}
	};

	tcpPollThread.detach();
	udpPollThread.detach();

	runtxmonitor(); // this is also in a thread
}

void ProcessMonitor::configureApis()
{
	WORD wVersionRequested;
	WSADATA wsaData;
	wVersionRequested = MAKEWORD(2, 2);

	WSAStartup(wVersionRequested, &wsaData);
}

void ProcessMonitor::updateTcpTable() {
	PMIB_TCPTABLE_OWNER_MODULE pTcpTable = nullptr;
    DWORD dwSize = sizeof(MIB_TCPTABLE_OWNER_MODULE);
    DWORD dwRetValue = 0;
    std::vector<ConnDataObj> tcpList;
	
	do {
		pTcpTable = (PMIB_TCPTABLE_OWNER_MODULE)realloc(pTcpTable, dwSize);
		dwRetValue = GetExtendedTcpTable(pTcpTable, &dwSize, true, AF_INET, TCP_TABLE_OWNER_MODULE_ALL, 0);
	} while (dwRetValue == ERROR_INSUFFICIENT_BUFFER); //api idiom

	if (dwRetValue != ERROR_SUCCESS) {
		qDebug() << dwRetValue;
		return;
	}
	if (pTcpTable == nullptr) {
		qDebug() << "How null?";
		return;
	}
        
    for (int i = 0; i < pTcpTable->dwNumEntries; i++)
    {
        ConnDataObj tcpConnItem = ConnDataObj();
        MIB_TCPROW_OWNER_MODULE tcpRow = pTcpTable->table[i];

        tcpConnItem.pid = tcpRow.dwOwningPid;
        tcpConnItem.localAddr = getIpStringFromDword(tcpRow.dwLocalAddr);
        tcpConnItem.localPort = ntohs(tcpRow.dwLocalPort);
			
		struct servent* servLoc, *servRem;
		servLoc = getservbyport(tcpRow.dwLocalPort, nullptr);
		servRem = getservbyport(tcpRow.dwRemotePort, nullptr);

		if (servLoc == nullptr) {
			tcpConnItem.localProto = "";
		}
		else {
			tcpConnItem.localProto = servLoc->s_name;
		}

		if (servRem == nullptr) {
			tcpConnItem.remoteProtocol = "";
		}
		else {
			tcpConnItem.remoteProtocol = servRem->s_name;
		}

        tcpConnItem.remoteAddr = getIpStringFromDword(tcpRow.dwRemoteAddr);
		tcpConnItem.remotePort = ntohs(tcpRow.dwRemotePort);
		
		TCPIP_OWNER_MODULE_BASIC_INFO *ownerInfo = nullptr;
		DWORD ownerInfoSize = sizeof(TCPIP_OWNER_MODULE_BASIC_INFO);

		do {
			ownerInfo = (TCPIP_OWNER_MODULE_BASIC_INFO*)realloc(ownerInfo, ownerInfoSize);
			dwRetValue = GetOwnerModuleFromTcpEntry(&tcpRow, TCPIP_OWNER_MODULE_INFO_BASIC, ownerInfo, &ownerInfoSize);
		} while (dwRetValue == ERROR_INSUFFICIENT_BUFFER);

		if (dwRetValue == ERROR_SUCCESS) {
			std::wstring wProcName(ownerInfo->pModuleName);
			tcpConnItem.procName = std::string(wProcName.begin(), wProcName.end());
		}else {
			tcpConnItem.procName = "System Idle";
		}

		tcpList.push_back(tcpConnItem);
		NetworkTrafficHelper& ref = portBytes_map[tcpConnItem.localPort];
		auto cts = time(0);
		auto diff = cts - ref.timestamp;

		if (diff > 1 && ref.timestamp != 0) {
			ref.addPoint(ref.traffic / diff);
		}
    }
    
	model.updateModel(tcpList);
}

void ProcessMonitor::updateUdpTable()
{
	PMIB_UDPTABLE_OWNER_MODULE pUdpTable = nullptr;
	DWORD dwSize = sizeof(MIB_UDPTABLE_OWNER_MODULE);
	DWORD dwRetValue = 0;

	std::vector<ConnDataObj> udpList;

	do {
		pUdpTable = (PMIB_UDPTABLE_OWNER_MODULE)realloc(pUdpTable, dwSize);
		dwRetValue = GetExtendedUdpTable(pUdpTable, &dwSize, true, AF_INET, UDP_TABLE_OWNER_MODULE, 0);
	} while (dwRetValue == ERROR_INSUFFICIENT_BUFFER); //api idiom

	if (dwRetValue != ERROR_SUCCESS) {
		qDebug() << dwRetValue;
		return;
	}
	
	if (pUdpTable == nullptr) {
		qDebug() << "Null udp how?";
		return;
	}
	
	for (int i = 0; i < pUdpTable->dwNumEntries; i++)
	{
		ConnDataObj tcpConnItem = ConnDataObj();
		MIB_UDPROW_OWNER_MODULE udpRow = pUdpTable->table[i];

		tcpConnItem.pid = udpRow.dwOwningPid;
		tcpConnItem.localAddr = getIpStringFromDword(udpRow.dwLocalAddr);
		tcpConnItem.localPort = ntohs(udpRow.dwLocalPort);

		struct servent* servLoc, * servRem;
		servLoc = getservbyport(udpRow.dwLocalPort, nullptr);

		if (servLoc == nullptr) {
			tcpConnItem.localProto = "";
		}
		else {
			tcpConnItem.localProto = servLoc->s_name;
		}

		TCPIP_OWNER_MODULE_BASIC_INFO* ownerInfo = nullptr;
		DWORD ownerInfoSize = sizeof(TCPIP_OWNER_MODULE_BASIC_INFO);

		do {
			ownerInfo = (TCPIP_OWNER_MODULE_BASIC_INFO*)realloc(ownerInfo, ownerInfoSize);
			dwRetValue = GetOwnerModuleFromUdpEntry(&udpRow, TCPIP_OWNER_MODULE_INFO_BASIC, ownerInfo, &ownerInfoSize);
		} while (dwRetValue == ERROR_INSUFFICIENT_BUFFER);

		if (dwRetValue == ERROR_SUCCESS) {
			std::wstring wProcName(ownerInfo->pModuleName);
			tcpConnItem.procName = std::string(wProcName.begin(), wProcName.end());
		} else {
			//qDebug() << dwRetValue;
			tcpConnItem.procName = "System Idle";
		}

		udpList.push_back(tcpConnItem);
		NetworkTrafficHelper& ref = portBytes_map[tcpConnItem.localPort];
		auto cts = time(0);
		auto diff = cts - ref.timestamp;

		if (diff > 1 && ref.timestamp != 0) {
			ref.addPoint(ref.traffic / diff);
		}
	}
	udpModel.updateModel(udpList);
}

void ProcessMonitor::runtxmonitor()
{
	if (monitor_handle == nullptr) {
		std::thread pac_mon{ [=] {
			start_pcap();
		} };

		pac_mon.detach();
	}
}

long ProcessMonitor::capture_start_sec;

void got_packet(u_char* args, const struct pcap_pkthdr* pcap_header, const u_char* packet) {
	// here i jump to the ports

	auto portBytesMap = (std::unordered_map<uint16_t, NetworkTrafficHelper>*) args;
	const u_char* off = packet; // use to iterate over packet

	uint16_t srcPort;
	uint16_t destPort;

	struct eth_header* eth_header = (struct eth_header*)off;
	uint16_t ipV = ntohs(eth_header->type);

	off += ETH_LEN;

	if (ipV == ETH_TYPE_IPV4) {
		struct ipv4_stub* ipv4_stub = (struct ipv4_stub*) off;
		off += (ipv4_stub->version_IHL & 0x0F) * 4;
	} else if (ipV == ETH_TYPE_IPV6) {
		off += IPV6_LEN;
	} else {
		qDebug() << "Unrecognized packet";
	}

	struct tcpudp_stub* tcpudp_stub = (struct tcpudp_stub*)off;
	srcPort = ntohs(tcpudp_stub->src_port);
	destPort = ntohs(tcpudp_stub->dest_port);

	uint16_t listening_port;

	if (portBytesMap->count(srcPort) ) {
		listening_port = srcPort;
	} else if (portBytesMap->count(destPort)){
		listening_port = destPort;
	}

	if (portBytesMap->count(listening_port)) {
		NetworkTrafficHelper& ref = (*portBytesMap)[listening_port];
		//auto cts = time(0);
		auto seconds = pcap_header->ts.tv_sec - ref.timestamp;
		if (seconds > 1 && ref.timestamp != 0) {
			ref.addPoint(pcap_header->len * 8 / seconds);
		}
		else {
			auto previousTraffic = ref.traffic;
			ref.addPoint(previousTraffic + pcap_header->len * 8);
		}
		ref.timestamp = pcap_header->ts.tv_sec;
	}
}

int ProcessMonitor::start_pcap()
{
	pcap_if_t* dev_list, * dev;

	char errbuf[PCAP_ERRBUF_SIZE];

	printf("Finding available devices ...");
	if (pcap_findalldevs(&dev_list, errbuf))
	{
		qDebug() << "No available devices: %s";
		return 2;
	}

	dev = dev_list; // list head
	while (dev != NULL) {
		if (dev->flags & PCAP_IF_WIRELESS && dev->flags & PCAP_IF_CONNECTION_STATUS_CONNECTED)
			break;
		dev = dev->next;
	}
	printf("Finding wireless devices ...");
	if (dev == NULL) {
		qDebug() << "Couldn't find wireless device.";
		return 2;
	}
	printf("Done\n");

	pcap_t* handle;

	/* Open the session in promiscuous mode */
	// we only care about monitoring the port endpoints, so 256 should be enough
	handle = pcap_open_live(dev->name, 256, 1, 100, errbuf); // device, snaplen, promisc, to_ms, errbuf
	if (handle == NULL) {
		qDebug() << "Couldn't open device %s: %s";
		return 2;
	}

	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "(ip or ip6) and (tcp or udp)";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */

	/* Find the properties for the device */
	if (pcap_lookupnet((char*)dev, &net, &mask, errbuf) == -1) {
		qDebug()<<"Couldn't get netmask for device" << dev << errbuf;
		net = 0;
		mask = 0;
	}	

	if (pcap_compile(handle, &fp, filter_exp, 0, (bpf_u_int32) dev) == -1) {
		qDebug() << "Couldn't parse filter";
		return 2;
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		qDebug() << "Couldn't install filter";
		return 2;
	}
	// -- WORKING SNIFFING SESSION

	if (pcap_datalink(handle) != DLT_EN10MB) { // no monitor mode, so 
		qDebug() << "Device %s doesn't provide Ethernet headers - not supported\n";
		return 2;
	}
	
	this->monitor_handle = handle;
	int num_packets = 0; // -1 or 0 means it will catch packets until you call pcap_breakloop ( do this from another thread)
	capture_start_sec = time(0); // initialize packet time yes
	
	pcap_loop(handle, num_packets, got_packet, (u_char*)(&portBytes_map));
	/* Print its length */

	pcap_close(handle);
	return 0;
}

/*
	Perform a whois query to a server and record the response
 */

int whois(char* server, char* ip_addr, char** response)
{
	char ip[32], message[100];
	SOCKET sock;
	
	struct sockaddr_in dest;
	
	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	memset(&dest, 0, sizeof(dest));
	dest.sin_family = AF_INET;

	printf("%s", ip);
	
	dest.sin_addr.s_addr = inet_addr(ip);
	dest.sin_port = htons(43);

	//Now connect to dest
	if (connect(sock, (const struct sockaddr*)&dest, sizeof(dest)) < 0)
	{
		perror("connect failed");
	}

	//Now send some data or message
	printf("\nQuerying for ... %s ...", ip_addr);
	sprintf(message, "%s\r\n", ip_addr);

	if (send(sock, message, strlen(message), 0) < 0)
	{
		perror("Send failed");
	}


	if (recv_all(sock, response)) {
		perror("Recv failed");
	}

	closesocket(sock);
	return 0;
}

