#pragma once
#include <string>

class ConnDataObj
{
public:
	std::string localAddr;
	uint16_t localPort = 0;
	std::string localProto; // for the port

	std::string remoteAddr;
	int remotePort = 0;
	std::string remoteName; // dns request
	std::string remoteProtocol;

	int pid;
	std::string procName;

	std::string traffic; // bits per second

	ConnDataObj(){}

};

