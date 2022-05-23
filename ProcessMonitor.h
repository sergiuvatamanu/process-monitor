#pragma once

#include <QtWidgets/QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>

#include <QTableView>

#include "ui_processMonitor.h"
#include "model/ConnectionsModel.h"

#include <pcap.h>
#include <WinSock2.h>
#pragma comment(lib, "Ws2_32.lib")

class ProcessMonitor : public QWidget
{
public:
    ProcessMonitor(QWidget *parent = Q_NULLPTR);

    static long capture_start_sec;
private:
    Ui::ProcessMonitorClass ui;

    ConnectionsModel model;
    ConnectionsModel udpModel;

    std::unordered_map<uint16_t, NetworkTrafficHelper> portBytes_map;

    pcap_t* monitor_handle = nullptr;

    void configureApis();
    void updateTcpTable();
    void updateUdpTable();
    void runtxmonitor();
    int start_pcap();

};
